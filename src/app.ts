/**
 * The vault HTTP API.
 *
 * Middleware attaches a `VaultStore` and resolves the bearer token to an
 * `ApiKeyRecord` before any route body runs; `POST /v1/bootstrap` is the single
 * exception, authenticated instead by a constant-time comparison against the
 * Secrets Store bootstrap token.
 *
 * Every request schema is `.strict()`. An unknown field is a 400 rather than a
 * silently ignored key, so a caller sending a field this Worker does not
 * implement finds out immediately instead of believing it took effect.
 *
 * Authority is never decided here — routes call into `policy.ts` and let its
 * `PolicyError` / `StoreError` / `KeyringError` carry the status out through
 * `onError`. An unrecognized error logs structurally and answers a generic 500,
 * because an internal message is a description of the vault's internals.
 *
 * Audit rows are appended on the same path as the effect they describe, so a
 * successful mutation cannot leave no trace.
 *
 * @see {@link https://vault.buildwithfriends.dev/reference/http-api/}
 */
import { Hono } from "hono";
import { z } from "zod";

import { VaultCrypto, timingSafeStringEqual } from "./crypto.ts";
import { StoreError, VaultStore } from "./db.ts";
import { KeyringError, VaultKeyring } from "./keyring.ts";
import { bearerFrom, randomApiKey, randomSecretValue } from "./keys.ts";
import {
  PolicyError,
  assertCanDecrypt,
  assertCanWrite,
  assertActiveKey,
  assertScope,
  canManageKeys,
  canManageProjects,
  valueVisibleOnGet,
} from "./policy.ts";
import { issuanceRoutes } from "./issuance/routes.ts";
import { IssuanceStore } from "./issuance/store.ts";
import { IssuanceService } from "./issuance/service.ts";
import { adminSchema, id as issuanceId } from "./issuance/contracts.ts";
import { handleMcp } from "./mcp.ts";
import { genericRoute, routePreset } from "./presets.ts";
import type {
  ApiKeyMeta,
  ApiKeyRecord,
  AuditAction,
  KeyMode,
  Permission,
  SecretKind,
} from "./types.ts";
import * as v from "valibot";

type Variables = {
  store: VaultStore;
  key: ApiKeyRecord;
};

const secretKindSchema = z.enum(["config", "secret", "sealed"]);
const bootstrapSchema = z
  .object({
    label: z.string().min(1).max(120).optional(),
  })
  .strict();
const createProjectSchema = z.object({ name: z.string().min(1).max(120) }).strict();
const createEnvSchema = z.object({ name: z.string().min(1).max(120) }).strict();
const createKeySchema = z
  .object({
    type: z.enum(["user", "system"]),
    label: z.string().optional(),
    permission: z.enum(["read", "readwrite", "full"]).optional(),
    mode: z.enum(["inject", "broker"]).optional(),
    scopes: z.array(z.object({ project: z.string(), env: z.string() })).optional(),
    expiresInDays: z.number().int().min(1).max(365).optional(),
  })
  .strict();
const rotateKeySchema = z
  .object({
    expiresInDays: z.number().int().min(1).max(365).optional(),
  })
  .strict();
const patchSecretsSchema = z
  .object({
    set: z
      .array(
        z.object({
          name: z.string().min(1),
          value: z.string().optional(),
          kind: secretKindSchema.optional(),
          random: z.boolean().optional(),
        }),
      )
      .optional(),
    delete: z.array(z.string()).optional(),
  })
  .strict();
const putRouteSchema = z
  .object({
    host: z.string().min(1).optional(),
    secret: z.string().min(1),
    preset: z.string().optional(),
    header: z.string().optional(),
    dummyEnvName: z.string().optional(),
    dummyValue: z.string().optional(),
  })
  .strict();
const auditCursorSchema = v.object({
  createdAt: v.string(),
  id: v.string(),
});

type AppBindings = { DB: D1Database };

type AppOptions = {
  bootstrapToken: string;
  activeMasterKeyFingerprint: string;
  keyring?: VaultKeyring;
  inactiveMasterKey?: string;
  issuanceFetch?: typeof fetch;
  now?: () => number;
};

export function createApp(
  vaultCrypto: VaultCrypto,
  options: AppOptions,
): Hono<{ Bindings: AppBindings; Variables: Variables }> {
  const app = new Hono<{ Bindings: AppBindings; Variables: Variables }>();

  app.onError((error, c) => {
    if (
      error instanceof PolicyError ||
      error instanceof StoreError ||
      error instanceof KeyringError
    ) {
      return c.json({ error: error.message }, error.status);
    }
    if (error instanceof z.ZodError) {
      return c.json({ error: "request body is invalid" }, 400);
    }
    console.error(
      JSON.stringify({
        message: "vault request failed",
        error: error instanceof Error ? error.message : "internal error",
      }),
    );
    return c.json({ error: "internal error" }, 500);
  });

  app.get("/", async (c) => {
    const store = new VaultStore(c.env.DB, vaultCrypto);
    return c.json({
      ok: true,
      name: "bwf-vault",
      bootstrapped: await store.isBootstrapped(),
      activeMasterKeyFingerprint: options.activeMasterKeyFingerprint,
    });
  });

  app.use("/v1/*", async (c, next) => {
    await attachStore(c, vaultCrypto);
    if (c.req.path === "/v1/bootstrap" && c.req.method === "POST") {
      const provided = c.req.header("X-Vault-Bootstrap-Token");
      if (
        provided == null ||
        !(await timingSafeStringEqual(provided, options.bootstrapToken))
      ) {
        throw new PolicyError(401, "invalid bootstrap credential");
      }
      await next();
      return;
    }
    await attachKey(c);
    await next();
  });

  app.use("/mcp", async (c, next) => {
    await attachStore(c, vaultCrypto);
    await attachKey(c);
    await next();
  });

  app.route("/issuance", issuanceRoutes(vaultCrypto, options.issuanceFetch, options.now));
  app.get("/v1/issuance/requests/:id", async (c) => {
    if (!canManageKeys(c.get("key")))
      throw new PolicyError(403, "only operators inspect issuer requests");
    const store = new IssuanceStore(c.env.DB, vaultCrypto);
    const request = await store.request(issuanceId.parse(c.req.param("id")));
    const eventRows = await c.env.DB.prepare(
      "SELECT actor, action, created_at FROM issuance_events WHERE request_id = ? ORDER BY created_at, rowid",
    )
      .bind(request.id)
      .all<{ actor: string; action: string; created_at: number }>();
    const events = eventRows.results;
    return c.json({
      ...(await new IssuanceService(store).view(request)),
      subject: request.subject,
      sessionId: request.auth_hash,
      providerTokenId: request.token_id,
      events,
    });
  });
  app.get("/v1/issuance/setup", async (c) => {
    if (!canManageKeys(c.get("key")))
      throw new PolicyError(403, "only operators inspect issuer setup");
    return c.json(await new IssuanceStore(c.env.DB, vaultCrypto).setup());
  });
  app.post("/v1/issuance/admin", async (c) => {
    if (!canManageKeys(c.get("key")))
      throw new PolicyError(403, "only operators manage issuer configuration");
    await new IssuanceStore(c.env.DB, vaultCrypto).admin(
      adminSchema.parse(await c.req.json()),
      c.get("key").keyPrefix,
    );
    return c.json({ ok: true });
  });

  app.post("/mcp", (c) => handleMcp(c));

  app.post("/v1/bootstrap", async (c) => {
    const store = c.get("store");
    const body = bootstrapSchema.parse(await c.req.json().catch(() => ({})));
    const generated = randomApiKey("user");
    await store.claimBootstrapKey({
      plaintext: generated.plaintext,
      prefix: generated.prefix,
      label: body.label ?? "bootstrap",
      expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    });
    await store.audit({
      keyPrefix: generated.prefix,
      action: "bootstrap",
      status: "ok",
    });
    return c.json({ key: generated.plaintext, prefix: generated.prefix });
  });

  app.get("/v1/projects", async (c) => {
    return c.json({ projects: await c.get("store").listProjects() });
  });

  app.post("/v1/projects", async (c) => {
    if (!canManageProjects(c.get("key")))
      throw new PolicyError(403, "cannot manage projects");
    const body = createProjectSchema.parse(await c.req.json());
    const project = await c.get("store").createProject(body.name);
    await c.get("store").audit({
      keyPrefix: c.get("key").keyPrefix,
      action: "project_create",
      status: "ok",
    });
    return c.json(project, 201);
  });

  app.delete("/v1/projects/:project", async (c) => {
    if (!canManageProjects(c.get("key")))
      throw new PolicyError(403, "cannot manage projects");
    const deleted = await c.get("store").deleteProject(c.req.param("project"));
    if (!deleted) throw new StoreError(404, "project not found");
    await c.get("store").audit({
      keyPrefix: c.get("key").keyPrefix,
      action: "project_delete",
      status: "ok",
    });
    return c.json({ ok: true });
  });

  app.get("/v1/projects/:project/environments", async (c) => {
    const store = c.get("store");
    const project = await store.getProject(c.req.param("project"));
    if (project == null) throw new StoreError(404, "project not found");
    return c.json({ environments: await store.listEnvironments(project.id) });
  });

  app.post("/v1/projects/:project/environments", async (c) => {
    if (!canManageProjects(c.get("key")))
      throw new PolicyError(403, "cannot manage projects");
    const store = c.get("store");
    const project = await store.getProject(c.req.param("project"));
    if (project == null) throw new StoreError(404, "project not found");
    const body = createEnvSchema.parse(await c.req.json());
    await store.createEnvironment(project.id, body.name);
    await store.audit({
      keyPrefix: c.get("key").keyPrefix,
      action: "environment_create",
      status: "ok",
    });
    return c.json({ name: body.name.toLowerCase() }, 201);
  });

  app.delete("/v1/projects/:project/environments/:env", async (c) => {
    if (!canManageProjects(c.get("key")))
      throw new PolicyError(403, "cannot manage projects");
    const store = c.get("store");
    const project = await store.getProject(c.req.param("project"));
    if (project == null) throw new StoreError(404, "project not found");
    const deleted = await store.deleteEnvironment(project.id, c.req.param("env"));
    if (!deleted) throw new StoreError(404, "environment not found");
    await store.audit({
      keyPrefix: c.get("key").keyPrefix,
      action: "environment_delete",
      status: "deleted",
    });
    return c.json({ ok: true });
  });

  app.get("/v1/projects/:project/environments/:env/secrets", async (c) => {
    const key = c.get("key");
    const store = c.get("store");
    const project = c.req.param("project");
    const env = c.req.param("env");
    assertScope(key, project, env);
    const { environmentId } = await store.requireEnvironment(project, env);
    const show = c.req.query("show") === "1";
    const exporting = c.req.query("export") === "1";
    if (show || exporting) assertCanDecrypt(key);
    let action: AuditAction = "list";
    if (exporting) action = "inject";
    else if (show) action = "get";
    await store.audit({ keyPrefix: key.keyPrefix, action, status: "ok" });
    if (!show && !exporting) {
      return c.json({ secrets: await store.listSecretMeta(environmentId) });
    }
    const secrets = await store.listSecrets(environmentId);
    return c.json({
      secrets: secrets.map((secret) => ({
        name: secret.name,
        kind: secret.kind,
        value:
          exporting || valueVisibleOnGet(key, secret.kind) ? secret.value : undefined,
      })),
    });
  });

  app.get("/v1/projects/:project/environments/:env/secrets/:name", async (c) => {
    const key = c.get("key");
    const store = c.get("store");
    const project = c.req.param("project");
    const env = c.req.param("env");
    const name = c.req.param("name");
    assertScope(key, project, env);
    assertCanDecrypt(key);
    const { environmentId } = await store.requireEnvironment(project, env);
    const secret = await store.getSecretByName(environmentId, name);
    if (secret == null) throw new StoreError(404, "secret not found");
    if (!valueVisibleOnGet(key, secret.kind)) {
      throw new PolicyError(403, "sealed secret values are not returned");
    }
    await store.audit({
      keyPrefix: key.keyPrefix,
      action: "get",
      status: "ok",
      secretName: name,
    });
    return c.json(secret);
  });

  app.patch("/v1/projects/:project/environments/:env/secrets", async (c) => {
    const key = c.get("key");
    const store = c.get("store");
    const project = c.req.param("project");
    const env = c.req.param("env");
    assertScope(key, project, env);
    assertCanWrite(key);
    const { environmentId } = await store.requireEnvironment(project, env);
    const body = patchSecretsSchema.parse(await c.req.json());
    for (const item of body.set ?? []) {
      const kind: SecretKind = item.kind ?? "secret";
      let value = item.value;
      if (item.random === true) value = randomSecretValue();
      if (value == null) throw new PolicyError(400, `missing value for ${item.name}`);
      if (key.mode === "broker" && kind !== "sealed") {
        throw new PolicyError(403, "broker keys may only create sealed secrets");
      }
      if (key.mode === "broker" && item.random !== true) {
        throw new PolicyError(
          403,
          "broker keys must create sealed secrets with random values",
        );
      }
      await store.setSecret(environmentId, item.name, value, kind);
      await store.audit({
        keyPrefix: key.keyPrefix,
        action: "set",
        status: "ok",
        secretName: item.name,
      });
    }
    for (const name of body.delete ?? []) {
      if (await store.deleteSecret(environmentId, name)) {
        await store.audit({
          keyPrefix: key.keyPrefix,
          action: "secret_delete",
          status: "ok",
          secretName: name,
        });
      }
    }
    return c.json({ ok: true });
  });

  app.get("/v1/projects/:project/environments/:env/routes", async (c) => {
    const key = c.get("key");
    const store = c.get("store");
    const project = c.req.param("project");
    const env = c.req.param("env");
    assertScope(key, project, env);
    const { environmentId } = await store.requireEnvironment(project, env);
    return c.json({ routes: await store.listRoutes(environmentId) });
  });

  app.put("/v1/projects/:project/environments/:env/routes", async (c) => {
    const key = c.get("key");
    const store = c.get("store");
    const project = c.req.param("project");
    const env = c.req.param("env");
    assertScope(key, project, env);
    assertCanWrite(key);
    const { environmentId } = await store.requireEnvironment(project, env);
    const body = putRouteSchema.parse(await c.req.json());
    const preset = body.preset != null ? routePreset(body.preset) : null;
    const built =
      preset ??
      genericRoute({
        host: body.host ?? "",
        header: body.header ?? "Authorization",
        dummyEnvName: body.dummyEnvName ?? body.secret,
        dummyValue: body.dummyValue,
      });
    const host = body.host ?? built.host;
    if (host.length === 0) throw new PolicyError(400, "host is required");
    await store.upsertRoute(environmentId, {
      host,
      secretName: body.secret,
      inject: built.inject,
      stripHeaders: built.stripHeaders,
      dummyEnvName: built.dummyEnvName,
      dummyValue: built.dummyValue,
    });
    await store.audit({
      keyPrefix: key.keyPrefix,
      action: "route_put",
      status: "ok",
      host,
      secretName: body.secret,
    });
    return c.json({ ok: true, host });
  });

  app.get("/v1/keys", async (c) => {
    if (!canManageKeys(c.get("key"))) throw new PolicyError(403, "cannot manage keys");
    const includeRevoked = c.req.query("includeRevoked") === "1";
    const keys = await c.get("store").listKeys(includeRevoked);
    return c.json({ keys: keys.map(publicKeyMeta) });
  });

  app.post("/v1/keys", async (c) => {
    if (!canManageKeys(c.get("key"))) throw new PolicyError(403, "cannot manage keys");
    const body = createKeySchema.parse(await c.req.json());
    const generated = randomApiKey(body.type);
    const permission: Permission =
      body.type === "user" ? "full" : (body.permission ?? "read");
    const mode: KeyMode | null = body.type === "user" ? null : (body.mode ?? "inject");
    if (body.type === "system" && (body.scopes == null || body.scopes.length === 0)) {
      throw new PolicyError(400, "system keys require scopes");
    }
    await c.get("store").insertKey({
      plaintext: generated.plaintext,
      prefix: generated.prefix,
      type: body.type,
      permission,
      mode,
      label: body.label ?? null,
      scopes: body.type === "system" ? (body.scopes ?? []) : null,
      expiresAt: expiresAtFromDays(body.expiresInDays ?? 90),
    });
    await c.get("store").audit({
      keyPrefix: c.get("key").keyPrefix,
      action: "key_create",
      status: "ok",
    });
    return c.json({ key: generated.plaintext, prefix: generated.prefix }, 201);
  });

  app.post("/v1/keys/:prefix/rotate", async (c) => {
    if (!canManageKeys(c.get("key"))) throw new PolicyError(403, "cannot manage keys");
    const store = c.get("store");
    const current = await store.findKeyByPrefix(c.req.param("prefix"));
    if (current == null) throw new StoreError(404, "key not found");
    assertActiveKey(current);
    const body = rotateKeySchema.parse(await c.req.json().catch(() => ({})));
    const generated = randomApiKey(current.type);
    await store.rotateKey(current, {
      plaintext: generated.plaintext,
      prefix: generated.prefix,
      expiresAt: expiresAtFromDays(body.expiresInDays ?? 90),
    });
    await store.audit({
      keyPrefix: c.get("key").keyPrefix,
      action: "key_rotate",
      status: "ok",
    });
    return c.json({ key: generated.plaintext, prefix: generated.prefix }, 201);
  });

  app.delete("/v1/keys/:prefix", async (c) => {
    if (!canManageKeys(c.get("key"))) throw new PolicyError(403, "cannot manage keys");
    const revoked = await c.get("store").revokeKey(c.req.param("prefix"));
    if (!revoked) throw new StoreError(404, "key not found");
    await c.get("store").audit({
      keyPrefix: c.get("key").keyPrefix,
      action: "key_revoke",
      status: "ok",
    });
    return c.json({ ok: true });
  });

  app.get("/v1/audit", async (c) => {
    if (!canManageKeys(c.get("key"))) throw new PolicyError(403, "cannot read audit");
    const limit = Number(c.req.query("limit") ?? "50");
    if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
      throw new PolicyError(400, "audit limit must be an integer from 1 to 200");
    }
    const cursor = decodeAuditCursor(c.req.query("cursor"));
    const auditInput: Parameters<VaultStore["listAudit"]>[0] = { limit };
    if (cursor != null) {
      auditInput.beforeCreatedAt = cursor.createdAt;
      auditInput.beforeId = cursor.id;
    }
    const events = await c.get("store").listAudit(auditInput);
    const last = events.at(-1);
    await c.get("store").audit({
      keyPrefix: c.get("key").keyPrefix,
      action: "audit_list",
      status: "ok",
    });
    return c.json({
      events,
      nextCursor:
        events.length === limit && last != null
          ? encodeAuditCursor(last.createdAt, last.id)
          : null,
    });
  });

  app.get("/v1/master-keys", async (c) => {
    if (!canManageKeys(c.get("key")))
      throw new PolicyError(403, "cannot manage master keys");
    if (options.keyring == null) {
      throw new KeyringError(501, "master-key management requires the Worker runtime");
    }
    return c.json({
      activeFingerprint: options.keyring.activeFingerprint,
      wraps: await options.keyring.list(c.env.DB),
    });
  });

  app.post("/v1/master-keys/prepare", async (c) => {
    if (!canManageKeys(c.get("key")))
      throw new PolicyError(403, "cannot manage master keys");
    if (options.keyring == null || options.inactiveMasterKey == null) {
      throw new KeyringError(501, "master-key management requires the Worker runtime");
    }
    const fingerprint = await options.keyring.prepare(
      c.env.DB,
      options.inactiveMasterKey,
    );
    await c.get("store").audit({
      keyPrefix: c.get("key").keyPrefix,
      action: "master_key_prepare",
      status: "ok",
    });
    return c.json({ fingerprint });
  });

  app.delete("/v1/master-keys/:fingerprint", async (c) => {
    if (!canManageKeys(c.get("key")))
      throw new PolicyError(403, "cannot manage master keys");
    if (options.keyring == null) {
      throw new KeyringError(501, "master-key management requires the Worker runtime");
    }
    await options.keyring.retire(c.env.DB, c.req.param("fingerprint"));
    await c.get("store").audit({
      keyPrefix: c.get("key").keyPrefix,
      action: "master_key_retire",
      status: "ok",
    });
    return c.json({ ok: true });
  });

  return app;
}

async function attachStore(
  c: { env: AppBindings; set: (key: "store", value: VaultStore) => void },
  vaultCrypto: VaultCrypto,
): Promise<void> {
  c.set("store", new VaultStore(c.env.DB, vaultCrypto));
}

async function attachKey(c: {
  req: { header: (name: string) => string | undefined };
  get: (key: "store") => VaultStore;
  set: (key: "key", value: ApiKeyRecord) => void;
}): Promise<void> {
  const store = c.get("store");
  const token = bearerFrom(c.req.header("Authorization"));
  if (token == null) throw new PolicyError(401, "missing bearer token");
  const key = await store.findKeyByPlaintext(token);
  if (key == null) throw new PolicyError(401, "invalid API key");
  assertActiveKey(key);
  await store.touchKey(key.keyPrefix);
  c.set("key", key);
}

function expiresAtFromDays(days: number): string {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
}

function publicKeyMeta(key: ApiKeyRecord): ApiKeyMeta {
  const { id: _id, ...meta } = key;
  return meta;
}

function encodeAuditCursor(createdAt: string, id: string): string {
  return btoa(JSON.stringify({ createdAt, id }));
}

function decodeAuditCursor(
  value: string | undefined,
): { createdAt: string; id: string } | null {
  if (value == null) return null;
  try {
    const parsed: unknown = JSON.parse(atob(value));
    const result = v.safeParse(auditCursorSchema, parsed);
    if (result.success) return result.output;
  } catch {
    // The same generic error is returned for every malformed cursor.
  }
  throw new PolicyError(400, "invalid audit cursor");
}
