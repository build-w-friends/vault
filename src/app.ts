import { Hono } from "hono";
import { z } from "zod";

import { VaultCrypto } from "./crypto.ts";
import { StoreError, VaultStore } from "./db.ts";
import { bearerFrom, randomApiKey, randomSecretValue } from "./keys.ts";
import {
  PolicyError,
  assertCanDecrypt,
  assertCanWrite,
  assertNotRevoked,
  assertScope,
  canManageKeys,
  canManageProjects,
  valueVisibleOnGet,
} from "./policy.ts";
import { handleMcp } from "./mcp.ts";
import { applyInject, genericRoute, routePreset } from "./presets.ts";
import type { ApiKeyRecord, KeyMode, Permission, SecretKind, VaultEnv } from "./types.ts";

type Variables = {
  store: VaultStore;
  key: ApiKeyRecord;
};

const secretKindSchema = z.enum(["config", "secret", "sealed"]);
const bootstrapSchema = z.object({
  label: z.string().optional(),
});
const createProjectSchema = z.object({ name: z.string().min(1) });
const createEnvSchema = z.object({ name: z.string().min(1) });
const createKeySchema = z.object({
  type: z.enum(["user", "system"]),
  label: z.string().optional(),
  permission: z.enum(["read", "readwrite", "full"]).optional(),
  mode: z.enum(["inject", "broker"]).optional(),
  scopes: z.array(z.object({ project: z.string(), env: z.string() })).optional(),
});
const patchSecretsSchema = z.object({
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
});
const putRouteSchema = z.object({
  host: z.string().min(1).optional(),
  secret: z.string().min(1),
  preset: z.string().optional(),
  header: z.string().optional(),
  dummyEnvName: z.string().optional(),
  dummyValue: z.string().optional(),
});
const brokerApplySchema = z.object({
  project: z.string(),
  environment: z.string(),
  host: z.string(),
  headers: z.record(z.string(), z.string()),
});

export function createApp(
  vaultCrypto: VaultCrypto,
): Hono<{ Bindings: VaultEnv; Variables: Variables }> {
  const app = new Hono<{ Bindings: VaultEnv; Variables: Variables }>();

  app.onError((error, c) => {
    if (error instanceof PolicyError || error instanceof StoreError) {
      return c.json({ error: error.message }, error.status as 400);
    }
    return c.json(
      { error: error instanceof Error ? error.message : "internal error" },
      500,
    );
  });

  app.get("/", (c) => c.json({ ok: true, name: "poc-vault" }));

  app.use("/v1/*", async (c, next) => {
    await attachStore(c, vaultCrypto);
    if (c.req.path === "/v1/bootstrap" && c.req.method === "POST") {
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

  app.post("/mcp", (c) => handleMcp(c));

  app.post("/v1/bootstrap", async (c) => {
    const store = c.get("store");
    if ((await store.countKeys()) > 0) {
      throw new PolicyError(409, "already bootstrapped");
    }
    const body = bootstrapSchema.parse(await c.req.json().catch(() => ({})));
    const generated = randomApiKey("user");
    await store.insertKey({
      plaintext: generated.plaintext,
      prefix: generated.prefix,
      type: "user",
      permission: "full",
      mode: null,
      label: body.label ?? "bootstrap",
      scopes: null,
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
    return c.json(project, 201);
  });

  app.delete("/v1/projects/:project", async (c) => {
    if (!canManageProjects(c.get("key")))
      throw new PolicyError(403, "cannot manage projects");
    const deleted = await c.get("store").deleteProject(c.req.param("project"));
    if (!deleted) throw new StoreError(404, "project not found");
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
    return c.json({ name: body.name.toLowerCase() }, 201);
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
    await store.audit({
      keyPrefix: key.keyPrefix,
      action: exporting ? "inject" : show ? "get" : "list",
      status: "ok",
    });
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
      await store.deleteSecret(environmentId, name);
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
    return c.json({ ok: true, host });
  });

  app.post("/v1/broker/apply", async (c) => {
    const key = c.get("key");
    const store = c.get("store");
    const body = brokerApplySchema.parse(await c.req.json());
    assertScope(key, body.project, body.environment);
    const { environmentId } = await store.requireEnvironment(
      body.project,
      body.environment,
    );
    const route = await store.findRoute(environmentId, body.host);
    if (route == null) {
      await store.audit({
        keyPrefix: key.keyPrefix,
        action: "broker",
        status: "unmatched",
        host: body.host,
      });
      return c.json({ matched: false, headers: body.headers });
    }
    const secret = await store.getSecretByName(environmentId, route.secretName);
    if (secret == null) throw new StoreError(404, "routed secret not found");
    const headers = new Headers(body.headers);
    for (const name of route.stripHeaders) headers.delete(name);
    applyInject(headers, route.inject, secret.value);
    await store.audit({
      keyPrefix: key.keyPrefix,
      action: "broker",
      status: "ok",
      host: body.host,
      secretName: route.secretName,
    });
    return c.json({ matched: true, headers: Object.fromEntries(headers.entries()) });
  });

  app.get("/v1/keys", async (c) => {
    if (!canManageKeys(c.get("key"))) throw new PolicyError(403, "cannot manage keys");
    return c.json({ keys: await c.get("store").listKeys() });
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
    });
    return c.json({ key: generated.plaintext, prefix: generated.prefix }, 201);
  });

  app.delete("/v1/keys/:prefix", async (c) => {
    if (!canManageKeys(c.get("key"))) throw new PolicyError(403, "cannot manage keys");
    const revoked = await c.get("store").revokeKey(c.req.param("prefix"));
    if (!revoked) throw new StoreError(404, "key not found");
    return c.json({ ok: true });
  });

  return app;
}

async function attachStore(
  c: { env: VaultEnv; set: (key: "store", value: VaultStore) => void },
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
  assertNotRevoked(key);
  await store.touchKey(key.keyPrefix);
  c.set("key", key);
}
