/**
 * `VaultClient` — the typed HTTP client for the vault API.
 *
 * Shared by the CLI and the Vite plugin so both speak one wire contract. It
 * holds an API key for the lifetime of a command and never persists one;
 * writing credentials to disk belongs to `config.ts` alone.
 *
 * `exportSecrets` is the call behind `vault run` and `vault push`: it asks for
 * every non-sealed value at once rather than issuing one request per name, so
 * an injected process makes a single round trip.
 *
 * @see {@link https://vault.buildwithfriends.dev/reference/http-api/}
 */
import * as v from "valibot";
import {
  apiKeyMetaSchema,
  auditRecordSchema,
  masterKeyWrapMetaSchema,
  routeInputSchema,
  routeRecordSchema,
  secretMetaSchema,
  secretRecordSchema,
} from "./client-schemas.ts";
import type { Scope, SecretKind } from "./types.ts";

const keyResponseSchema = v.looseObject({ key: v.string(), prefix: v.string() });
const okResponseSchema = v.looseObject({ ok: v.literal(true) });
const errorResponseSchema = v.object({ error: v.string() });

class VaultClientError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "VaultClientError";
    this.status = status;
  }
}

export function parseVaultApiUrl(value: string): URL {
  const url = new URL(value);
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "::1";
  if (url.username.length > 0 || url.password.length > 0) {
    throw new Error("vault API URL must not include credentials");
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error("vault API URL must use HTTPS or loopback HTTP");
  }
  return url;
}

export class VaultClient {
  readonly apiUrl: string;
  readonly apiKey: string;
  private readonly origin: URL;

  constructor(apiUrl: string, apiKey: string) {
    this.origin = parseVaultApiUrl(apiUrl);
    this.apiUrl = this.origin.origin;
    this.apiKey = apiKey;
  }

  private async request<TSchema extends v.GenericSchema>(
    method: string,
    path: string,
    schema: TSchema,
    body?: string,
    auth = true,
    extraHeaders?: Record<string, string>,
  ): Promise<v.InferOutput<TSchema>> {
    const headers: Record<string, string> = {};
    if (auth) headers.Authorization = `Bearer ${this.apiKey}`;
    if (body != null) headers["content-type"] = "application/json";
    const response = await fetch(new URL(path, this.origin), {
      method,
      headers: { ...headers, ...extraHeaders },
      body,
      redirect: "error",
    });
    const text = await response.text();
    const parsed: unknown = text.length > 0 ? JSON.parse(text) : {};
    if (!response.ok) {
      const error = v.safeParse(errorResponseSchema, parsed);
      throw new VaultClientError(
        response.status,
        error.success ? error.output.error : `request failed: ${response.status}`,
      );
    }
    const result = v.safeParse(schema, parsed);
    if (!result.success) {
      throw new VaultClientError(
        response.status,
        "vault API returned an invalid response",
      );
    }
    return result.output;
  }

  bootstrap(bootstrapToken: string, label?: string) {
    return this.request(
      "POST",
      "/v1/bootstrap",
      keyResponseSchema,
      JSON.stringify({ label }),
      false,
      { "X-Vault-Bootstrap-Token": bootstrapToken },
    );
  }

  listProjects() {
    return this.request(
      "GET",
      "/v1/projects",
      v.looseObject({ projects: v.array(v.string()) }),
    );
  }

  createProject(name: string) {
    return this.request(
      "POST",
      "/v1/projects",
      v.looseObject({ id: v.string(), name: v.string() }),
      JSON.stringify({ name }),
    );
  }

  deleteProject(name: string) {
    return this.request(
      "DELETE",
      `/v1/projects/${encodeURIComponent(name)}`,
      okResponseSchema,
    );
  }

  listEnvironments(project: string) {
    return this.request(
      "GET",
      `/v1/projects/${encodeURIComponent(project)}/environments`,
      v.looseObject({ environments: v.array(v.string()) }),
    );
  }

  createEnvironment(project: string, name: string) {
    return this.request(
      "POST",
      `/v1/projects/${encodeURIComponent(project)}/environments`,
      v.looseObject({ name: v.string() }),
      JSON.stringify({ name }),
    );
  }

  deleteEnvironment(project: string, env: string) {
    return this.request(
      "DELETE",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}`,
      okResponseSchema,
    );
  }

  listSecretMeta(project: string, env: string) {
    return this.request(
      "GET",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}/secrets`,
      v.looseObject({ secrets: v.array(secretMetaSchema) }),
    );
  }

  listSecrets(project: string, env: string) {
    return this.request(
      "GET",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}/secrets?show=1`,
      v.looseObject({
        secrets: v.array(
          v.looseObject({
            ...secretMetaSchema.entries,
            value: v.exactOptional(v.string()),
          }),
        ),
      }),
    );
  }

  exportSecrets(project: string, env: string) {
    return this.request(
      "GET",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}/secrets?export=1`,
      v.looseObject({ secrets: v.array(secretRecordSchema) }),
    );
  }

  getSecret(project: string, env: string, name: string) {
    return this.request(
      "GET",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}/secrets/${encodeURIComponent(name)}`,
      secretRecordSchema,
    );
  }

  patchSecrets(
    project: string,
    env: string,
    body: {
      set?: Array<{ name: string; value?: string; kind?: SecretKind; random?: boolean }>;
      delete?: string[];
    },
  ) {
    return this.request(
      "PATCH",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}/secrets`,
      okResponseSchema,
      JSON.stringify(body),
    );
  }

  listRoutes(project: string, env: string) {
    return this.request(
      "GET",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}/routes`,
      v.looseObject({ routes: v.array(routeRecordSchema) }),
    );
  }

  putRoute(project: string, env: string, body: v.InferInput<typeof routeInputSchema>) {
    return this.request(
      "PUT",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}/routes`,
      v.looseObject({ ok: v.literal(true), host: v.string() }),
      JSON.stringify(body),
    );
  }

  createKey(body: {
    type: "user" | "system";
    label?: string;
    permission?: "read" | "readwrite" | "full";
    mode?: "inject" | "broker";
    scopes?: Scope[];
    expiresInDays?: number;
  }) {
    return this.request("POST", "/v1/keys", keyResponseSchema, JSON.stringify(body));
  }

  listKeys(includeRevoked = false) {
    return this.request(
      "GET",
      `/v1/keys${includeRevoked ? "?includeRevoked=1" : ""}`,
      v.looseObject({ keys: v.array(apiKeyMetaSchema) }),
    );
  }

  rotateKey(prefix: string, expiresInDays?: number) {
    return this.request(
      "POST",
      `/v1/keys/${encodeURIComponent(prefix)}/rotate`,
      keyResponseSchema,
      JSON.stringify(expiresInDays == null ? {} : { expiresInDays }),
    );
  }

  revokeKey(prefix: string) {
    return this.request(
      "DELETE",
      `/v1/keys/${encodeURIComponent(prefix)}`,
      okResponseSchema,
    );
  }

  listAudit(limit = 50, cursor?: string) {
    const query = new URLSearchParams({ limit: String(limit) });
    if (cursor != null) query.set("cursor", cursor);
    return this.request(
      "GET",
      `/v1/audit?${query.toString()}`,
      v.looseObject({
        events: v.array(auditRecordSchema),
        nextCursor: v.nullable(v.string()),
      }),
    );
  }

  listMasterKeys() {
    return this.request(
      "GET",
      "/v1/master-keys",
      v.looseObject({
        activeFingerprint: v.string(),
        wraps: v.array(masterKeyWrapMetaSchema),
      }),
    );
  }

  prepareMasterKey() {
    return this.request(
      "POST",
      "/v1/master-keys/prepare",
      v.looseObject({ fingerprint: v.string() }),
      JSON.stringify({}),
    );
  }

  retireMasterKey(fingerprint: string) {
    return this.request(
      "DELETE",
      `/v1/master-keys/${encodeURIComponent(fingerprint)}`,
      okResponseSchema,
    );
  }
}
