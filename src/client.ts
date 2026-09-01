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
 * @see {@link https://vault.buildwithfriends.com/reference/http-api/}
 */
import type {
  ApiKeyMeta,
  AuditRecord,
  RouteRecord,
  Scope,
  SecretKind,
  SecretMeta,
  SecretRecord,
} from "./types.ts";

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

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    auth = true,
    extraHeaders?: Record<string, string>,
  ): Promise<T> {
    const response = await fetch(new URL(path, this.origin), {
      method,
      headers: {
        ...(auth ? { Authorization: `Bearer ${this.apiKey}` } : {}),
        ...(body != null ? { "content-type": "application/json" } : {}),
        ...extraHeaders,
      },
      body: body != null ? JSON.stringify(body) : undefined,
      redirect: "error",
    });
    const text = await response.text();
    const parsed: unknown = text.length > 0 ? JSON.parse(text) : {};
    if (!response.ok) {
      const message =
        typeof parsed === "object" &&
        parsed != null &&
        "error" in parsed &&
        typeof parsed.error === "string"
          ? parsed.error
          : `request failed: ${response.status}`;
      throw new VaultClientError(response.status, message);
    }
    return parsed as T;
  }

  bootstrap(bootstrapToken: string, label?: string) {
    return this.request<{ key: string; prefix: string }>(
      "POST",
      "/v1/bootstrap",
      { label },
      false,
      { "X-Vault-Bootstrap-Token": bootstrapToken },
    );
  }

  listProjects() {
    return this.request<{ projects: string[] }>("GET", "/v1/projects");
  }

  createProject(name: string) {
    return this.request<{ id: string; name: string }>("POST", "/v1/projects", { name });
  }

  deleteProject(name: string) {
    return this.request<{ ok: true }>(
      "DELETE",
      `/v1/projects/${encodeURIComponent(name)}`,
    );
  }

  listEnvironments(project: string) {
    return this.request<{ environments: string[] }>(
      "GET",
      `/v1/projects/${encodeURIComponent(project)}/environments`,
    );
  }

  createEnvironment(project: string, name: string) {
    return this.request<{ name: string }>(
      "POST",
      `/v1/projects/${encodeURIComponent(project)}/environments`,
      { name },
    );
  }

  deleteEnvironment(project: string, env: string) {
    return this.request<{ ok: true }>(
      "DELETE",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}`,
    );
  }

  listSecretMeta(project: string, env: string) {
    return this.request<{ secrets: SecretMeta[] }>(
      "GET",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}/secrets`,
    );
  }

  listSecrets(project: string, env: string) {
    return this.request<{ secrets: Array<SecretRecord & { value?: string }> }>(
      "GET",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}/secrets?show=1`,
    );
  }

  exportSecrets(project: string, env: string) {
    return this.request<{ secrets: Array<SecretRecord & { value?: string }> }>(
      "GET",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}/secrets?export=1`,
    );
  }

  getSecret(project: string, env: string, name: string) {
    return this.request<SecretRecord>(
      "GET",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}/secrets/${encodeURIComponent(name)}`,
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
    return this.request<{ ok: true }>(
      "PATCH",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}/secrets`,
      body,
    );
  }

  listRoutes(project: string, env: string) {
    return this.request<{ routes: RouteRecord[] }>(
      "GET",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}/routes`,
    );
  }

  putRoute(project: string, env: string, body: Record<string, unknown>) {
    return this.request<{ ok: true; host: string }>(
      "PUT",
      `/v1/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}/routes`,
      body,
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
    return this.request<{ key: string; prefix: string }>("POST", "/v1/keys", body);
  }

  listKeys(includeRevoked = false) {
    return this.request<{ keys: ApiKeyMeta[] }>(
      "GET",
      `/v1/keys${includeRevoked ? "?includeRevoked=1" : ""}`,
    );
  }

  rotateKey(prefix: string, expiresInDays?: number) {
    return this.request<{ key: string; prefix: string }>(
      "POST",
      `/v1/keys/${encodeURIComponent(prefix)}/rotate`,
      expiresInDays == null ? {} : { expiresInDays },
    );
  }

  revokeKey(prefix: string) {
    return this.request<{ ok: true }>("DELETE", `/v1/keys/${encodeURIComponent(prefix)}`);
  }

  listAudit(limit = 50, cursor?: string) {
    const query = new URLSearchParams({ limit: String(limit) });
    if (cursor != null) query.set("cursor", cursor);
    return this.request<{ events: AuditRecord[]; nextCursor: string | null }>(
      "GET",
      `/v1/audit?${query.toString()}`,
    );
  }

  listMasterKeys() {
    return this.request<{
      activeFingerprint: string;
      wraps: Array<{ fingerprint: string; createdAt: string }>;
    }>("GET", "/v1/master-keys");
  }

  prepareMasterKey() {
    return this.request<{ fingerprint: string }>("POST", "/v1/master-keys/prepare", {});
  }

  retireMasterKey(fingerprint: string) {
    return this.request<{ ok: true }>(
      "DELETE",
      `/v1/master-keys/${encodeURIComponent(fingerprint)}`,
    );
  }
}
