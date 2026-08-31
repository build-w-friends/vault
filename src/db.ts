import type { VaultCrypto } from "./crypto.ts";
import type {
  ApiKeyRecord,
  AuditAction,
  KeyMode,
  KeyType,
  Permission,
  RouteRecord,
  Scope,
  SecretKind,
  SecretMeta,
  SecretRecord,
} from "./types.ts";

type KeyRow = {
  id: string;
  key_prefix: string;
  key_hash: string;
  type: KeyType;
  label_encrypted: string | null;
  scopes_encrypted: string | null;
  permission: Permission;
  mode: KeyMode | null;
  created_at: string;
  last_used_at: string | null;
  revoked: number;
};

type SecretRow = {
  id: string;
  environment_id: string;
  key_encrypted: string;
  key_hash: string;
  value_encrypted: string;
  kind: SecretKind;
  updated_at: string;
};

type RouteRow = {
  id: string;
  environment_id: string;
  host: string;
  secret_key_hash: string;
  inject: string;
  strip_headers: string;
  dummy_env_name: string;
  dummy_value: string;
};

export function nowIso(clock: () => Date = () => new Date()): string {
  return clock().toISOString();
}

export function newId(): string {
  return crypto.randomUUID();
}

export class VaultStore {
  constructor(
    private readonly db: D1Database,
    private readonly vaultCrypto: VaultCrypto,
  ) {}

  async countKeys(): Promise<number> {
    const row = await this.db
      .prepare("SELECT COUNT(*) AS n FROM api_keys")
      .first<{ n: number }>();
    return row?.n ?? 0;
  }

  async insertKey(input: {
    plaintext: string;
    prefix: string;
    type: KeyType;
    permission: Permission;
    mode: KeyMode | null;
    label: string | null;
    scopes: Scope[] | null;
  }): Promise<void> {
    const hash = await this.vaultCrypto.sha256(input.plaintext);
    const labelEncrypted =
      input.label != null ? await this.vaultCrypto.encrypt(input.label) : null;
    const scopesEncrypted =
      input.scopes != null
        ? await this.vaultCrypto.encrypt(JSON.stringify(input.scopes))
        : null;
    await this.db
      .prepare(
        `INSERT INTO api_keys (
          id, key_prefix, key_hash, type, label_encrypted, scopes_encrypted,
          permission, mode, created_at, revoked
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
      )
      .bind(
        newId(),
        input.prefix,
        hash,
        input.type,
        labelEncrypted,
        scopesEncrypted,
        input.permission,
        input.mode,
        nowIso(),
      )
      .run();
  }

  async findKeyByPlaintext(plaintext: string): Promise<ApiKeyRecord | null> {
    const hash = await this.vaultCrypto.sha256(plaintext);
    const row = await this.db
      .prepare("SELECT * FROM api_keys WHERE key_hash = ?")
      .bind(hash)
      .first<KeyRow>();
    if (row == null) return null;
    return this.toApiKey(row);
  }

  async listKeys(): Promise<
    Array<{ prefix: string; type: KeyType; permission: Permission; mode: KeyMode | null }>
  > {
    const result = await this.db
      .prepare(
        "SELECT key_prefix, type, permission, mode FROM api_keys WHERE revoked = 0 ORDER BY created_at",
      )
      .all<{
        key_prefix: string;
        type: KeyType;
        permission: Permission;
        mode: KeyMode | null;
      }>();
    return (result.results ?? []).map((row) => ({
      prefix: row.key_prefix,
      type: row.type,
      permission: row.permission,
      mode: row.mode,
    }));
  }

  async revokeKey(prefix: string): Promise<boolean> {
    const result = await this.db
      .prepare("UPDATE api_keys SET revoked = 1 WHERE key_prefix = ? AND revoked = 0")
      .bind(prefix)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async touchKey(prefix: string): Promise<void> {
    await this.db
      .prepare("UPDATE api_keys SET last_used_at = ? WHERE key_prefix = ?")
      .bind(nowIso(), prefix)
      .run();
  }

  async createProject(name: string): Promise<{ id: string; name: string }> {
    const id = newId();
    const normalized = name.toLowerCase();
    await this.db
      .prepare("INSERT INTO projects (id, name, created_at) VALUES (?, ?, ?)")
      .bind(id, normalized, nowIso())
      .run();
    const devId = newId();
    const prodId = newId();
    const created = nowIso();
    await this.db
      .prepare(
        "INSERT INTO environments (id, project_id, name, created_at) VALUES (?, ?, ?, ?)",
      )
      .bind(devId, id, "dev", created)
      .run();
    await this.db
      .prepare(
        "INSERT INTO environments (id, project_id, name, created_at) VALUES (?, ?, ?, ?)",
      )
      .bind(prodId, id, "prod", created)
      .run();
    return { id, name: normalized };
  }

  async listProjects(): Promise<string[]> {
    const result = await this.db
      .prepare("SELECT name FROM projects ORDER BY name")
      .all<{ name: string }>();
    return (result.results ?? []).map((row) => row.name);
  }

  async getProject(name: string): Promise<{ id: string; name: string } | null> {
    return this.db
      .prepare("SELECT id, name FROM projects WHERE name = ?")
      .bind(name.toLowerCase())
      .first<{ id: string; name: string }>();
  }

  async deleteProject(name: string): Promise<boolean> {
    const project = await this.getProject(name);
    if (project == null) return false;
    await this.db.prepare("DELETE FROM projects WHERE id = ?").bind(project.id).run();
    return true;
  }

  async createEnvironment(projectId: string, name: string): Promise<void> {
    await this.db
      .prepare(
        "INSERT INTO environments (id, project_id, name, created_at) VALUES (?, ?, ?, ?)",
      )
      .bind(newId(), projectId, name.toLowerCase(), nowIso())
      .run();
  }

  async listEnvironments(projectId: string): Promise<string[]> {
    const result = await this.db
      .prepare("SELECT name FROM environments WHERE project_id = ? ORDER BY name")
      .bind(projectId)
      .all<{ name: string }>();
    return (result.results ?? []).map((row) => row.name);
  }

  async getEnvironment(
    projectId: string,
    name: string,
  ): Promise<{ id: string; name: string } | null> {
    return this.db
      .prepare("SELECT id, name FROM environments WHERE project_id = ? AND name = ?")
      .bind(projectId, name.toLowerCase())
      .first<{ id: string; name: string }>();
  }

  async requireEnvironment(
    projectName: string,
    envName: string,
  ): Promise<{ projectId: string; environmentId: string }> {
    const project = await this.getProject(projectName);
    if (project == null) throw new StoreError(404, "project not found");
    const environment = await this.getEnvironment(project.id, envName);
    if (environment == null) throw new StoreError(404, "environment not found");
    return { projectId: project.id, environmentId: environment.id };
  }

  async listSecretRows(environmentId: string): Promise<SecretRow[]> {
    const result = await this.db
      .prepare("SELECT * FROM secrets WHERE environment_id = ?")
      .bind(environmentId)
      .all<SecretRow>();
    return result.results ?? [];
  }

  async listSecretMeta(environmentId: string): Promise<SecretMeta[]> {
    const rows = await this.listSecretRows(environmentId);
    const meta: SecretMeta[] = [];
    for (const row of rows) {
      meta.push({
        name: await this.vaultCrypto.decrypt(row.key_encrypted),
        kind: row.kind,
      });
    }
    meta.sort((left, right) => left.name.localeCompare(right.name));
    return meta;
  }

  async listSecrets(environmentId: string): Promise<SecretRecord[]> {
    const rows = await this.listSecretRows(environmentId);
    const secrets: SecretRecord[] = [];
    for (const row of rows) {
      secrets.push({
        name: await this.vaultCrypto.decrypt(row.key_encrypted),
        value: await this.vaultCrypto.decrypt(row.value_encrypted),
        kind: row.kind,
      });
    }
    secrets.sort((left, right) => left.name.localeCompare(right.name));
    return secrets;
  }

  async setSecret(
    environmentId: string,
    name: string,
    value: string,
    kind: SecretKind,
  ): Promise<void> {
    if (value.length === 0) throw new StoreError(400, "secret value must not be empty");
    const keyHash = await this.vaultCrypto.lookupHash(name);
    const keyEncrypted = await this.vaultCrypto.encrypt(name);
    const valueEncrypted = await this.vaultCrypto.encrypt(value);
    const existing = await this.db
      .prepare("SELECT id FROM secrets WHERE environment_id = ? AND key_hash = ?")
      .bind(environmentId, keyHash)
      .first<{ id: string }>();
    if (existing != null) {
      await this.db
        .prepare(
          "UPDATE secrets SET key_encrypted = ?, value_encrypted = ?, kind = ?, updated_at = ? WHERE id = ?",
        )
        .bind(keyEncrypted, valueEncrypted, kind, nowIso(), existing.id)
        .run();
      return;
    }
    await this.db
      .prepare(
        `INSERT INTO secrets (
          id, environment_id, key_encrypted, key_hash, value_encrypted, kind, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(newId(), environmentId, keyEncrypted, keyHash, valueEncrypted, kind, nowIso())
      .run();
  }

  async deleteSecret(environmentId: string, name: string): Promise<boolean> {
    const keyHash = await this.vaultCrypto.lookupHash(name);
    const result = await this.db
      .prepare("DELETE FROM secrets WHERE environment_id = ? AND key_hash = ?")
      .bind(environmentId, keyHash)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async getSecretByName(
    environmentId: string,
    name: string,
  ): Promise<SecretRecord | null> {
    const keyHash = await this.vaultCrypto.lookupHash(name);
    const row = await this.db
      .prepare("SELECT * FROM secrets WHERE environment_id = ? AND key_hash = ?")
      .bind(environmentId, keyHash)
      .first<SecretRow>();
    if (row == null) return null;
    return {
      name: await this.vaultCrypto.decrypt(row.key_encrypted),
      value: await this.vaultCrypto.decrypt(row.value_encrypted),
      kind: row.kind,
    };
  }

  async ciphertextDump(environmentId: string): Promise<SecretRow[]> {
    return this.listSecretRows(environmentId);
  }

  async upsertRoute(environmentId: string, route: RouteRecord): Promise<void> {
    const secretHash = await this.vaultCrypto.lookupHash(route.secretName);
    const existing = await this.db
      .prepare("SELECT id FROM routes WHERE environment_id = ? AND host = ?")
      .bind(environmentId, route.host)
      .first<{ id: string }>();
    const strip = JSON.stringify(route.stripHeaders);
    if (existing != null) {
      await this.db
        .prepare(
          `UPDATE routes SET secret_key_hash = ?, inject = ?, strip_headers = ?,
            dummy_env_name = ?, dummy_value = ? WHERE id = ?`,
        )
        .bind(
          secretHash,
          route.inject,
          strip,
          route.dummyEnvName,
          route.dummyValue,
          existing.id,
        )
        .run();
      return;
    }
    await this.db
      .prepare(
        `INSERT INTO routes (
          id, environment_id, host, secret_key_hash, inject, strip_headers,
          dummy_env_name, dummy_value
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        newId(),
        environmentId,
        route.host,
        secretHash,
        route.inject,
        strip,
        route.dummyEnvName,
        route.dummyValue,
      )
      .run();
  }

  async listRoutes(environmentId: string): Promise<RouteRecord[]> {
    const result = await this.db
      .prepare("SELECT * FROM routes WHERE environment_id = ? ORDER BY host")
      .bind(environmentId)
      .all<RouteRow>();
    const routes: RouteRecord[] = [];
    const secrets = await this.listSecrets(environmentId);
    const byHash = new Map<string, string>();
    for (const secret of secrets) {
      byHash.set(await this.vaultCrypto.lookupHash(secret.name), secret.name);
    }
    for (const row of result.results ?? []) {
      const secretName = byHash.get(row.secret_key_hash);
      if (secretName == null) continue;
      routes.push({
        host: row.host,
        secretName,
        inject: row.inject,
        stripHeaders: JSON.parse(row.strip_headers) as string[],
        dummyEnvName: row.dummy_env_name,
        dummyValue: row.dummy_value,
      });
    }
    return routes;
  }

  async findRoute(environmentId: string, host: string): Promise<RouteRecord | null> {
    const routes = await this.listRoutes(environmentId);
    return routes.find((route) => route.host === host) ?? null;
  }

  async audit(input: {
    keyPrefix: string;
    action: AuditAction;
    status: string;
    host?: string;
    secretName?: string;
  }): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO audit_events (
          id, key_prefix, action, host, secret_name, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        newId(),
        input.keyPrefix,
        input.action,
        input.host ?? null,
        input.secretName ?? null,
        input.status,
        nowIso(),
      )
      .run();
  }

  private async toApiKey(row: KeyRow): Promise<ApiKeyRecord> {
    const scopes =
      row.scopes_encrypted != null
        ? (JSON.parse(await this.vaultCrypto.decrypt(row.scopes_encrypted)) as Scope[])
        : null;
    return {
      id: row.id,
      keyPrefix: row.key_prefix,
      type: row.type,
      permission: row.permission,
      mode: row.mode,
      scopes,
      revoked: row.revoked === 1,
    };
  }
}

export class StoreError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "StoreError";
    this.status = status;
  }
}
