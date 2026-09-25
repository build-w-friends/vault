/**
 * `VaultStore` — every SQL statement, and the encryption boundary around them.
 *
 * Values are encrypted on the way in and decrypted on the way out here, so no
 * route handler ever holds a ciphertext and no query ever holds a plaintext
 * name. A secret's name is written twice: `key_encrypted` for retrieval and
 * `key_hash` (keyed HMAC) for lookup and uniqueness.
 *
 * Audit paging is keyset, not offset: `(created_at DESC, id DESC)` matches the
 * index exactly, so a deep page is a range scan and a row inserted mid-scroll
 * cannot shift the window.
 *
 * Failures throw `PolicyError` with the HTTP status they should surface, which
 * is what lets `app.ts` translate a constraint violation into a 404 or 409
 * without re-deriving the reason.
 *
 * @see {@link https://vault.buildwithfriends.dev/reference/database/}
 */
import type { VaultCrypto } from "./crypto.ts";
import { PolicyError } from "./policy.ts";
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
  AuditRecord,
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
  expires_at: string;
  revoked: number;
  revoked_at: string | null;
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

type AuditRow = {
  id: string;
  key_prefix: string;
  action: AuditAction;
  host_encrypted: string | null;
  secret_name_encrypted: string | null;
  status: string;
  created_at: string;
};

/** `mcp.ts` imports the store's error under this name. */

const LAST_USER_KEY = "cannot revoke the last active user key";
const INSERT_ENVIRONMENT =
  "INSERT INTO environments (id, project_id, name, created_at) VALUES (?, ?, ?, ?)";

function nowIso(): string {
  return new Date().toISOString();
}

function newId(): string {
  return crypto.randomUUID();
}

function isUniqueConstraintFailure(cause: unknown): boolean {
  return String(cause).includes("UNIQUE constraint failed");
}

export class VaultStore {
  constructor(
    private readonly db: D1Database,
    private readonly vaultCrypto: VaultCrypto,
  ) {}

  async insertKey(input: {
    plaintext: string;
    prefix: string;
    type: KeyType;
    permission: Permission;
    mode: KeyMode | null;
    label: string | null;
    scopes: Scope[] | null;
    expiresAt: string;
  }): Promise<void> {
    const insertKey = await this.prepareInsertKey(input);
    await insertKey.run();
  }

  async claimBootstrapKey(input: {
    plaintext: string;
    prefix: string;
    label: string;
    expiresAt: string;
  }): Promise<void> {
    const claimedAt = nowIso();
    try {
      await this.db.batch([
        this.db
          .prepare(
            `INSERT INTO bootstrap_state (singleton, claimed_at, key_prefix)
             VALUES (1, ?, ?)`,
          )
          .bind(claimedAt, input.prefix),
        await this.prepareInsertKey({
          ...input,
          type: "user",
          permission: "full",
          mode: null,
          scopes: null,
        }),
      ]);
    } catch {
      throw new PolicyError(409, "already bootstrapped");
    }
  }

  async isBootstrapped(): Promise<boolean> {
    const row = await this.db
      .prepare("SELECT singleton FROM bootstrap_state WHERE singleton = 1")
      .first<{ singleton: number }>();
    return row != null;
  }

  private async prepareInsertKey(input: {
    plaintext: string;
    prefix: string;
    type: KeyType;
    permission: Permission;
    mode: KeyMode | null;
    label: string | null;
    scopes: Scope[] | null;
    expiresAt: string;
  }): Promise<D1PreparedStatement> {
    const hash = await this.vaultCrypto.sha256(input.plaintext);
    const labelEncrypted =
      input.label != null ? await this.vaultCrypto.encrypt(input.label) : null;
    const scopesEncrypted =
      input.scopes != null
        ? await this.vaultCrypto.encrypt(JSON.stringify(input.scopes))
        : null;
    return this.db
      .prepare(
        `INSERT INTO api_keys (
          id, key_prefix, key_hash, type, label_encrypted, scopes_encrypted,
          permission, mode, created_at, expires_at, revoked
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
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
        input.expiresAt,
      );
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

  async findKeyByPrefix(prefix: string): Promise<ApiKeyRecord | null> {
    const row = await this.db
      .prepare("SELECT * FROM api_keys WHERE key_prefix = ?")
      .bind(prefix)
      .first<KeyRow>();
    return row == null ? null : this.toApiKey(row);
  }

  async listKeys(includeRevoked = false): Promise<ApiKeyRecord[]> {
    const result = await this.db
      .prepare(
        `SELECT * FROM api_keys
         ${includeRevoked ? "" : "WHERE revoked = 0"}
         ORDER BY created_at`,
      )
      .all<KeyRow>();
    return Promise.all((result.results ?? []).map((row) => this.toApiKey(row)));
  }

  async revokeKey(prefix: string): Promise<boolean> {
    const result = await guardLastUserKey(this.revokeStatement(prefix).run());
    return (result.meta.changes ?? 0) > 0;
  }

  private revokeStatement(prefix: string): D1PreparedStatement {
    return this.db
      .prepare(
        `UPDATE api_keys SET revoked = 1, revoked_at = ?
         WHERE key_prefix = ? AND revoked = 0`,
      )
      .bind(nowIso(), prefix);
  }

  async rotateKey(
    current: ApiKeyRecord,
    replacement: {
      plaintext: string;
      prefix: string;
      expiresAt: string;
    },
  ): Promise<void> {
    await guardLastUserKey(
      this.db.batch([
        await this.prepareInsertKey({
          ...replacement,
          type: current.type,
          permission: current.permission,
          mode: current.mode,
          label: current.label,
          scopes: current.scopes,
        }),
        this.revokeStatement(current.keyPrefix),
      ]),
    );
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
    try {
      await this.db
        .prepare("INSERT INTO projects (id, name, created_at) VALUES (?, ?, ?)")
        .bind(id, normalized, nowIso())
        .run();
    } catch (error) {
      if (isUniqueConstraintFailure(error)) {
        throw new PolicyError(409, `project "${normalized}" already exists`);
      }
      throw error;
    }
    const created = nowIso();
    for (const env of ["dev", "prod"]) {
      await this.db.prepare(INSERT_ENVIRONMENT).bind(newId(), id, env, created).run();
    }
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
    const normalized = name.toLowerCase();
    try {
      await this.db
        .prepare(INSERT_ENVIRONMENT)
        .bind(newId(), projectId, normalized, nowIso())
        .run();
    } catch (error) {
      if (isUniqueConstraintFailure(error)) {
        throw new PolicyError(409, `environment "${normalized}" already exists`);
      }
      throw error;
    }
  }

  async deleteEnvironment(projectId: string, name: string): Promise<boolean> {
    const result = await this.db
      .prepare("DELETE FROM environments WHERE project_id = ? AND name = ?")
      .bind(projectId, name.toLowerCase())
      .run();
    return (result.meta.changes ?? 0) > 0;
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
    if (project == null) throw new PolicyError(404, "project not found");
    const environment = await this.getEnvironment(project.id, envName);
    if (environment == null) throw new PolicyError(404, "environment not found");
    return { projectId: project.id, environmentId: environment.id };
  }

  async listSecretRows(environmentId: string): Promise<SecretRow[]> {
    const result = await this.db
      .prepare("SELECT * FROM secrets WHERE environment_id = ?")
      .bind(environmentId)
      .all<SecretRow>();
    return result.results ?? [];
  }

  /** Names and kinds only; values stay encrypted. */
  async listSecretMeta(environmentId: string): Promise<SecretMeta[]> {
    const rows = await this.listSecretRows(environmentId);
    const meta: SecretMeta[] = [];
    for (const row of rows) {
      meta.push({
        name: await this.vaultCrypto.decrypt(row.key_encrypted),
        kind: row.kind,
      });
    }
    return meta.sort(byName);
  }

  async listSecrets(environmentId: string): Promise<SecretRecord[]> {
    const rows = await this.listSecretRows(environmentId);
    const secrets: SecretRecord[] = [];
    for (const row of rows) secrets.push(await this.decryptSecret(row));
    return secrets.sort(byName);
  }

  private async decryptSecret(row: SecretRow): Promise<SecretRecord> {
    return {
      name: await this.vaultCrypto.decrypt(row.key_encrypted),
      value: await this.vaultCrypto.decrypt(row.value_encrypted),
      kind: row.kind,
    };
  }

  async createSecret(
    environmentId: string,
    name: string,
    value: string,
    kind: SecretKind,
  ): Promise<void> {
    if (value.length === 0) throw new PolicyError(400, "secret value must not be empty");
    const row = await this.db
      .prepare(
        `INSERT INTO secrets (id, environment_id, key_encrypted, key_hash, value_encrypted, kind, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(environment_id, key_hash) DO NOTHING RETURNING id`,
      )
      .bind(
        newId(),
        environmentId,
        await this.vaultCrypto.encrypt(name),
        await this.vaultCrypto.lookupHash(name),
        await this.vaultCrypto.encrypt(value),
        kind,
        nowIso(),
      )
      .first<{ id: string }>();
    if (row == null)
      throw new PolicyError(409, "secret already exists; no value was changed");
  }

  async setSecret(
    environmentId: string,
    name: string,
    value: string,
    kind: SecretKind,
  ): Promise<void> {
    if (value.length === 0) throw new PolicyError(400, "secret value must not be empty");
    await this.db
      .prepare(
        `INSERT INTO secrets (
          id, environment_id, key_encrypted, key_hash, value_encrypted, kind, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(environment_id, key_hash) DO UPDATE SET
          key_encrypted = excluded.key_encrypted,
          value_encrypted = excluded.value_encrypted,
          kind = excluded.kind,
          updated_at = excluded.updated_at`,
      )
      .bind(
        newId(),
        environmentId,
        await this.vaultCrypto.encrypt(name),
        await this.vaultCrypto.lookupHash(name),
        await this.vaultCrypto.encrypt(value),
        kind,
        nowIso(),
      )
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
    return row == null ? null : this.decryptSecret(row);
  }

  async upsertRoute(environmentId: string, route: RouteRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO routes (
          id, environment_id, host, secret_key_hash, inject, strip_headers,
          dummy_env_name, dummy_value
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(environment_id, host) DO UPDATE SET
          secret_key_hash = excluded.secret_key_hash,
          inject = excluded.inject,
          strip_headers = excluded.strip_headers,
          dummy_env_name = excluded.dummy_env_name,
          dummy_value = excluded.dummy_value`,
      )
      .bind(
        newId(),
        environmentId,
        route.host,
        await this.vaultCrypto.lookupHash(route.secretName),
        route.inject,
        JSON.stringify(route.stripHeaders),
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
        // SAFETY: route rows are written only from RouteRecord.stripHeaders,
        // serialized as a JSON string array by putRoute.
        stripHeaders: JSON.parse(row.strip_headers) as string[],
        dummyEnvName: row.dummy_env_name,
        dummyValue: row.dummy_value,
      });
    }
    return routes;
  }

  async audit(input: {
    keyPrefix: string;
    action: AuditAction;
    status: string;
    host?: string;
    secretName?: string;
  }): Promise<void> {
    const hostEncrypted =
      input.host != null ? await this.vaultCrypto.encrypt(input.host) : null;
    const secretNameEncrypted =
      input.secretName != null ? await this.vaultCrypto.encrypt(input.secretName) : null;
    await this.db
      .prepare(
        `INSERT INTO audit_events (
          id, key_prefix, action, host_encrypted, secret_name_encrypted,
          status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        newId(),
        input.keyPrefix,
        input.action,
        hostEncrypted,
        secretNameEncrypted,
        input.status,
        nowIso(),
      )
      .run();
  }

  async listAudit(input: {
    limit: number;
    beforeCreatedAt?: string;
    beforeId?: string;
  }): Promise<AuditRecord[]> {
    const boundedLimit = Math.max(1, Math.min(input.limit, 200));
    const cursorClause =
      input.beforeCreatedAt != null && input.beforeId != null
        ? "WHERE created_at < ? OR (created_at = ? AND id < ?)"
        : "";
    const statement = this.db.prepare(
      `SELECT * FROM audit_events
       ${cursorClause}
       ORDER BY created_at DESC, id DESC
       LIMIT ?`,
    );
    const result =
      input.beforeCreatedAt != null && input.beforeId != null
        ? await statement
            .bind(
              input.beforeCreatedAt,
              input.beforeCreatedAt,
              input.beforeId,
              boundedLimit,
            )
            .all<AuditRow>()
        : await statement.bind(boundedLimit).all<AuditRow>();
    return Promise.all(
      (result.results ?? []).map(async (row) => ({
        id: row.id,
        keyPrefix: row.key_prefix,
        action: row.action,
        host:
          row.host_encrypted == null
            ? null
            : await this.vaultCrypto.decrypt(row.host_encrypted),
        secretName:
          row.secret_name_encrypted == null
            ? null
            : await this.vaultCrypto.decrypt(row.secret_name_encrypted),
        status: row.status,
        createdAt: row.created_at,
      })),
    );
  }

  async pruneAudit(before: string): Promise<number> {
    const result = await this.db
      .prepare("DELETE FROM audit_events WHERE created_at < ?")
      .bind(before)
      .run();
    return result.meta.changes ?? 0;
  }

  private async toApiKey(row: KeyRow): Promise<ApiKeyRecord> {
    // SAFETY: createKey encrypts the JSON serialization of its validated Scope[];
    // rotateKey preserves that value when issuing the replacement key.
    const scopes =
      row.scopes_encrypted != null
        ? (JSON.parse(await this.vaultCrypto.decrypt(row.scopes_encrypted)) as Scope[])
        : null;
    return {
      id: row.id,
      keyPrefix: row.key_prefix,
      type: row.type,
      label:
        row.label_encrypted == null
          ? null
          : await this.vaultCrypto.decrypt(row.label_encrypted),
      permission: row.permission,
      mode: row.mode,
      scopes,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
      expiresAt: row.expires_at,
      revoked: row.revoked === 1,
      revokedAt: row.revoked_at,
    };
  }
}

function byName(left: { name: string }, right: { name: string }): number {
  return left.name.localeCompare(right.name);
}

/** The `api_keys` trigger refuses to revoke the last active user key. */
async function guardLastUserKey<T>(operation: Promise<T>): Promise<T> {
  try {
    return await operation;
  } catch (error) {
    if (String(error).includes(LAST_USER_KEY)) throw new PolicyError(409, LAST_USER_KEY);
    throw error;
  }
}
