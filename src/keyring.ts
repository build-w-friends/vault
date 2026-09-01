/**
 * The set of master-key wraps, and the two-slot rotation ceremony over them.
 *
 * Each row in `master_key_wraps` is one root fingerprint and the vault data key
 * wrapped under that root. `open` resolves the configured root to its wrap and
 * unwraps the data key for the request.
 *
 * The one condition under which key material is *generated* is a database with
 * zero wraps. Everything else fails closed: a configured root with no wrap
 * throws rather than initializing, because initializing there would create a
 * second vault sitting on top of rows nobody can read — while looking healthy.
 *
 * `prepare` refuses a slot holding the active root (409), since that would look
 * like a successful rotation and leave one root. `retire` refuses the active
 * wrap (409), since removing it makes the database unreadable by the running
 * Worker.
 *
 * @see {@link https://vault.buildwithfriends.dev/operations/master-key-rotation/}
 */
import {
  MasterKeyError,
  VaultCrypto,
  masterKeyFingerprint,
  parseMasterKey,
} from "./crypto.ts";
import type { MasterKeyWrapMeta } from "./types.ts";

type WrapRow = {
  fingerprint: string;
  wrapped_data_key: string;
  created_at: string;
};

export class KeyringError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "KeyringError";
  }
}

export class VaultKeyring {
  private constructor(
    readonly crypto: VaultCrypto,
    readonly activeFingerprint: string,
  ) {}

  static async open(
    db: D1Database,
    masterKey: string | undefined,
  ): Promise<VaultKeyring> {
    const parsed = parseMasterKey(masterKey);
    const fingerprint = await masterKeyFingerprint(parsed);
    let row = await findWrap(db, fingerprint);
    if (row == null) {
      const count = await countWraps(db);
      if (count > 0) {
        throw new MasterKeyError(
          `MASTER_KEY fingerprint ${fingerprint} has no prepared vault wrap`,
        );
      }
      const crypto = await VaultCrypto.generate();
      const prepared = await crypto.wrapForMasterKey(masterKey);
      await db
        .prepare(
          `INSERT OR IGNORE INTO master_key_wraps (
            fingerprint, wrapped_data_key, created_at
          ) VALUES (?, ?, ?)`,
        )
        .bind(prepared.fingerprint, prepared.wrappedDataKey, new Date().toISOString())
        .run();
      row = await findWrap(db, fingerprint);
      if (row == null) throw new MasterKeyError("vault key material was not initialized");
    }
    return new VaultKeyring(
      await VaultCrypto.fromWrappedDataKey(masterKey, row.wrapped_data_key),
      fingerprint,
    );
  }

  async prepare(db: D1Database, masterKey: string | undefined): Promise<string> {
    const prepared = await this.crypto.wrapForMasterKey(masterKey);
    if (prepared.fingerprint === this.activeFingerprint) {
      throw new KeyringError(409, "inactive master-key slot matches the active slot");
    }
    await db
      .prepare(
        `INSERT OR IGNORE INTO master_key_wraps (
          fingerprint, wrapped_data_key, created_at
        ) VALUES (?, ?, ?)`,
      )
      .bind(prepared.fingerprint, prepared.wrappedDataKey, new Date().toISOString())
      .run();
    return prepared.fingerprint;
  }

  async list(db: D1Database): Promise<MasterKeyWrapMeta[]> {
    const result = await db
      .prepare("SELECT fingerprint, created_at FROM master_key_wraps ORDER BY created_at")
      .all<{ fingerprint: string; created_at: string }>();
    return (result.results ?? []).map((row) => ({
      fingerprint: row.fingerprint,
      createdAt: row.created_at,
    }));
  }

  async retire(db: D1Database, fingerprint: string): Promise<void> {
    if (fingerprint === this.activeFingerprint) {
      throw new KeyringError(409, "cannot retire the active master-key wrap");
    }
    const result = await db
      .prepare("DELETE FROM master_key_wraps WHERE fingerprint = ?")
      .bind(fingerprint)
      .run();
    if ((result.meta.changes ?? 0) === 0) {
      throw new KeyringError(404, "master-key wrap not found");
    }
  }
}

async function findWrap(db: D1Database, fingerprint: string): Promise<WrapRow | null> {
  return db
    .prepare("SELECT * FROM master_key_wraps WHERE fingerprint = ?")
    .bind(fingerprint)
    .first<WrapRow>();
}

async function countWraps(db: D1Database): Promise<number> {
  const row = await db
    .prepare("SELECT COUNT(*) AS n FROM master_key_wraps")
    .first<{ n: number }>();
  return row?.n ?? 0;
}
