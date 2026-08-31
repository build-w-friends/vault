import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createApp } from "./app.ts";
import { generateMasterKey, VaultCrypto } from "./crypto.ts";
import { openMemoryD1 } from "./d1-sqlite.ts";
import { VaultStore } from "./db.ts";
import type { VaultEnv } from "./types.ts";

const root = dirname(fileURLToPath(import.meta.url));
const migrationSql = readFileSync(
  join(root, "..", "migrations", "0001_init.sql"),
  "utf8",
);

export async function createTestVault(): Promise<{
  env: VaultEnv;
  crypto: VaultCrypto;
  store: VaultStore;
  app: ReturnType<typeof createApp>;
  masterKey: string;
}> {
  const masterKey = generateMasterKey();
  const crypto = await VaultCrypto.fromMasterKey(masterKey);
  const env: VaultEnv = { DB: openMemoryD1(migrationSql), MASTER_KEY: masterKey };
  return {
    env,
    crypto,
    store: new VaultStore(env.DB, crypto),
    app: createApp(crypto),
    masterKey,
  };
}

export async function bootstrapUser(
  app: ReturnType<typeof createApp>,
  env: VaultEnv,
): Promise<string> {
  const response = await app.request(
    "/v1/bootstrap",
    { method: "POST", body: "{}" },
    env,
  );
  if (!response.ok) throw new Error(`bootstrap failed: ${await response.text()}`);
  const body = (await response.json()) as { key: string };
  return body.key;
}

export function authHeaders(key: string, body?: unknown): Record<string, string> {
  return {
    Authorization: `Bearer ${key}`,
    ...(body != null ? { "content-type": "application/json" } : {}),
  };
}
