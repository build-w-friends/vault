import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createApp } from "./app.ts";
import { generateMasterKey, VaultCrypto } from "./crypto.ts";
import { openMemoryD1 } from "./d1-sqlite.ts";
import { VaultStore } from "./db.ts";

export const TEST_BOOTSTRAP_TOKEN = "test-bootstrap-token";

type TestEnv = { DB: D1Database };

const root = dirname(fileURLToPath(import.meta.url));
const migrationDirectory = join(root, "..", "migrations");
const migrationSql = readdirSync(migrationDirectory)
  .filter((name) => name.endsWith(".sql"))
  .sort()
  .map((name) => readFileSync(join(migrationDirectory, name), "utf8"))
  .join("\n");

export async function createTestVault(
  options: { issuanceFetch?: typeof fetch; now?: () => number } = {},
): Promise<{
  env: TestEnv;
  crypto: VaultCrypto;
  store: VaultStore;
  app: ReturnType<typeof createApp>;
  masterKey: string;
}> {
  const masterKey = generateMasterKey();
  const crypto = await VaultCrypto.fromMasterKey(masterKey);
  const env: TestEnv = { DB: openMemoryD1(migrationSql) };
  return {
    env,
    crypto,
    store: new VaultStore(env.DB, crypto),
    app: createApp(crypto, {
      bootstrapToken: TEST_BOOTSTRAP_TOKEN,
      activeMasterKeyFingerprint: "test-master-key",
      ...options,
    }),
    masterKey,
  };
}

export async function bootstrapUser(
  app: ReturnType<typeof createApp>,
  env: TestEnv,
): Promise<string> {
  const response = await app.request(
    "/v1/bootstrap",
    {
      method: "POST",
      headers: { "X-Vault-Bootstrap-Token": TEST_BOOTSTRAP_TOKEN },
      body: "{}",
    },
    env,
  );
  if (!response.ok) throw new Error(`bootstrap failed: ${await response.text()}`);
  // SAFETY: the app's successful /v1/bootstrap response always contains its
  // generated API key under the string-valued key field.
  const body = (await response.json()) as { key: string };
  return body.key;
}

export function authHeaders(key: string, contentType?: "application/json") {
  const headers = new Headers({ Authorization: `Bearer ${key}` });
  if (contentType !== undefined) headers.set("content-type", contentType);
  return headers;
}
