import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { VaultClient } from "../src/client.ts";
import { readConfig } from "../src/config.ts";
import {
  generateMasterKey,
  masterKeyFingerprint,
  parseMasterKey,
} from "../src/crypto.ts";
import { parseJsonc } from "../src/jsonc.ts";
import { secretsStoreSecretId } from "../src/operational-proofs.ts";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

type Slot = "primary" | "secondary";

type Configuration = {
  readonly env: {
    readonly production: {
      readonly vars: { readonly ACTIVE_MASTER_KEY: Slot };
      readonly secrets_store_secrets: readonly {
        readonly binding: string;
        readonly secret_name: string;
        readonly store_id: string;
      }[];
    };
  };
};

async function main(argv: readonly string[]): Promise<void> {
  if (argv.length !== 2 || argv[0] !== "prepare" || argv[1] !== "--yes") {
    throw new Error("usage: rotate-master-key.ts prepare --yes");
  }
  const configuration = parseConfiguration();
  const activeSlot = configuration.env.production.vars.ACTIVE_MASTER_KEY;
  const inactiveSlot: Slot = activeSlot === "primary" ? "secondary" : "primary";
  const binding = configuration.env.production.secrets_store_secrets.find(
    (candidate) => candidate.binding === `MASTER_KEY_${inactiveSlot.toUpperCase()}`,
  );
  if (binding === undefined) throw new Error("inactive Secrets Store binding is missing");
  const client = operatorClient();
  const before = await client.listMasterKeys();
  const list = await command([
    "bunx",
    "wrangler",
    "secrets-store",
    "secret",
    "list",
    binding.store_id,
    "--remote",
    "--env",
    "production",
  ]);
  const secretId = secretsStoreSecretId(list, binding.secret_name);
  const root = generateMasterKey();
  const expectedFingerprint = await masterKeyFingerprint(parseMasterKey(root));
  await updateSecretWithWrangler(binding.store_id, secretId, root);
  const prepared = await prepareExpectedRoot(client, expectedFingerprint);
  const after = await client.listMasterKeys();
  if (!after.wraps.some((wrap) => wrap.fingerprint === prepared.fingerprint)) {
    throw new Error("new root wrap was not persisted");
  }
  const receiptDirectory = join(homedir(), ".config", "poc-vault", "rotations");
  mkdirSync(receiptDirectory, { mode: 0o700, recursive: true });
  chmodSync(receiptDirectory, 0o700);
  const receiptPath = join(
    receiptDirectory,
    `${new Date().toISOString().replaceAll(/[:.]/gu, "-")}.json`,
  );
  writeFileSync(
    receiptPath,
    `${JSON.stringify(
      {
        activeSlotBefore: activeSlot,
        preparedFingerprint: expectedFingerprint,
        preparedSlot: inactiveSlot,
      },
      null,
      2,
    )}\n`,
    { mode: 0o600 },
  );
  chmodSync(receiptPath, 0o600);
  console.log(`prepared ${prepared.fingerprint} in ${inactiveSlot}`);
  console.log(`previous active ${before.activeFingerprint} in ${activeSlot}`);
  console.log(`rotation receipt ${receiptPath}`);
}

async function prepareExpectedRoot(
  client: VaultClient,
  expectedFingerprint: string,
): Promise<{ fingerprint: string }> {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const prepared = await client.prepareMasterKey();
    if (prepared.fingerprint === expectedFingerprint) return prepared;
    await Bun.sleep(1_000);
  }
  throw new Error("Secrets Store did not propagate the expected root within one minute");
}

function parseConfiguration(): Configuration {
  const value = parseJsonc(readFileSync(join(packageRoot, "wrangler.jsonc"), "utf8"));
  if (typeof value !== "object" || value === null) {
    throw new Error("vault Wrangler configuration is invalid");
  }
  const configuration = value as Configuration;
  const slot = configuration.env.production.vars.ACTIVE_MASTER_KEY;
  if (slot !== "primary" && slot !== "secondary") {
    throw new Error("production ACTIVE_MASTER_KEY is invalid");
  }
  return configuration;
}

function operatorClient(): VaultClient {
  const config = readConfig();
  if (config.apiUrl == null || config.apiKey == null) {
    throw new Error("vault operator configuration is missing");
  }
  return new VaultClient(config.apiUrl, config.apiKey);
}

async function updateSecretWithWrangler(
  storeId: string,
  secretId: string,
  value: string,
): Promise<void> {
  // Root rotation is always an explicit human ceremony. `--value` is safe here
  // because Bun spawns the logged-in Wrangler client directly: there is no
  // shell command or history entry, and both output streams stay captured.
  const child = Bun.spawn(
    [
      "bunx",
      "wrangler",
      "secrets-store",
      "secret",
      "update",
      storeId,
      "--secret-id",
      secretId,
      "--value",
      value,
      "--scopes",
      "workers",
      "--comment",
      "Root of trust for isolated bwf-vault replacement candidate",
      "--remote",
    ],
    { cwd: packageRoot, stdout: "pipe", stderr: "pipe" },
  );
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (code !== 0) throw new Error(`Secrets Store update failed: ${stderr || stdout}`);
}

async function command(argv: readonly string[]): Promise<string> {
  const child = Bun.spawn([...argv], {
    cwd: packageRoot,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (code !== 0) throw new Error(`${argv[1] ?? argv[0]} failed`);
  return `${stdout}${stderr}`;
}

if (import.meta.main) {
  void main(process.argv.slice(2)).catch((error: unknown) => {
    console.error(
      error instanceof Error ? error.message : "master-key preparation failed",
    );
    process.exit(1);
  });
}
