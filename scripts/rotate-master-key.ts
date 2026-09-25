import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { VaultClient } from "../src/client.ts";
import {
  generateMasterKey,
  masterKeyFingerprint,
  parseMasterKey,
} from "../src/crypto.ts";
import { stripJsonComments } from "../src/jsonc.ts";
import { secretsStoreSecretId } from "../src/operational-proofs.ts";
import * as v from "valibot";
import { operatorClient } from "./operator.ts";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
Bun.$.cwd(packageRoot);

const slotSchema = v.picklist(["primary", "secondary"]);
type Slot = v.InferOutput<typeof slotSchema>;
const configurationSchema = v.looseObject({
  env: v.looseObject({
    production: v.looseObject({
      vars: v.looseObject({ ACTIVE_MASTER_KEY: slotSchema }),
      secrets_store_secrets: v.array(
        v.looseObject({
          binding: v.string(),
          secret_name: v.string(),
          store_id: v.string(),
        }),
      ),
    }),
  }),
});

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
  const list =
    await Bun.$`bunx wrangler secrets-store secret list ${binding.store_id} --remote --env production`
      .quiet()
      .nothrow();
  if (list.exitCode !== 0) throw new Error("wrangler failed");
  const secretId = secretsStoreSecretId(
    list.stdout.toString() + list.stderr.toString(),
    binding.secret_name,
  );
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
    // The timestamped path is new on every run, so the mode applies.
    { mode: 0o600 },
  );
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

function parseConfiguration(): v.InferOutput<typeof configurationSchema> {
  const value = JSON.parse(
    stripJsonComments(readFileSync(join(packageRoot, "wrangler.jsonc"), "utf8")),
  );
  const parsed = v.safeParse(configurationSchema, value);
  if (!parsed.success) {
    const invalidSlot = parsed.issues.some((issue) =>
      issue.path?.some((segment) => segment.key === "ACTIVE_MASTER_KEY"),
    );
    if (invalidSlot) {
      throw new Error("production ACTIVE_MASTER_KEY is invalid");
    }
    throw new Error("vault Wrangler configuration is invalid");
  }
  return parsed.output;
}

async function updateSecretWithWrangler(
  storeId: string,
  secretId: string,
  value: string,
): Promise<void> {
  // Root rotation is always an explicit human ceremony. `--value` is safe here
  // because Bun's built-in shell runs the logged-in Wrangler client directly and
  // escapes every interpolated argument: no system shell or history entry sees
  // the value, and both output streams stay captured.
  const comment = "Root of trust for isolated bwf-vault replacement candidate";
  const update =
    await Bun.$`bunx wrangler secrets-store secret update ${storeId} --secret-id ${secretId} --value ${value} --scopes workers --comment ${comment} --remote`
      .quiet()
      .nothrow();
  if (update.exitCode !== 0) {
    throw new Error(
      `Secrets Store update failed: ${update.stderr.toString() || update.stdout.toString()}`,
    );
  }
}

if (import.meta.main) {
  void main(process.argv.slice(2)).catch((cause: unknown) => {
    console.error(
      cause instanceof Error ? cause.message : "master-key preparation failed",
    );
    process.exit(1);
  });
}
