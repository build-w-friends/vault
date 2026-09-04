import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { VaultClient } from "../src/client.ts";
import { readConfig } from "../src/config.ts";
import { stripJsonComments } from "../src/jsonc.ts";
import {
  d1DatabaseIdFromListOutput,
  deployedWorkersDevUrl,
} from "../src/operational-proofs.ts";
import * as v from "valibot";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const sourceConfigPath = join(packageRoot, "wrangler.jsonc");
const project = "bwf-shadow";
const canaryEnvironment = "prod-worker";
const canarySecret = "POSTHOG_PROJECT_TOKEN";

const productionConfigSchema = v.looseObject({
  account_id: v.string(),
  compatibility_date: v.string(),
  compatibility_flags: v.optional(v.array(v.string())),
  env: v.looseObject({
    production: v.looseObject({
      vars: v.looseObject({}),
      secrets_store_secrets: v.array(v.looseObject({})),
    }),
  }),
});

async function main(): Promise<void> {
  const stamp = new Date().toISOString().replaceAll(/[:.]/gu, "-");
  const evidenceDirectory = join(homedir(), ".config", "poc-vault", "recovery", stamp);
  mkdirSync(evidenceDirectory, { mode: 0o700, recursive: true });
  chmodSync(evidenceDirectory, 0o700);
  const timeTravelPath = join(evidenceDirectory, "time-travel.json");
  const exportPath = join(evidenceDirectory, "bwf-vault.sql");

  const timeTravel = await command([
    "bunx",
    "wrangler",
    "d1",
    "time-travel",
    "info",
    "DB",
    "--env",
    "production",
    "--json",
  ]);
  writeFileSync(timeTravelPath, timeTravel, { mode: 0o600 });
  chmodSync(timeTravelPath, 0o600);
  await command([
    "bunx",
    "wrangler",
    "d1",
    "export",
    "DB",
    "--env",
    "production",
    "--remote",
    "--skip-confirmation",
    "--output",
    exportPath,
  ]);
  chmodSync(exportPath, 0o600);
  console.log("PASS  production Time Travel bookmark and encrypted export captured");

  const temporaryDirectory = mkdtempSync(join(tmpdir(), "bwf-vault-recovery-"));
  chmodSync(temporaryDirectory, 0o700);
  const suffix = crypto.randomUUID().replaceAll("-", "").slice(0, 12);
  const databaseName = `bwf-vault-recovery-${suffix}`;
  const workerName = `bwf-vault-recovery-${suffix}`;
  const temporaryConfigPath = join(temporaryDirectory, "wrangler.json");
  let databaseId: string | null = null;
  let workerCreated = false;
  const cleanupFailures: string[] = [];
  try {
    await command(["bunx", "wrangler", "d1", "create", databaseName]);
    databaseId = d1DatabaseIdFromListOutput(
      await command(["bunx", "wrangler", "d1", "list", "--json"]),
      databaseName,
    );
    writeTemporaryConfig(temporaryConfigPath, workerName, databaseName, databaseId);
    await inherited([
      "bunx",
      "wrangler",
      "d1",
      "execute",
      "DB",
      "--remote",
      "--yes",
      "--file",
      exportPath,
      "--config",
      temporaryConfigPath,
    ]);
    const deployed = await command([
      "bunx",
      "wrangler",
      "deploy",
      "--config",
      temporaryConfigPath,
      "--message",
      "Disposable bwf-vault recovery rehearsal",
    ]);
    workerCreated = true;
    const workerUrl = deployedWorkersDevUrl(deployed);
    await waitForWorker(workerUrl);
    await verifyRecoveredVault(workerUrl);
    console.log(
      "PASS  disposable D1 import decrypted through the production root binding",
    );
    console.log("PASS  recovered operator API key, canary secret, and audit continuity");
  } finally {
    if (workerCreated) {
      try {
        await command([
          "bunx",
          "wrangler",
          "delete",
          workerName,
          "--force",
          "--config",
          temporaryConfigPath,
        ]);
      } catch {
        cleanupFailures.push(`Worker ${workerName}`);
      }
    }
    if (databaseId !== null) {
      try {
        await command([
          "bunx",
          "wrangler",
          "d1",
          "delete",
          databaseId,
          "--skip-confirmation",
          "--config",
          temporaryConfigPath,
        ]);
      } catch {
        cleanupFailures.push(`D1 ${databaseId}`);
      }
    }
    rmSync(temporaryDirectory, { recursive: true, force: true });
    if (cleanupFailures.length === 0 && databaseId !== null) {
      console.log("PASS  disposable Worker and D1 database removed");
    }
  }
  if (cleanupFailures.length > 0) {
    throw new Error(
      `disposable recovery resources need manual cleanup: ${cleanupFailures.join(", ")}`,
    );
  }
  console.log(`Recovery evidence retained at ${evidenceDirectory}`);
}

function productionConfig(): v.InferOutput<typeof productionConfigSchema> {
  const value = JSON.parse(stripJsonComments(readFileSync(sourceConfigPath, "utf8")));
  const parsed = v.safeParse(productionConfigSchema, value);
  if (!parsed.success) throw new Error("vault Wrangler configuration is invalid");
  return parsed.output;
}

function writeTemporaryConfig(
  path: string,
  workerName: string,
  databaseName: string,
  databaseId: string,
): void {
  const source = productionConfig();
  const production = source.env.production;
  writeFileSync(
    path,
    `${JSON.stringify(
      {
        name: workerName,
        account_id: source.account_id,
        main: resolve(packageRoot, "src/worker.ts"),
        compatibility_date: source.compatibility_date,
        compatibility_flags: source.compatibility_flags ?? [],
        workers_dev: true,
        preview_urls: false,
        observability: { enabled: false },
        vars: production.vars,
        secrets_store_secrets: production.secrets_store_secrets,
        d1_databases: [
          {
            binding: "DB",
            database_name: databaseName,
            database_id: databaseId,
          },
        ],
      },
      null,
      2,
    )}\n`,
    { mode: 0o600 },
  );
  chmodSync(path, 0o600);
}

async function verifyRecoveredVault(origin: URL): Promise<void> {
  const config = readConfig();
  if (config.apiKey == null) throw new Error("vault operator API key is missing");
  const client = new VaultClient(origin.href, config.apiKey);
  const keys = await client.listMasterKeys();
  if (!keys.wraps.some((wrap) => wrap.fingerprint === keys.activeFingerprint)) {
    throw new Error("recovered vault did not open the active root wrap");
  }
  const exported = await client.exportSecrets(project, canaryEnvironment);
  const secret = exported.secrets.find((candidate) => candidate.name === canarySecret);
  if (secret?.value == null || secret.value.length === 0) {
    throw new Error("recovered canary secret was absent or empty");
  }
  const audit = await client.listAudit(1);
  if (audit.events.length === 0) throw new Error("recovered audit history was empty");
}

async function waitForWorker(origin: URL): Promise<void> {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(origin, { redirect: "manual" });
      if (response.ok) return;
    } catch {
      // The disposable workers.dev route has not propagated yet.
    }
    await Bun.sleep(500);
  }
  throw new Error("disposable recovery Worker did not become reachable");
}

async function inherited(argv: readonly string[]): Promise<void> {
  const child = Bun.spawn([...argv], {
    cwd: packageRoot,
    env: process.env,
    stdout: "inherit",
    stderr: "inherit",
  });
  if ((await child.exited) !== 0) throw new Error(`${argv[1] ?? argv[0]} failed`);
}

async function command(argv: readonly string[]): Promise<string> {
  const child = Bun.spawn([...argv], {
    cwd: packageRoot,
    env: process.env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (code !== 0) throw new Error(`${argv[1] ?? argv[0]} failed: ${stderr || stdout}`);
  return `${stdout}${stderr}`;
}

if (import.meta.main) {
  void main().catch((cause: unknown) => {
    console.error(cause instanceof Error ? cause.message : "recovery rehearsal failed");
    process.exit(1);
  });
}
