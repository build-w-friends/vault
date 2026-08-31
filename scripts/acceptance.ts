import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { VaultClient } from "../src/client.ts";
import { generateMasterKey } from "../src/crypto.ts";
import { randomSecretValue } from "../src/keys.ts";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const state = mkdtempSync(join(tmpdir(), "bwf-vault-acceptance-"));
const envFile = join(state, "vault.env");
const port = 18787;
const origin = `http://127.0.0.1:${port}`;
const bootstrapToken = randomSecretValue();

type WorkerProcess = {
  exited: Promise<number>;
  kill: () => void;
  stdout: ReadableStream<Uint8Array>;
  stderr: ReadableStream<Uint8Array>;
};

writeFileSync(
  envFile,
  [
    `MASTER_KEY_PRIMARY=${generateMasterKey()}`,
    `MASTER_KEY_SECONDARY=${generateMasterKey()}`,
    `BOOTSTRAP_TOKEN=${bootstrapToken}`,
    "",
  ].join("\n"),
  { mode: 0o600 },
);

let worker: WorkerProcess | null = null;
try {
  await checked([
    "bunx",
    "wrangler",
    "d1",
    "migrations",
    "apply",
    "DB",
    "--local",
    "--persist-to",
    state,
  ]);
  worker = Bun.spawn(
    [
      "bunx",
      "wrangler",
      "dev",
      "--local",
      "--port",
      String(port),
      "--persist-to",
      state,
      "--env-file",
      envFile,
    ],
    { cwd: packageRoot, stdout: "pipe", stderr: "pipe" },
  );
  await waitForWorker(origin, worker);

  const temporary = await new VaultClient(origin, "").bootstrap(
    bootstrapToken,
    "acceptance bootstrap",
  );
  const client = new VaultClient(origin, temporary.key);
  await client.createProject("acceptance");
  await client.patchSecrets("acceptance", "dev", {
    set: [{ name: "ACCEPTANCE_TOKEN", value: "acceptance-value", kind: "secret" }],
  });
  const listed = await client.listSecretMeta("acceptance", "dev");
  if (listed.secrets.length !== 1 || listed.secrets[0]?.name !== "ACCEPTANCE_TOKEN") {
    throw new Error("local Worker did not return the stored secret metadata");
  }
  const read = await client.getSecret("acceptance", "dev", "ACCEPTANCE_TOKEN");
  if (read.value !== "acceptance-value") {
    throw new Error("local Worker did not decrypt the stored secret");
  }
  const audit = await client.listAudit(20);
  if (!audit.events.some((event) => event.action === "set")) {
    throw new Error("local Worker did not record the secret write audit event");
  }
  console.log(
    "vault acceptance passed: workerd + D1 + bootstrap + encrypted CRUD + audit",
  );
} finally {
  if (worker != null) {
    worker.kill();
    await worker.exited;
  }
  rmSync(state, { recursive: true, force: true });
}

async function checked(command: string[]): Promise<void> {
  const child = Bun.spawn(command, {
    cwd: packageRoot,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (code !== 0) {
    throw new Error(`command failed (${command.join(" ")}):\n${stdout}${stderr}`);
  }
}

async function waitForWorker(url: string, child: WorkerProcess): Promise<void> {
  const deadline = Date.now() + 30_000;
  let exited = false;
  void child.exited.then(() => {
    exited = true;
  });
  while (Date.now() < deadline) {
    if (exited) {
      throw new Error("wrangler dev exited before becoming ready");
    }
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // Wrangler has not bound the port yet.
    }
    await Bun.sleep(200);
  }
  throw new Error("wrangler dev did not become ready within 30 seconds");
}
