import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { VaultClient } from "../src/client.ts";
import { readConfig } from "../src/config.ts";
import {
  diagnosticIdFromProofOutput,
  sentryCanaryEventsUrl,
} from "../src/operational-proofs.ts";
import * as v from "valibot";

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const project = "bwf-shadow";

async function main(argv: readonly string[]): Promise<void> {
  const secrets = await loadEnvironment("prod-ci");
  // SAFETY: apps/desktop/package.json is a repository-owned package manifest
  // whose required version field is consumed by the release tooling.
  const version = (
    JSON.parse(await Bun.file(join(projectRoot, "apps/desktop/package.json")).text()) as {
      version: string;
    }
  ).version;
  const commit = (await command(["git", "rev-parse", "HEAD"])).trim();
  const release = `build-with-friends@${version}+${commit}`;
  const environment = {
    ...process.env,
    BWF_ELECTRON_SENTRY_EXPORT_ENABLED: "true",
    BWF_ELECTRON_NATIVE_CRASH_EXPORT_ENABLED: "false",
    BWF_SENTRY_SOURCE_MAP_UPLOAD_ENABLED: "true",
    BWF_RELEASE: release,
    SENTRY_AUTH_TOKEN: required(secrets, "SENTRY_AUTH_TOKEN"),
    SENTRY_DSN: required(secrets, "SENTRY_DSN"),
    SENTRY_ORG: required(secrets, "SENTRY_ORG"),
    SENTRY_PROJECT: required(secrets, "SENTRY_PROJECT"),
  };
  if (!argv.includes("--no-build")) {
    await inherited(["bun", "run", "package:desktop:unsigned"], environment);
  }
  const proof = await command(
    ["bun", "run", "--cwd", "apps/desktop", "diagnostics:sentry:proof"],
    environment,
  );
  process.stdout.write(proof);
  const diagnosticId = diagnosticIdFromProofOutput(proof);
  await waitForSentry({
    authToken: environment.SENTRY_AUTH_TOKEN,
    diagnosticId,
    organization: environment.SENTRY_ORG,
    project: environment.SENTRY_PROJECT,
    release,
  });
  console.log(`PASS  Sentry accepted and returned ${diagnosticId} for ${release}`);
}

async function loadEnvironment(environment: string): Promise<Map<string, string>> {
  const config = readConfig();
  if (config.apiUrl == null || config.apiKey == null) {
    throw new Error("vault operator configuration is missing");
  }
  const exported = await new VaultClient(config.apiUrl, config.apiKey).exportSecrets(
    project,
    environment,
  );
  return new Map(exported.secrets.map((secret) => [secret.name, secret.value]));
}

function required(secrets: ReadonlyMap<string, string>, name: string): string {
  const value = secrets.get(name)?.trim();
  if (value === undefined || value === "") throw new Error(`${name} is absent`);
  return value;
}

async function waitForSentry(input: {
  readonly authToken: string;
  readonly diagnosticId: string;
  readonly organization: string;
  readonly project: string;
  readonly release: string;
}): Promise<void> {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    const response = await fetch(sentryCanaryEventsUrl(input), {
      headers: { Authorization: `Bearer ${input.authToken}` },
    });
    if (!response.ok) {
      const detail = (await response.text()).slice(0, 500);
      throw new Error(`Sentry event query failed (${response.status}): ${detail}`);
    }
    const parsed = v.safeParse(
      v.looseObject({
        data: v.optional(v.array(v.unknown())),
      }),
      await response.json(),
    );
    const row = parsed.success
      ? parsed.output.data?.find((candidate) => {
          const release = v.safeParse(v.looseObject({ release: v.string() }), candidate);
          return release.success && release.output.release === input.release;
        })
      : undefined;
    if (row !== undefined) {
      const title = v.safeParse(v.looseObject({ title: v.unknown() }), row);
      if (
        !title.success ||
        !v.is(v.string(), title.output.title) ||
        !title.output.title.includes("ELECTRON_PROCESS_GONE")
      ) {
        throw new Error("Sentry returned the canary with the wrong diagnostic code");
      }
      return;
    }
    await Bun.sleep(2_000);
  }
  throw new Error("Sentry did not return the packaged canary within two minutes");
}

async function inherited(argv: readonly string[], env: NodeJS.ProcessEnv): Promise<void> {
  const child = Bun.spawn([...argv], {
    cwd: projectRoot,
    env,
    stdout: "inherit",
    stderr: "inherit",
  });
  if ((await child.exited) !== 0) throw new Error(`${argv[0]} failed`);
}

async function command(
  argv: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
): Promise<string> {
  const child = Bun.spawn([...argv], {
    cwd: projectRoot,
    env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (code !== 0) throw new Error(`${argv[0]} failed: ${stderr || stdout}`);
  return stdout;
}

if (import.meta.main) {
  void main(process.argv.slice(2)).catch((cause: unknown) => {
    console.error(cause instanceof Error ? cause.message : "Sentry acceptance failed");
    process.exit(1);
  });
}
