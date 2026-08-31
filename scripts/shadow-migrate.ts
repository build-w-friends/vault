import { resolve } from "node:path";

import { VaultClient } from "../src/client.ts";
import { readConfig } from "../src/config.ts";

const SHADOW_PROJECT = "bwf-shadow";
const DEFAULT_ENVIRONMENTS = ["dev", "staging", "prod"] as const;
const repoRoot = resolve(import.meta.dir, "../../..");

export type InfisicalInventory = {
  names: string[];
  duplicateRows: number;
};

export function parseInfisicalNames(output: string): InfisicalInventory {
  const rows: string[] = [];
  for (const line of output.split(/\r?\n/u)) {
    const fields = line.split("│");
    const name = fields[1]?.trim();
    if (name == null || name === "" || name === "SECRET NAME") continue;
    if (/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name)) rows.push(name);
  }
  const names = [...new Set(rows)].sort();
  return { names, duplicateRows: rows.length - names.length };
}

export function parseInfisicalFolderNames(output: string): string[] {
  const names: string[] = [];
  for (const line of output.split(/\r?\n/u)) {
    const fields = line.split("│");
    const name = fields[1]?.trim();
    if (name == null || name === "" || name === "FOLDER NAME") continue;
    if (/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(name)) names.push(name);
  }
  return [...new Set(names)].sort();
}

export function shadowEnvironmentName(
  sourceEnvironment: string,
  sourcePath: string,
): string {
  const suffix =
    sourcePath === "/" ? "root" : sourcePath.split("/").filter(Boolean).join("-");
  return `${sourceEnvironment}-${suffix}`;
}

type PathInventory = InfisicalInventory & {
  sourceEnvironment: string;
  sourcePath: string;
  targetEnvironment: string;
};

type PathMigrationReceipt = {
  sourceEnvironment: string;
  sourcePath: string;
  targetEnvironment: string;
  sourceNames: number;
  duplicateSourceRows: number;
  prunedNames: number;
  parity: true;
};

async function main(argv: string[]): Promise<void> {
  if (argv[0] === "--child") {
    const [sourceEnvironment, sourcePath, targetEnvironment, ...names] = argv.slice(1);
    if (sourceEnvironment == null || sourcePath == null || targetEnvironment == null) {
      throw new Error("shadow migration child is missing source path metadata");
    }
    console.log(
      JSON.stringify(
        await importInjectedPath(sourceEnvironment, sourcePath, targetEnvironment, names),
      ),
    );
    return;
  }

  const requested = argv.length > 0 ? argv : [...DEFAULT_ENVIRONMENTS];
  for (const sourceEnvironment of requested) {
    if (!/^[a-z][a-z0-9-]*$/u.test(sourceEnvironment)) {
      throw new Error("environment slugs must be lowercase alphanumeric names");
    }
    const sourcePaths = await discoverSourcePaths(sourceEnvironment);
    assertUniqueTargets(sourceEnvironment, sourcePaths);
    const receipts: PathMigrationReceipt[] = [];
    for (const sourcePath of sourcePaths) {
      const inventory = await inventoryPath(sourceEnvironment, sourcePath);
      receipts.push(await runInjectedImport(inventory));
    }
    const prunedEnvironments = await pruneObsoleteShadowEnvironments(
      sourceEnvironment,
      new Set(receipts.map((receipt) => receipt.targetEnvironment)),
    );
    const sourceNames = receipts.reduce((sum, receipt) => sum + receipt.sourceNames, 0);
    const duplicateRows = receipts.reduce(
      (sum, receipt) => sum + receipt.duplicateSourceRows,
      0,
    );
    const prunedNames = receipts.reduce((sum, receipt) => sum + receipt.prunedNames, 0);
    console.log(
      `${sourceEnvironment}: ${receipts.length} folders, ${sourceNames} names migrated, ` +
        `${duplicateRows} duplicate rows collapsed, ${prunedNames} stale names pruned, ` +
        `${prunedEnvironments} obsolete shadow environments removed, parity verified`,
    );
  }
}

async function discoverSourcePaths(sourceEnvironment: string): Promise<string[]> {
  const paths = ["/"];
  for (let index = 0; index < paths.length; index += 1) {
    const parentPath = paths[index]!;
    const child = Bun.spawn(
      [
        "infisical",
        "secrets",
        "folders",
        "get",
        "--silent",
        `--env=${sourceEnvironment}`,
        `--path=${parentPath}`,
      ],
      {
        cwd: repoRoot,
        env: { ...process.env, NO_COLOR: "1", LOG_FORMAT: "plain" },
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    const [exitCode, stdout] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    if (exitCode !== 0) {
      throw new Error(`Infisical folder discovery failed for ${sourceEnvironment}`);
    }
    for (const folder of parseInfisicalFolderNames(stdout)) {
      paths.push(parentPath === "/" ? `/${folder}` : `${parentPath}/${folder}`);
    }
  }
  return paths;
}

function assertUniqueTargets(sourceEnvironment: string, sourcePaths: string[]): void {
  const targets = new Set<string>();
  for (const sourcePath of sourcePaths) {
    const target = shadowEnvironmentName(sourceEnvironment, sourcePath);
    if (targets.has(target)) {
      throw new Error(`Infisical folder paths collide in ${sourceEnvironment}`);
    }
    targets.add(target);
  }
}

async function inventoryPath(
  sourceEnvironment: string,
  sourcePath: string,
): Promise<PathInventory> {
  const child = Bun.spawn(
    [
      "infisical",
      "secrets",
      "--silent",
      `--env=${sourceEnvironment}`,
      `--path=${sourcePath}`,
    ],
    {
      cwd: repoRoot,
      env: { ...process.env, NO_COLOR: "1", LOG_FORMAT: "plain" },
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  const [exitCode, stdout] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (exitCode !== 0) {
    throw new Error(`Infisical inventory failed for ${sourceEnvironment}${sourcePath}`);
  }
  return {
    ...parseInfisicalNames(stdout),
    sourceEnvironment,
    sourcePath,
    targetEnvironment: shadowEnvironmentName(sourceEnvironment, sourcePath),
  };
}

async function runInjectedImport(
  inventory: PathInventory,
): Promise<PathMigrationReceipt> {
  const child = Bun.spawn(
    [
      "infisical",
      "run",
      "--silent",
      `--env=${inventory.sourceEnvironment}`,
      `--path=${inventory.sourcePath}`,
      "--",
      "bun",
      import.meta.path,
      "--child",
      inventory.sourceEnvironment,
      inventory.sourcePath,
      inventory.targetEnvironment,
      ...inventory.names,
    ],
    { cwd: repoRoot, stdout: "pipe", stderr: "pipe" },
  );
  const [exitCode, stdout] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (exitCode !== 0) {
    throw new Error(
      `Infisical injection or vault import failed for ${inventory.sourceEnvironment}${inventory.sourcePath}`,
    );
  }
  const lastLine = stdout.trim().split(/\r?\n/u).at(-1);
  if (lastLine == null) {
    throw new Error(
      `vault import returned no receipt for ${inventory.sourceEnvironment}${inventory.sourcePath}`,
    );
  }
  const receipt = JSON.parse(lastLine) as PathMigrationReceipt;
  return { ...receipt, duplicateSourceRows: inventory.duplicateRows };
}

async function importInjectedPath(
  sourceEnvironment: string,
  sourcePath: string,
  targetEnvironment: string,
  names: string[],
): Promise<PathMigrationReceipt> {
  const values = new Map<string, string>();
  for (const name of names) {
    const value = process.env[name];
    if (value == null || value.length === 0) {
      throw new Error("Infisical injection omitted a source value");
    }
    values.set(name, value);
  }

  const client = operatorClient();
  await ensureShadowEnvironment(client, targetEnvironment);
  const existing = await client.listSecretMeta(SHADOW_PROJECT, targetEnvironment);
  const expectedNames = new Set(names);
  const stale = existing.secrets
    .map((secret) => secret.name)
    .filter((name) => !expectedNames.has(name));
  await client.patchSecrets(SHADOW_PROJECT, targetEnvironment, {
    set: names.map((name) => ({
      name,
      value: values.get(name)!,
      kind: "sealed" as const,
    })),
    delete: stale,
  });

  const exported = await client.exportSecrets(SHADOW_PROJECT, targetEnvironment);
  if (exported.secrets.length !== names.length) {
    throw new Error(`shadow name parity failed for ${targetEnvironment}`);
  }
  const actual = new Map(exported.secrets.map((secret) => [secret.name, secret.value]));
  for (const [name, value] of values) {
    const copied = actual.get(name);
    if (copied == null || (await digest(copied)) !== (await digest(value))) {
      throw new Error(`shadow value parity failed for ${targetEnvironment}`);
    }
  }
  return {
    sourceEnvironment,
    sourcePath,
    targetEnvironment,
    sourceNames: names.length,
    duplicateSourceRows: 0,
    prunedNames: stale.length,
    parity: true,
  };
}

function operatorClient(): VaultClient {
  const config = readConfig();
  if (config.apiUrl == null || config.apiKey == null) {
    throw new Error("vault operator configuration is missing");
  }
  return new VaultClient(config.apiUrl, config.apiKey);
}

async function ensureShadowEnvironment(
  client: VaultClient,
  environment: string,
): Promise<void> {
  const projects = await client.listProjects();
  if (!projects.projects.includes(SHADOW_PROJECT)) {
    await client.createProject(SHADOW_PROJECT);
  }
  const environments = await client.listEnvironments(SHADOW_PROJECT);
  if (!environments.environments.includes(environment)) {
    await client.createEnvironment(SHADOW_PROJECT, environment);
  }
}

async function pruneObsoleteShadowEnvironments(
  sourceEnvironment: string,
  expected: Set<string>,
): Promise<number> {
  const client = operatorClient();
  const environments = await client.listEnvironments(SHADOW_PROJECT);
  const obsolete = environments.environments.filter(
    (environment) =>
      (environment === sourceEnvironment ||
        environment.startsWith(`${sourceEnvironment}-`)) &&
      !expected.has(environment),
  );
  for (const environment of obsolete) {
    await client.deleteEnvironment(SHADOW_PROJECT, environment);
  }
  return obsolete.length;
}

async function digest(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

if (import.meta.main) {
  void main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.message : "shadow migration failed");
    process.exit(1);
  });
}
