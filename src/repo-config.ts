/**
 * Reading `vault.json` and the Wrangler config it points at.
 *
 * Both are found by walking up from the working directory, which is what lets
 * `vault` run from anywhere inside a repository.
 *
 * A Wrangler config can declare environments, and Wrangler does **not** inherit
 * `vars`, bindings, or secrets from the top level into one — `wrangler deploy
 * --env production` warns about exactly that. So `secrets.required` is read per
 * environment too, and the environment has to be chosen before the list means
 * anything. `resolveWranglerEnvironment` is that choice, and it throws rather
 * than falling back to the top-level list: a config with environments whose
 * environment nobody selected would otherwise inject a set that is wrong and
 * looks fine.
 *
 * `authority` is read here and enforced in `cli.ts`: absent or `vault` means
 * the vault is the source of truth; any other value names another system as
 * authoritative and makes provider push fail closed.
 *
 * @see {@link https://vault.buildwithfriends.dev/reference/configuration/}
 * @see {@link https://developers.cloudflare.com/workers/wrangler/environments/}
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";

import { stripJsonComments } from "./jsonc.ts";
import { z } from "zod";

const requiredSchema = z
  .array(z.unknown())
  .catch([])
  .transform((values) =>
    values.filter((value): value is string => z.string().safeParse(value).success),
  );
const secretsSchema = z.object({ required: requiredSchema }).catch({ required: [] });
const objectSchema = z.object({});
function isEnvironmentContainer(value: unknown): value is object {
  return Array.isArray(value) || objectSchema.safeParse(value).success;
}
const environmentEntriesSchema = z
  .unknown()
  .transform((value) => (isEnvironmentContainer(value) ? Object.entries(value) : []))
  .pipe(z.array(z.tuple([z.string(), z.unknown()])));
const configSchema = z
  .object({
    secrets: secretsSchema.optional(),
    name: z.string().optional().catch(undefined),
    account_id: z.string().optional().catch(undefined),
    env: environmentEntriesSchema.optional().default([]),
  })
  .passthrough()
  .catch({ env: [] });
const requiredConfigSchema = z
  .object({ secrets: secretsSchema.optional() })
  .passthrough()
  .catch({});

const vaultJsonSchema = z.object({
  project: z.string().optional(),
  env: z.string().optional(),
  authority: z.string().optional(),
  wrangler: z.string().optional(),
  // null selects top-level Wrangler configuration; names select env.<name>.
  wranglerEnvironments: z.record(z.string(), z.string().nullable()).optional(),
  github: z
    .object({
      repo: z.string(),
      // Absent means the session environment supplies GitHub secrets.
      env: z.string().optional(),
      secrets: z.array(z.string()),
    })
    .optional(),
});
type VaultJson = z.output<typeof vaultJsonSchema>;

/** One Wrangler environment's resolved contract. */
export type WranglerEnvironmentConfig = {
  /** `null` for the top-level configuration, otherwise the `env.<name>` key. */
  environment: string | null;
  name: string | null;
  accountId: string | null;
  required: string[];
};

export type WranglerConfig = {
  path: string;
  topLevel: WranglerEnvironmentConfig;
  environments: WranglerEnvironmentConfig[];
};

export type RepoContext = {
  root: string;
  vaultJsonPath: string | null;
  vault: VaultJson;
  wrangler: WranglerConfig | null;
};

export class WranglerEnvironmentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WranglerEnvironmentError";
  }
}

function findUp(start: string, names: string[]): string | null {
  let directory = resolve(start);
  while (true) {
    for (const name of names) {
      const candidate = join(directory, name);
      if (existsSync(candidate)) return candidate;
    }
    const parent = dirname(directory);
    if (parent === directory) return null;
    directory = parent;
  }
}

/**
 * One object's own `secrets.required`. Never another's: an environment that
 * declares none requires none, exactly as it holds none of the top level's
 * `vars`.
 */
const requiredNamesSchema = requiredConfigSchema.transform(
  (config) => config.secrets?.required ?? [],
);
export const readRequiredSecretNames =
  requiredNamesSchema.parse.bind(requiredNamesSchema);

export function loadRepoContext(cwd: string): RepoContext {
  const vaultJsonPath = findUp(cwd, ["vault.json"]);
  const root = vaultJsonPath != null ? dirname(vaultJsonPath) : resolve(cwd);
  let vault: VaultJson = {};
  if (vaultJsonPath != null) {
    vault = vaultJsonSchema.parse(
      JSON.parse(stripJsonComments(readFileSync(vaultJsonPath, "utf8"))),
    );
  }
  let wranglerPath: string | null;
  if (vault.wrangler == null)
    wranglerPath = findUp(cwd, ["wrangler.jsonc", "wrangler.json"]);
  else
    wranglerPath = isAbsolute(vault.wrangler)
      ? vault.wrangler
      : resolve(root, vault.wrangler);
  return {
    root,
    vaultJsonPath,
    vault,
    wrangler: wranglerPath != null ? readWrangler(wranglerPath) : null,
  };
}

function stringField(
  config: z.output<typeof configSchema>,
  field: "name" | "account_id",
): string | null {
  const value = field === "name" ? config.name : config.account_id;
  return z.string().nullable().catch(null).parse(value);
}

const wranglerConfigArgumentsSchema = z
  .tuple([z.unknown(), z.string()])
  .transform(([source, path]): [z.output<typeof configSchema>, string] => [
    configSchema.parse(source ?? {}),
    path,
  ]);

export const readWranglerConfig = z
  .function({ input: wranglerConfigArgumentsSchema })
  .implement((config, path): WranglerConfig => {
    const topLevel: WranglerEnvironmentConfig = {
      environment: null,
      name: stringField(config, "name"),
      accountId: stringField(config, "account_id"),
      required: readRequiredSecretNames(config),
    };
    const declared = config.env;
    const environments: WranglerEnvironmentConfig[] = [];
    for (const [name, value] of declared) {
      const block = configSchema.parse(value);
      environments.push({
        environment: name,
        // Inheritable, but Wrangler appends the environment name to a Worker
        // that does not override it: `<name>-<environment>`.
        name:
          stringField(block, "name") ??
          (topLevel.name != null ? `${topLevel.name}-${name}` : null),
        accountId: stringField(block, "account_id") ?? topLevel.accountId,
        // Not inheritable. Wrangler carries no top-level secret or var into an
        // environment, so neither does this.
        required: readRequiredSecretNames(block),
      });
    }
    return { path, topLevel, environments };
  });

function readWrangler(path: string): WranglerConfig {
  return readWranglerConfig(
    JSON.parse(stripJsonComments(readFileSync(path, "utf8"))),
    path,
  );
}

/**
 * The environment whose contract this invocation is about.
 *
 * `wranglerEnv` is `--wrangler-env`; `vaultEnv` is the vault environment the
 * session already resolved. They are separate namespaces and neither is
 * inferred from the other — `vault.json`'s `wranglerEnvironments` is where a
 * repository writes the correspondence down once.
 */
export function resolveWranglerEnvironment(
  repo: RepoContext,
  selection: { vaultEnv: string; wranglerEnv?: string },
): WranglerEnvironmentConfig | null {
  const config = repo.wrangler;
  if (config == null) return null;
  if (selection.wranglerEnv != null) {
    return requireEnvironment(config, selection.wranglerEnv, "--wrangler-env");
  }
  const mapping = repo.vault.wranglerEnvironments;
  if (mapping != null && Object.hasOwn(mapping, selection.vaultEnv)) {
    const mapped = mapping[selection.vaultEnv];
    if (mapped == null) return config.topLevel;
    return requireEnvironment(
      config,
      mapped,
      `vault.json wranglerEnvironments.${selection.vaultEnv}`,
    );
  }
  if (config.environments.length === 0) return config.topLevel;
  throw new WranglerEnvironmentError(
    `${config.path} declares Wrangler environments (${declaredNames(config)}) and ` +
      `none is selected for vault environment "${selection.vaultEnv}". Pass ` +
      `--wrangler-env NAME, or record it in vault.json as ` +
      `"wranglerEnvironments": { "${selection.vaultEnv}": "<name>" } — null there ` +
      "selects the top-level configuration.",
  );
}

function requireEnvironment(
  config: WranglerConfig,
  name: string,
  source: string,
): WranglerEnvironmentConfig {
  const found = config.environments.find((entry) => entry.environment === name);
  if (found != null) return found;
  throw new WranglerEnvironmentError(
    `${source} names Wrangler environment "${name}", which ${config.path} does not ` +
      `declare. It declares: ${declaredNames(config)}.`,
  );
}

function declaredNames(config: WranglerConfig): string {
  if (config.environments.length === 0) return "none";
  return config.environments.map((entry) => entry.environment).join(", ");
}

/** How an error or a report should name the selected environment. */
export function describeWranglerEnvironment(
  wrangler: WranglerEnvironmentConfig | null,
): string {
  if (wrangler == null) return "no Wrangler config";
  if (wrangler.environment == null) return "the top-level configuration";
  return `environment "${wrangler.environment}"`;
}

export function githubOwnerRepo(spec: string): { owner: string; repo: string } | null {
  const match = /^([^/]+)\/([^/]+)$/u.exec(spec.trim());
  if (match == null || match[1] == null || match[2] == null) return null;
  return { owner: match[1], repo: match[2] };
}
