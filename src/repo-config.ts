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
 * `authority` is read here and enforced in `cli.ts`: `infisical-shadow` means
 * Infisical is authoritative and provider push must fail closed.
 *
 * @see {@link https://vault.buildwithfriends.dev/reference/configuration/}
 * @see {@link https://developers.cloudflare.com/workers/wrangler/environments/}
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";

import { parseJsonc } from "./jsonc.ts";

type GithubDestination = {
  repo: string;
  secrets: string[];
};

type VaultJson = {
  project?: string;
  env?: string;
  authority?: "vault" | "infisical-shadow";
  wrangler?: string;
  /**
   * Which Wrangler environment each vault environment's contract lives in.
   * `null` selects the top-level configuration, the way omitting Wrangler's
   * own `--env` does.
   */
  wranglerEnvironments?: Record<string, string | null>;
  github?: GithubDestination;
};

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
export function readRequiredSecretNames(config: unknown): string[] {
  if (typeof config !== "object" || config == null) return [];
  const secrets = (config as { secrets?: { required?: unknown } }).secrets;
  const required = secrets?.required;
  if (!Array.isArray(required)) return [];
  return required.filter((name): name is string => typeof name === "string");
}

export function loadRepoContext(cwd: string): RepoContext {
  const vaultJsonPath = findUp(cwd, ["vault.json"]);
  const root = vaultJsonPath != null ? dirname(vaultJsonPath) : resolve(cwd);
  const vault: VaultJson =
    vaultJsonPath != null
      ? (parseJsonc(readFileSync(vaultJsonPath, "utf8")) as VaultJson)
      : {};
  const wranglerPath =
    vault.wrangler != null
      ? isAbsolute(vault.wrangler)
        ? vault.wrangler
        : resolve(root, vault.wrangler)
      : findUp(cwd, ["wrangler.jsonc", "wrangler.json"]);
  return {
    root,
    vaultJsonPath,
    vault,
    wrangler: wranglerPath != null ? readWrangler(wranglerPath) : null,
  };
}

function stringField(config: object, field: string): string | null {
  const value = (config as Record<string, unknown>)[field];
  return typeof value === "string" ? value : null;
}

export function readWranglerConfig(source: unknown, path: string): WranglerConfig {
  const config = typeof source === "object" && source != null ? source : {};
  const topLevel: WranglerEnvironmentConfig = {
    environment: null,
    name: stringField(config, "name"),
    accountId: stringField(config, "account_id"),
    required: readRequiredSecretNames(config),
  };
  const declared = (config as { env?: unknown }).env;
  const environments: WranglerEnvironmentConfig[] = [];
  if (typeof declared === "object" && declared != null) {
    for (const [name, value] of Object.entries(declared)) {
      const block = typeof value === "object" && value != null ? value : {};
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
  }
  return { path, topLevel, environments };
}

function readWrangler(path: string): WranglerConfig {
  return readWranglerConfig(parseJsonc(readFileSync(path, "utf8")), path);
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
  const match = /^([^/]+)\/([^/]+)$/.exec(spec.trim());
  if (match == null || match[1] == null || match[2] == null) return null;
  return { owner: match[1], repo: match[2] };
}
