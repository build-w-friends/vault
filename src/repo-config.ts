import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";

import { parseJsonc } from "./jsonc.ts";

export type GithubDestination = {
  repo: string;
  secrets: string[];
};

export type VaultJson = {
  project?: string;
  env?: string;
  wrangler?: string;
  github?: GithubDestination;
};

export type WranglerSecretsConfig = {
  path: string;
  name: string | null;
  accountId: string | null;
  required: string[];
};

export type RepoContext = {
  root: string;
  vaultJsonPath: string | null;
  vault: VaultJson;
  wrangler: WranglerSecretsConfig | null;
};

export function findUp(start: string, names: string[]): string | null {
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

function readWrangler(path: string): WranglerSecretsConfig {
  const config = parseJsonc(readFileSync(path, "utf8")) as {
    name?: unknown;
    account_id?: unknown;
  };
  return {
    path,
    name: typeof config.name === "string" ? config.name : null,
    accountId: typeof config.account_id === "string" ? config.account_id : null,
    required: readRequiredSecretNames(config),
  };
}

export function githubOwnerRepo(spec: string): { owner: string; repo: string } | null {
  const match = /^([^/]+)\/([^/]+)$/.exec(spec.trim());
  if (match == null || match[1] == null || match[2] == null) return null;
  return { owner: match[1], repo: match[2] };
}
