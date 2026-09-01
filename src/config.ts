/**
 * The operator's stored credential at `~/.config/poc-vault/config.json`.
 *
 * Written with mode 0600 inside a directory forced to 0700, and `chmod`ed after
 * writing rather than trusting the create mode, since `writeFileSync`'s mode is
 * masked by the process umask.
 *
 * `resolveClientOptions` fixes the precedence every command shares: explicit
 * flags, then environment, then this file. A missing URL or key is an error
 * here rather than a request that fails later with a less useful message.
 *
 * @see {@link https://vault.buildwithfriends.dev/start/install/}
 */
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export type VaultConfig = {
  apiUrl?: string;
  apiKey?: string;
  project?: string;
  env?: string;
  githubRepo?: string;
};

function configPath(): string {
  return join(homedir(), ".config", "poc-vault", "config.json");
}

export function readConfig(): VaultConfig {
  try {
    return JSON.parse(readFileSync(configPath(), "utf8")) as VaultConfig;
  } catch {
    return {};
  }
}

export function writeConfig(config: VaultConfig): void {
  writeConfigAt(configPath(), config);
}

export function writeConfigAt(path: string, config: VaultConfig): void {
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
  writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
}

export function resolveClientOptions(flags: VaultConfig): {
  apiUrl: string;
  apiKey: string;
  project?: string;
  env?: string;
  githubRepo?: string;
} {
  const stored = readConfig();
  const apiUrl = flags.apiUrl ?? process.env.VAULT_API_URL ?? stored.apiUrl;
  const apiKey = flags.apiKey ?? process.env.VAULT_API_KEY ?? stored.apiKey;
  if (apiUrl == null || apiUrl.length === 0)
    throw new Error("missing API URL (login or --api-url)");
  if (apiKey == null || apiKey.length === 0)
    throw new Error("missing API key (login or --api-key)");
  const project = flags.project ?? process.env.VAULT_PROJECT ?? stored.project;
  const env = flags.env ?? process.env.VAULT_ENV ?? stored.env;
  return {
    apiUrl,
    apiKey,
    ...(project != null ? { project } : {}),
    ...(env != null ? { env } : {}),
    ...(stored.githubRepo != null ? { githubRepo: stored.githubRepo } : {}),
  };
}
