/**
 * Resolving a Wrangler config's `secrets.required` list into process values.
 *
 * That list is the contract, and it is the reason `vault run` is narrower than
 * "give this process the vault": only declared names are exported, never
 * everything the environment holds.
 *
 * A declared name with no value is an error, not an empty string. An empty
 * string is a second, untested configuration of whatever consumes it, and the
 * failure it produces is a capability that silently does nothing.
 *
 * @see {@link https://vault.buildwithfriends.dev/reference/configuration/}
 */
import { VaultClient } from "./client.ts";
import { loadRepoContext } from "./repo-config.ts";

export class InjectError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InjectError";
  }
}

export async function loadRequiredSecretValues(input: {
  cwd: string;
  client: VaultClient;
  project: string;
  env: string;
}): Promise<Record<string, string>> {
  const repo = loadRepoContext(input.cwd);
  const required = repo.wrangler?.required ?? [];
  if (required.length === 0) {
    throw new InjectError("wrangler.jsonc has no secrets.required; nothing to inject");
  }
  const listed = await input.client.exportSecrets(input.project, input.env);
  const byName = new Map(listed.secrets.map((secret) => [secret.name, secret.value]));
  const values: Record<string, string> = {};
  const missing: string[] = [];
  for (const name of required) {
    const value = byName.get(name);
    if (value == null || value.length === 0) missing.push(name);
    else values[name] = value;
  }
  if (missing.length > 0) {
    throw new InjectError(`missing required secrets: ${missing.join(", ")}`);
  }
  return values;
}

export function applyProcessEnv(values: Record<string, string>): void {
  for (const [name, value] of Object.entries(values)) {
    process.env[name] = value;
  }
}

export async function injectRequiredIntoProcess(input: {
  cwd: string;
  client: VaultClient;
  project: string;
  env: string;
}): Promise<string[]> {
  const values = await loadRequiredSecretValues(input);
  applyProcessEnv(values);
  return Object.keys(values);
}
