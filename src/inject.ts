/**
 * Resolving a Wrangler config's `secrets.required` list into process values.
 *
 * That list is the contract, and it is the reason `vault run` is narrower than
 * "give this process the vault": only declared names are exported, never
 * everything the environment holds.
 *
 * The list belongs to one Wrangler environment, so the environment is resolved
 * first and an unresolved one is an error. Falling back to the top-level list
 * for an environment-scoped Worker injects a set that is quietly wrong, which
 * is the failure this whole path exists to prevent.
 *
 * A declared name with no value is an error, not an empty string. An empty
 * string is a second, untested configuration of whatever consumes it, and the
 * failure it produces is a capability that silently does nothing.
 *
 * @see {@link https://vault.buildwithfriends.dev/reference/configuration/}
 */
import { VaultClient } from "./client.ts";
import {
  describeWranglerEnvironment,
  loadRepoContext,
  resolveWranglerEnvironment,
} from "./repo-config.ts";

export class InjectError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InjectError";
  }
}

export type InjectInput = {
  cwd: string;
  client: VaultClient;
  project: string;
  env: string;
  wranglerEnv?: string;
};

export async function loadRequiredSecretValues(
  input: InjectInput,
): Promise<Record<string, string>> {
  const repo = loadRepoContext(input.cwd);
  const selection: Parameters<typeof resolveWranglerEnvironment>[1] = {
    vaultEnv: input.env,
  };
  if (input.wranglerEnv != null) selection.wranglerEnv = input.wranglerEnv;
  const wrangler = resolveWranglerEnvironment(repo, selection);
  const required = wrangler?.required ?? [];
  if (required.length === 0) {
    throw new InjectError(
      `${repo.wrangler?.path ?? "wrangler.jsonc"} declares no secrets.required for ` +
        `${describeWranglerEnvironment(wrangler)}; nothing to inject`,
    );
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
    throw new InjectError(
      `missing required secrets: ${missing.join(", ")} ` +
        `(${input.project}/${input.env}, ${describeWranglerEnvironment(wrangler)})`,
    );
  }
  return values;
}

export function applyProcessEnv(values: Record<string, string>): void {
  for (const [name, value] of Object.entries(values)) {
    process.env[name] = value;
  }
}

export async function injectRequiredIntoProcess(input: InjectInput): Promise<string[]> {
  const values = await loadRequiredSecretValues(input);
  applyProcessEnv(values);
  return Object.keys(values);
}
