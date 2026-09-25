/** Operator-side helpers for scripts that read the production vault with the logged-in key. */
import { VaultClient } from "../src/client.ts";
import { readConfig } from "../src/config.ts";

/** The vault project that holds the production environments these scripts read. */
const PROJECT = "bwf-shadow";

export function operatorClient(): VaultClient {
  const config = readConfig();
  if (config.apiUrl == null || config.apiKey == null) {
    throw new Error("vault operator configuration is missing");
  }
  return new VaultClient(config.apiUrl, config.apiKey);
}

export async function loadEnvironment(
  environment: string,
  client = operatorClient(),
): Promise<ReadonlyMap<string, string>> {
  const exported = await client.exportSecrets(PROJECT, environment);
  return new Map(exported.secrets.map((secret) => [secret.name, secret.value]));
}

/** The named value as stored; throws when it is absent, empty or only whitespace. */
export function required(secrets: ReadonlyMap<string, string>, name: string): string {
  const value = secrets.get(name);
  if (value == null || value.trim() === "") throw new Error(`${name} is absent`);
  return value;
}
