import { randomUUID } from "node:crypto";

import { createProductAnalytics } from "../../../apps/worker/src/product-analytics/index.ts";
import { VaultClient } from "../src/client.ts";
import { readConfig } from "../src/config.ts";

const PROJECT = "bwf-shadow";

async function main(argv: string[]): Promise<void> {
  if (argv.length !== 1 || argv[0] !== "posthog") {
    throw new Error("usage: canary-posthog.ts posthog");
  }
  await postHogCanary();
  console.log("PASS  PostHog consumer canary accepted");
}

async function postHogCanary(): Promise<void> {
  const secrets = await loadEnvironment("prod-worker");
  const warnings: unknown[] = [];
  const analytics = createProductAnalytics(
    {
      POSTHOG_HOST: "https://us.i.posthog.com",
      POSTHOG_PROJECT_TOKEN: required(secrets, "POSTHOG_PROJECT_TOKEN"),
      PRODUCT_ANALYTICS: "true",
      PRODUCT_ANALYTICS_ENVIRONMENT: "production",
      PRODUCT_ANALYTICS_PSEUDONYM_KEY: required(
        secrets,
        "PRODUCT_ANALYTICS_PSEUDONYM_KEY",
      ),
    },
    { logWarning: (warning) => warnings.push(warning) },
  );
  await analytics.capture({
    event: "bwf.product.server_connected",
    memberId: `vault-canary:${randomUUID()}`,
    serverVisibility: "public",
  });
  if (warnings.length > 0) throw new Error("PostHog consumer reported an export failure");
}

async function loadEnvironment(environment: string): Promise<Map<string, string>> {
  const config = readConfig();
  if (config.apiUrl == null || config.apiKey == null) {
    throw new Error("vault operator configuration is missing");
  }
  const exported = await new VaultClient(config.apiUrl, config.apiKey).exportSecrets(
    PROJECT,
    environment,
  );
  return new Map(exported.secrets.map((secret) => [secret.name, secret.value]));
}

function required(secrets: ReadonlyMap<string, string>, name: string): string {
  const value = secrets.get(name);
  if (value == null || value.length === 0) throw new Error("required secret is absent");
  return value;
}

if (import.meta.main) {
  void main(process.argv.slice(2)).catch(() => {
    console.error("vault consumer canary failed");
    process.exit(1);
  });
}
