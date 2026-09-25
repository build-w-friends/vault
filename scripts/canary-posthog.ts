import { randomUUID } from "node:crypto";

import { createProductAnalytics } from "../../../apps/worker/src/product-analytics/index.ts";
import { loadEnvironment, required } from "./operator.ts";

async function main(): Promise<void> {
  const secrets = await loadEnvironment("prod-worker");
  const warnings: unknown[] = [];
  const analytics = createProductAnalytics(
    {
      BWF_ENVIRONMENT: "production",
      POSTHOG_HOST: "https://us.i.posthog.com",
      POSTHOG_PROJECT_TOKEN: required(secrets, "POSTHOG_PROJECT_TOKEN"),
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
  console.log("PASS  PostHog consumer canary accepted");
}

if (import.meta.main) {
  void main().catch(() => {
    console.error("vault consumer canary failed");
    process.exit(1);
  });
}
