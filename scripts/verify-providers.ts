import { AwsClient } from "aws4fetch";

import { GitHubAppClient } from "../../../apps/worker/src/github/github-app.ts";
import * as v from "valibot";
import { loadEnvironment, required } from "./operator.ts";

const CLOUDFLARE_ACCOUNT_ID = "00000000000000000000000000000000";
const WORKSPACE_BACKUP_BUCKET = "bwf-workspace-backups";
const REVIEW_INDEX_BUCKET = "bwf-review-indexes";
const ANALYTICS_ORIGIN = "https://analytics.buildwithfriends.dev";

type SecretMap = ReadonlyMap<string, string>;

export function cloudflareVerifyUrl(token: string): string {
  return token.startsWith("cfat_")
    ? `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/tokens/verify`
    : "https://api.cloudflare.com/client/v4/user/tokens/verify";
}

async function main(): Promise<void> {
  const [prodWorker, prodCi] = await Promise.all([
    loadEnvironment("prod-worker"),
    loadEnvironment("prod-ci"),
  ]);

  const results = await Promise.all([
    probe("GitHub App", () => verifyGitHubApp(prodWorker)),
    probe("analytics worker token", () => verifyAnalytics(prodWorker)),
    probe("analytics CI token", () => verifyAnalytics(prodCi)),
    probe("Cloudflare CI token", () => verifyCloudflare(prodCi)),
    probe("workspace backup R2", () =>
      verifyR2(
        prodWorker,
        "R2_ACCESS_KEY_ID",
        "R2_SECRET_ACCESS_KEY",
        WORKSPACE_BACKUP_BUCKET,
      ),
    ),
    probe("review index R2", () =>
      verifyR2(
        prodCi,
        "BWF_REVIEW_INDEX_R2_ACCESS_KEY_ID",
        "BWF_REVIEW_INDEX_R2_SECRET_ACCESS_KEY",
        REVIEW_INDEX_BUCKET,
      ),
    ),
    probe("Sentry API", () => verifySentry(prodCi)),
  ]);

  for (const result of results) console.log(`${result.status}  ${result.label}`);
  const failed = results.filter((result) => result.status === "FAIL").length;
  console.log(`${results.length - failed} read-only probes passed, ${failed} failed`);
  if (failed > 0) process.exitCode = 1;
}

async function probe(label: string, operation: () => Promise<void>) {
  try {
    await operation();
    return { label, status: "PASS" };
  } catch {
    return { label, status: "FAIL" };
  }
}

async function verifyGitHubApp(secrets: SecretMap): Promise<void> {
  const client = new GitHubAppClient({
    configuration: {
      appId: required(secrets, "GITHUB_APP_ID"),
      privateKeyPem: required(secrets, "GITHUB_APP_PRIVATE_KEY"),
    },
  });
  await client.installationUrl("vault-read-only-verification");
}

/**
 * An empty ingest batch is the one write-gated request that writes nothing:
 * the platform answers 200 with the token and 401 without it.
 */
async function verifyAnalytics(secrets: SecretMap): Promise<void> {
  const response = await fetch(`${ANALYTICS_ORIGIN}/api/ingest`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${required(secrets, "ANALYTICS_API_TOKEN")}`,
      "Content-Type": "application/json",
    },
    body: "{}",
  });
  if (!response.ok) throw new Error("the analytics platform rejected the token");
}

async function verifyCloudflare(secrets: SecretMap): Promise<void> {
  const token = required(secrets, "CLOUDFLARE_API_TOKEN");
  const response = await fetch(cloudflareVerifyUrl(token), {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) throw new Error("Cloudflare rejected the token");
  const active = v.object({
    success: v.literal(true),
    result: v.object({ status: v.literal("active") }),
  });
  if (!v.is(active, await response.json())) {
    throw new Error("Cloudflare token is not active");
  }
}

async function verifyR2(
  secrets: SecretMap,
  accessKeyName: string,
  secretAccessKeyName: string,
  bucket: string,
): Promise<void> {
  const client = new AwsClient({
    accessKeyId: required(secrets, accessKeyName),
    secretAccessKey: required(secrets, secretAccessKeyName),
    service: "s3",
    region: "auto",
  });
  const endpoint =
    `https://${CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com/` +
    `${encodeURIComponent(bucket)}?list-type=2&max-keys=1`;
  const response = await client.fetch(endpoint);
  if (!response.ok) throw new Error("R2 rejected the credential");
}

async function verifySentry(secrets: SecretMap): Promise<void> {
  const organization = required(secrets, "SENTRY_ORG");
  const project = required(secrets, "SENTRY_PROJECT");
  const response = await fetch(
    `https://sentry.io/api/0/organizations/${encodeURIComponent(organization)}/projects/`,
    {
      headers: {
        Authorization: `Bearer ${required(secrets, "SENTRY_AUTH_TOKEN")}`,
      },
    },
  );
  if (!response.ok) throw new Error("Sentry rejected the credential");
  const parsed = v.safeParse(
    v.array(v.looseObject({ slug: v.optional(v.string()) })),
    await response.json(),
  );
  if (!parsed.success || !parsed.output.some((candidate) => candidate.slug === project)) {
    throw new Error("Sentry project is not visible to the credential");
  }
}

if (import.meta.main) {
  void main().catch(() => {
    console.error("vault verification could not run");
    process.exit(1);
  });
}
