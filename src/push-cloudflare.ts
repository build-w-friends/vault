import { z } from "zod";

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export type CloudflarePushTarget = {
  accountId: string;
  scriptName: string;
  token: string;
};

type CloudflareBulkEntry = { type: "secret_text"; name: string; text: string } | null;

type CloudflareBulkBodyResult = {
  secrets: Record<string, CloudflareBulkEntry>;
};

/** Creates, updates and deletes share one request's allowance. */
const CLOUDFLARE_BULK_OPERATION_LIMIT = 100;

const cloudflareSecretEntryParser = z.union([
  z.string(),
  z.preprocess(
    (value) => (Array.isArray(value) ? Object.create(value) : value),
    z.object({ name: z.string() }).transform((entry) => entry.name),
  ),
]);
const cloudflareListingParser = z.preprocess(
  (value) => (Array.isArray(value) ? Object.create(value) : value),
  z.looseObject({
    result: z.union([
      z.array(cloudflareSecretEntryParser),
      z.looseObject({ secrets: z.array(cloudflareSecretEntryParser) }),
    ]),
  }),
);
const cloudflareListingNamesParser = cloudflareListingParser
  .transform((listing) => {
    const rows = Array.isArray(listing.result) ? listing.result : listing.result.secrets;
    return rows;
  })
  .nullable()
  .catch(null);

/**
 * The merge-patch body. A name mapped to `null` is deleted, which is what
 * makes a push a reconciliation rather than an accumulation.
 *
 * @see https://developers.cloudflare.com/changelog/post/2026-06-03-bulk-secrets-api/
 */
export function cloudflareBulkBody(
  values: Record<string, string>,
  retire: readonly string[] = [],
): CloudflareBulkBodyResult {
  const secrets: Record<string, CloudflareBulkEntry> = {};
  for (const [name, text] of Object.entries(values)) {
    secrets[name] = { type: "secret_text", name, text };
  }
  for (const name of retire) {
    // A name being written wins: it is required, whatever the caller computed.
    if (!Object.hasOwn(secrets, name)) secrets[name] = null;
  }
  return { secrets };
}

/**
 * Names live on the Worker that `secrets.required` no longer declares.
 *
 * The required list is the authority, never the vault environment's contents:
 * an environment holds names for destinations this Worker does not have, and
 * subtracting what the vault happens to carry would retire a required name the
 * vault is merely missing — which `pushDestinations` already refuses by name
 * before it gets here.
 */
export function cloudflareSecretsToRetire(
  live: readonly string[],
  required: readonly string[],
): string[] {
  const keep = new Set(required);
  return live.filter((name) => !keep.has(name));
}

export const namesFromCloudflareListing = cloudflareListingNamesParser.parse.bind(
  cloudflareListingNamesParser,
);

export async function listCloudflareSecretNames(
  target: CloudflarePushTarget,
  fetchImpl: FetchLike = fetch,
): Promise<string[]> {
  const url = `https://api.cloudflare.com/client/v4/accounts/${target.accountId}/workers/scripts/${target.scriptName}/secrets`;
  const response = await fetchImpl(url, {
    headers: { Authorization: `Bearer ${target.token}` },
  });
  const body: unknown = await response.json();
  if (!response.ok) {
    throw new Error(`Cloudflare secret list failed: ${response.status}`);
  }
  const names = namesFromCloudflareListing(body);
  if (names == null) throw new Error("Cloudflare secret list was unreadable");
  return names;
}

export async function pushCloudflareSecrets(
  target: CloudflarePushTarget,
  values: Record<string, string>,
  fetchImpl: FetchLike = fetch,
  retire: readonly string[] = [],
): Promise<void> {
  const names = Object.keys(values);
  const operations = names.length + retire.filter((name) => !(name in values)).length;
  if (operations === 0) return;
  if (operations > CLOUDFLARE_BULK_OPERATION_LIMIT) {
    throw new Error(
      `Cloudflare bulk secrets accepts at most ${CLOUDFLARE_BULK_OPERATION_LIMIT} operations`,
    );
  }
  const url = `https://api.cloudflare.com/client/v4/accounts/${target.accountId}/workers/scripts/${target.scriptName}/secrets-bulk`;
  const response = await fetchImpl(url, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${target.token}`,
      "Content-Type": "application/merge-patch+json",
    },
    body: JSON.stringify(cloudflareBulkBody(values, retire)),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Cloudflare secret bulk failed: ${response.status} ${text}`);
  }
}

export function cloudflareTokenFromEnv(
  env: ProcessEnvironment = process.env,
): string | null {
  const token = env.CLOUDFLARE_API_TOKEN;
  return token != null && token.length > 0 ? token : null;
}
import type { ProcessEnvironment } from "./types.ts";
