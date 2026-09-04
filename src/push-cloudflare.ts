import { z } from "zod";

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export type CloudflarePushTarget = {
  accountId: string;
  scriptName: string;
  token: string;
};

type CloudflareBulkBodyResult = {
  secrets: Record<string, { type: "secret_text"; name: string; text: string }>;
};

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

export function cloudflareBulkBody(
  values: Record<string, string>,
): CloudflareBulkBodyResult {
  const secrets: Record<string, { type: "secret_text"; name: string; text: string }> = {};
  for (const [name, text] of Object.entries(values)) {
    secrets[name] = { type: "secret_text", name, text };
  }
  return { secrets };
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
): Promise<void> {
  const names = Object.keys(values);
  if (names.length === 0) return;
  if (names.length > 100) {
    throw new Error("Cloudflare bulk secrets accepts at most 100 operations");
  }
  const url = `https://api.cloudflare.com/client/v4/accounts/${target.accountId}/workers/scripts/${target.scriptName}/secrets-bulk`;
  const response = await fetchImpl(url, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${target.token}`,
      "Content-Type": "application/merge-patch+json",
    },
    body: JSON.stringify(cloudflareBulkBody(values)),
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
