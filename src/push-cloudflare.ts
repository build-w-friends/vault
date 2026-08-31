export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export type CloudflarePushTarget = {
  accountId: string;
  scriptName: string;
  token: string;
};

export function cloudflareBulkBody(values: Record<string, string>): {
  secrets: Record<string, { type: "secret_text"; name: string; text: string }>;
} {
  const secrets: Record<string, { type: "secret_text"; name: string; text: string }> = {};
  for (const [name, text] of Object.entries(values)) {
    secrets[name] = { type: "secret_text", name, text };
  }
  return { secrets };
}

export function namesFromCloudflareListing(listing: unknown): string[] | null {
  if (typeof listing !== "object" || listing == null) return null;
  const result = (listing as { result?: unknown }).result;
  const rows = Array.isArray(result)
    ? result
    : typeof result === "object" && result != null && "secrets" in result
      ? (result as { secrets?: unknown }).secrets
      : null;
  if (!Array.isArray(rows)) return null;
  const names: string[] = [];
  for (const entry of rows) {
    if (typeof entry === "string") names.push(entry);
    else if (
      typeof entry === "object" &&
      entry != null &&
      typeof (entry as { name?: unknown }).name === "string"
    ) {
      names.push((entry as { name: string }).name);
    } else return null;
  }
  return names;
}

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
  env: NodeJS.ProcessEnv = process.env,
): string | null {
  const token = env.CLOUDFLARE_API_TOKEN;
  return token != null && token.length > 0 ? token : null;
}
