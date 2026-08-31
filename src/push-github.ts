import sodium from "libsodium-wrappers";

import type { FetchLike } from "./push-cloudflare.ts";
import { githubOwnerRepo } from "./repo-config.ts";

export type GithubPushTarget = {
  repo: string;
  token: string;
};

export async function encryptGithubSecret(
  value: string,
  publicKeyBase64: string,
): Promise<string> {
  await sodium.ready;
  const keyBytes = sodium.from_base64(publicKeyBase64, sodium.base64_variants.ORIGINAL);
  const sealed = sodium.crypto_box_seal(sodium.from_string(value), keyBytes);
  return sodium.to_base64(sealed, sodium.base64_variants.ORIGINAL);
}

async function githubJson(
  url: string,
  token: string,
  init: RequestInit = {},
  fetchImpl: FetchLike = fetch,
): Promise<{ status: number; body: unknown }> {
  const headers = new Headers({
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
    "X-GitHub-Api-Version": "2022-11-28",
  });
  if (init.headers != null) {
    const extra = new Headers(init.headers);
    extra.forEach((value, name) => {
      headers.set(name, value);
    });
  }
  const response = await fetchImpl(url, {
    ...init,
    headers,
  });
  const text = await response.text();
  const body: unknown = text.length > 0 ? JSON.parse(text) : {};
  return { status: response.status, body };
}

export function namesFromGithubListing(listing: unknown): string[] | null {
  if (typeof listing !== "object" || listing == null) return null;
  const secrets = (listing as { secrets?: unknown }).secrets;
  if (!Array.isArray(secrets)) return null;
  const names: string[] = [];
  for (const entry of secrets) {
    if (
      typeof entry === "object" &&
      entry != null &&
      typeof (entry as { name?: unknown }).name === "string"
    ) {
      names.push((entry as { name: string }).name);
    } else return null;
  }
  return names;
}

export async function listGithubSecretNames(
  target: GithubPushTarget,
  fetchImpl: FetchLike = fetch,
): Promise<string[]> {
  const parsed = githubOwnerRepo(target.repo);
  if (parsed == null) throw new Error(`invalid github.repo: ${target.repo}`);
  const { status, body } = await githubJson(
    `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/actions/secrets`,
    target.token,
    {},
    fetchImpl,
  );
  if (status < 200 || status >= 300) {
    throw new Error(`GitHub secret list failed: ${status}`);
  }
  const names = namesFromGithubListing(body);
  if (names == null) throw new Error("GitHub secret list was unreadable");
  return names;
}

export async function pushGithubSecrets(
  target: GithubPushTarget,
  values: Record<string, string>,
  fetchImpl: FetchLike = fetch,
): Promise<void> {
  const parsed = githubOwnerRepo(target.repo);
  if (parsed == null) throw new Error(`invalid github.repo: ${target.repo}`);
  const keyResponse = await githubJson(
    `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/actions/secrets/public-key`,
    target.token,
    {},
    fetchImpl,
  );
  if (keyResponse.status < 200 || keyResponse.status >= 300) {
    throw new Error(`GitHub public key failed: ${keyResponse.status}`);
  }
  const keyBody = keyResponse.body as { key?: unknown; key_id?: unknown };
  if (typeof keyBody.key !== "string" || typeof keyBody.key_id !== "string") {
    throw new Error("GitHub public key was unreadable");
  }
  for (const [name, value] of Object.entries(values)) {
    const encrypted_value = await encryptGithubSecret(value, keyBody.key);
    const put = await githubJson(
      `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/actions/secrets/${encodeURIComponent(name)}`,
      target.token,
      {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ encrypted_value, key_id: keyBody.key_id }),
      },
      fetchImpl,
    );
    if (put.status !== 201 && put.status !== 204) {
      throw new Error(`GitHub secret put ${name} failed: ${put.status}`);
    }
  }
}

export function githubTokenFromEnv(env: NodeJS.ProcessEnv = process.env): string | null {
  const token = env.GH_TOKEN ?? env.GITHUB_TOKEN;
  return token != null && token.length > 0 ? token : null;
}
