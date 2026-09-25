/* oxlint-disable no-named-as-default-member -- libsodium-wrappers' ESM build only re-exports a
   small static surface (ready, from_base64, to_base64, ...); crypto_box_seal and friends are
   attached to the default export at runtime once `ready` resolves, so they are not real named
   exports despite the package's .d.ts claiming otherwise. */
import sodium from "libsodium-wrappers";
import { z } from "zod";

import type { FetchLike } from "./push-cloudflare.ts";
import { githubOwnerRepo } from "./repo-config.ts";
import type { ProcessEnvironment } from "./types.ts";

export type GithubPushTarget = {
  repo: string;
  token: string;
};

/** An Actions secrets listing, parsed to its secret names. */
export const githubSecretListing = z
  .object({ secrets: z.array(z.object({ name: z.string() })) })
  .transform((listing) => listing.secrets.map((entry) => entry.name));
const githubPublicKeyParser = z.object({ key: z.string(), key_id: z.string() });

export async function encryptGithubSecret(
  value: string,
  publicKeyBase64: string,
): Promise<string> {
  await sodium.ready;
  const keyBytes = sodium.from_base64(publicKeyBase64, sodium.base64_variants.ORIGINAL);
  const sealed = sodium.crypto_box_seal(sodium.from_string(value), keyBytes);
  return sodium.to_base64(sealed, sodium.base64_variants.ORIGINAL);
}

function githubFetch(
  url: string,
  token: string,
  init: RequestInit = {},
  fetchImpl: FetchLike = fetch,
): Promise<Response> {
  const headers = new Headers({
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
    "X-GitHub-Api-Version": "2022-11-28",
  });
  new Headers(init.headers).forEach((value, name) => {
    headers.set(name, value);
  });
  return fetchImpl(url, { ...init, headers });
}

export async function listGithubSecretNames(
  target: GithubPushTarget,
  fetchImpl: FetchLike = fetch,
): Promise<string[]> {
  const parsed = githubOwnerRepo(target.repo);
  if (parsed == null) throw new Error(`invalid github.repo: ${target.repo}`);
  const response = await githubFetch(
    `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/actions/secrets`,
    target.token,
    {},
    fetchImpl,
  );
  if (!response.ok) throw new Error(`GitHub secret list failed: ${response.status}`);
  const names = githubSecretListing.safeParse(await response.json().catch(() => null));
  if (!names.success) throw new Error("GitHub secret list was unreadable");
  return names.data;
}

export async function pushGithubSecrets(
  target: GithubPushTarget,
  values: Record<string, string>,
  fetchImpl: FetchLike = fetch,
): Promise<void> {
  const parsed = githubOwnerRepo(target.repo);
  if (parsed == null) throw new Error(`invalid github.repo: ${target.repo}`);
  const keyResponse = await githubFetch(
    `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/actions/secrets/public-key`,
    target.token,
    {},
    fetchImpl,
  );
  if (!keyResponse.ok) throw new Error(`GitHub public key failed: ${keyResponse.status}`);
  const keyBody = githubPublicKeyParser.safeParse(
    await keyResponse.json().catch(() => null),
  );
  if (!keyBody.success) {
    throw new Error("GitHub public key was unreadable");
  }
  for (const [name, value] of Object.entries(values)) {
    const encrypted_value = await encryptGithubSecret(value, keyBody.data.key);
    const put = await githubFetch(
      `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/actions/secrets/${encodeURIComponent(name)}`,
      target.token,
      {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ encrypted_value, key_id: keyBody.data.key_id }),
      },
      fetchImpl,
    );
    if (put.status !== 201 && put.status !== 204) {
      throw new Error(`GitHub secret put ${name} failed: ${put.status}`);
    }
  }
}

export function githubTokenFromEnv(env: ProcessEnvironment = process.env): string | null {
  const token = env.GH_TOKEN ?? env.GITHUB_TOKEN;
  return token != null && token.length > 0 ? token : null;
}
