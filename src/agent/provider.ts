import { createSign } from "node:crypto";
import * as v from "valibot";
import { z } from "zod";

const githubAppSchema = v.strictObject({
  appId: v.pipe(v.string(), v.regex(/^[0-9]+$/u)),
  privateKey: v.pipe(v.string(), v.minLength(1)),
});
const installSchema = v.object({ id: v.pipe(v.number(), v.integer(), v.minValue(1)) });
const tokenSchema = v.object({ token: v.string(), expires_at: v.string() });
export const githubAccessSchema = v.object({
  token: v.string(),
  expiresAt: v.number(),
  repository: v.string(),
});
export const cloudflareConfigSchema = v.strictObject({
  clientId: v.pipe(v.string(), v.minLength(1)),
  redirectUri: v.pipe(v.string(), v.url()),
  scopes: v.pipe(
    v.array(v.pipe(v.string(), v.regex(/^[a-zA-Z0-9_.:-]+$/u))),
    v.minLength(1),
  ),
});
export const cloudflareAccessSchema = v.object({
  accessToken: v.string(),
  expiresAt: v.number(),
  scopes: v.string(),
});
const oauthTokenSchema = v.object({
  access_token: v.string(),
  token_type: v.string(),
  expires_in: v.pipe(v.number(), v.minValue(1)),
  scope: v.optional(v.string()),
});

export async function providerJson(response: Response) {
  if (!response.ok) throw new Error(`Provider request failed (HTTP ${response.status})`);
  // Bound provider output before decoding, including responses without Content-Length.
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Provider returned an empty response");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > 1048576) throw new Error("Provider response exceeds one MiB");
      chunks.push(part.value);
    }
  } finally {
    await reader.cancel();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return z.json().parse(JSON.parse(new TextDecoder().decode(bytes)));
}
export async function githubAccess(
  config: string,
  repository: string,
  send: typeof fetch = fetch,
  now = Date.now(),
) {
  const app = v.parse(githubAppSchema, JSON.parse(config));
  const seconds = Math.floor(now / 1000);
  const unsigned = `${Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url")}.${Buffer.from(JSON.stringify({ iat: seconds - 60, exp: seconds + 540, iss: app.appId })).toString("base64url")}`;
  const signer = createSign("RSA-SHA256");
  signer.update(unsigned);
  signer.end();
  const jwt = `${unsigned}.${signer.sign(app.privateKey).toString("base64url")}`;
  const headers = {
    Authorization: `Bearer ${jwt}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2026-03-10",
    "User-Agent": "Vault",
  };
  const install = v.parse(
    installSchema,
    await providerJson(
      await send(`https://api.github.com/repos/${repository}/installation`, {
        headers,
        redirect: "error",
        signal: AbortSignal.timeout(30000),
      }),
    ),
  );
  const token = v.parse(
    tokenSchema,
    await providerJson(
      await send(`https://api.github.com/app/installations/${install.id}/access_tokens`, {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({
          repositories: [repository.split("/")[1]],
          permissions: { contents: "read", metadata: "read" },
        }),
        redirect: "error",
        signal: AbortSignal.timeout(30000),
      }),
    ),
  );
  const expiresAt = Date.parse(token.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= now || expiresAt > now + 3660000)
    throw new Error("Invalid provider token expiry");
  return { token: token.token, expiresAt, repository };
}
export async function exchangeCloudflare(
  input: {
    clientId: string;
    redirectUri: string;
    code: string;
    verifier: string;
    scopes: string[];
  },
  send: typeof fetch = fetch,
) {
  const token = v.parse(
    oauthTokenSchema,
    await providerJson(
      await send("https://dash.cloudflare.com/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: input.clientId,
          redirect_uri: input.redirectUri,
          code: input.code,
          code_verifier: input.verifier,
        }),
        redirect: "error",
        signal: AbortSignal.timeout(30000),
      }),
    ),
  );
  if (token.token_type.toLowerCase() !== "bearer")
    throw new Error("Unsupported OAuth token type");
  const scopes = token.scope ?? input.scopes.join(" ");
  if (input.scopes.some((scope) => !scopes.split(" ").includes(scope)))
    throw new Error("Required OAuth scope was not granted");
  return {
    accessToken: token.access_token,
    expiresAt: Date.now() + token.expires_in * 1000,
    scopes,
  };
}
