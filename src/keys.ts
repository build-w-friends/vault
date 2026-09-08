/**
 * API-key and secret-value generation.
 *
 * A key is a type-tagged prefix plus 128 random bits. The first 27 characters
 * are the *prefix*, which is what identifies a key in audit rows, `keys list`,
 * and revocation — it is safe to log, and the full key is never stored at all,
 * only its keyed hash.
 *
 * @see {@link https://vault.buildwithfriends.dev/concepts/keys-and-policy/}
 */
import type { KeyType } from "./types.ts";

type RandomApiKeyResult = { plaintext: string; prefix: string };

export function randomApiKey(type: KeyType): RandomApiKeyResult {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  const head = type === "user" ? "vault_user_" : "vault_sys_";
  const plaintext = `${head}${hex}`;
  return { plaintext, prefix: plaintext.slice(0, 27) };
}

export function randomSecretValue(bytes = 32): string {
  const raw = crypto.getRandomValues(new Uint8Array(bytes));
  let hex = "";
  for (const byte of raw) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

export function bearerFrom(header: string | undefined): string | null {
  if (header == null) return null;
  const match = /^Bearer\s+(\S+)$/iu.exec(header.trim());
  return match?.[1] ?? null;
}
