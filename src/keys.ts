import type { KeyType } from "./types.ts";

export function randomApiKey(type: KeyType): { plaintext: string; prefix: string } {
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
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
  return match?.[1] ?? null;
}
