import { describe, expect, test } from "bun:test";

import { generateMasterKey, parseMasterKey, VaultCrypto } from "./crypto.ts";

describe("crypto", () => {
  test("rejects a missing or short master key", () => {
    expect(() => parseMasterKey(undefined)).toThrow("required");
    expect(() => parseMasterKey("")).toThrow("required");
    expect(() => parseMasterKey(btoa("short"))).toThrow("32 bytes");
  });

  test("encrypts with a unique IV and decrypts", async () => {
    const vaultCrypto = await VaultCrypto.fromMasterKey(generateMasterKey());
    const first = await vaultCrypto.encrypt("hunter2");
    const second = await vaultCrypto.encrypt("hunter2");
    expect(first).not.toBe(second);
    expect(await vaultCrypto.decrypt(first)).toBe("hunter2");
    expect(await vaultCrypto.decrypt(second)).toBe("hunter2");
  });

  test("lookup hashes are deterministic and not the plaintext", async () => {
    const vaultCrypto = await VaultCrypto.fromMasterKey(generateMasterKey());
    const hash = await vaultCrypto.lookupHash("DATABASE_URL");
    expect(hash).toBe(await vaultCrypto.lookupHash("DATABASE_URL"));
    expect(hash.includes("DATABASE")).toBe(false);
    expect(hash).toHaveLength(64);
  });
});
