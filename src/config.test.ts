import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "bun:test";

import { readConfigAt, writeConfigAt } from "./config.ts";

describe("vault config", () => {
  test("writes credentials into a private directory and file", () => {
    const root = mkdtempSync(join(tmpdir(), "vault-config-"));
    try {
      const path = join(root, "config", "config.json");
      writeConfigAt(path, {
        apiKey: "vault_user_key",
        apiUrl: "https://vault.example.test",
      });
      expect(statSync(join(root, "config")).mode & 0o777).toBe(0o700);
      expect(statSync(path).mode & 0o777).toBe(0o600);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("reads partial configs and retains unknown keys", () => {
    const root = mkdtempSync(join(tmpdir(), "vault-config-"));
    try {
      const path = join(root, "config.json");
      writeFileSync(
        path,
        JSON.stringify({ apiUrl: "https://vault.example.test", futureOption: true }),
      );
      expect(readConfigAt(path)).toEqual({
        apiUrl: "https://vault.example.test",
        futureOption: true,
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("treats missing, invalid, and malformed config as empty", () => {
    const root = mkdtempSync(join(tmpdir(), "vault-config-"));
    try {
      const missing = join(root, "missing.json");
      const invalid = join(root, "invalid.json");
      const nullValue = join(root, "null.json");
      const primitive = join(root, "primitive.json");
      const wrongType = join(root, "wrong-type.json");
      writeFileSync(invalid, "not json");
      writeFileSync(nullValue, "null");
      writeFileSync(primitive, "42");
      writeFileSync(wrongType, JSON.stringify({ apiKey: 42 }));

      expect(readConfigAt(missing)).toEqual({});
      expect(readConfigAt(invalid)).toEqual({});
      expect(readConfigAt(nullValue)).toEqual({});
      expect(readConfigAt(primitive)).toEqual({});
      expect(readConfigAt(wrongType)).toEqual({});
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
