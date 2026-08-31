import { mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "bun:test";

import { writeConfigAt } from "./config.ts";

describe("vault config", () => {
  test("writes credentials into a private directory and file", () => {
    const root = mkdtempSync(join(tmpdir(), "vault-config-"));
    const path = join(root, "config", "config.json");
    writeConfigAt(path, {
      apiKey: "vault_user_key",
      apiUrl: "https://vault.example.test",
    });
    expect(statSync(join(root, "config")).mode & 0o777).toBe(0o700);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });
});
