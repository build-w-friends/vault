import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "bun:test";

import { applyProcessEnv, InjectError, loadRequiredSecretValues } from "./inject.ts";
import type { VaultClient } from "./client.ts";

describe("inject", () => {
  test("loads only secrets.required and fails on missing", async () => {
    const root = mkdtempSync(join(tmpdir(), "vault-inject-"));
    writeFileSync(
      join(root, "wrangler.jsonc"),
      `{ "secrets": { "required": ["NEED_A", "NEED_B"] } }\n`,
    );
    const client = {
      exportSecrets: async () => ({
        secrets: [
          { name: "NEED_A", value: "one", kind: "sealed" },
          { name: "EXTRA", value: "nope", kind: "sealed" },
        ],
      }),
    } as unknown as VaultClient;

    try {
      await loadRequiredSecretValues({
        cwd: root,
        client,
        project: "bwf",
        env: "dev",
      });
      throw new Error("expected missing NEED_B");
    } catch (error) {
      expect(error instanceof InjectError).toBe(true);
      expect(error instanceof Error && error.message.includes("NEED_B")).toBe(true);
    }

    writeFileSync(
      join(root, "wrangler.jsonc"),
      `{ "secrets": { "required": ["NEED_A"] } }\n`,
    );
    const values = await loadRequiredSecretValues({
      cwd: root,
      client,
      project: "bwf",
      env: "dev",
    });
    expect(values).toEqual({ NEED_A: "one" });
    expect(Object.hasOwn(values, "EXTRA")).toBe(false);
  });

  test("applyProcessEnv writes those names only", () => {
    applyProcessEnv({ NEED_A: "one" });
    const injected = process.env["NEED_A"];
    delete process.env["NEED_A"];
    expect(injected).toBe("one");
  });
});
