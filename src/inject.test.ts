import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "bun:test";

import { applyProcessEnv, InjectError, loadRequiredSecretValues } from "./inject.ts";
import { WranglerEnvironmentError } from "./repo-config.ts";
import type { VaultClient } from "./client.ts";

/** Holds NEED_A and an unrelated name; never NEED_B. */
function stubClient(): VaultClient {
  return {
    exportSecrets: async () => ({
      secrets: [
        { name: "NEED_A", value: "one", kind: "sealed" },
        { name: "EXTRA", value: "nope", kind: "sealed" },
      ],
    }),
  } as unknown as VaultClient;
}

describe("inject", () => {
  test("loads only secrets.required and fails on missing", async () => {
    const root = mkdtempSync(join(tmpdir(), "vault-inject-"));
    writeFileSync(
      join(root, "wrangler.jsonc"),
      `{ "secrets": { "required": ["NEED_A", "NEED_B"] } }\n`,
    );
    const client = stubClient();

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

/**
 * The failure this path exists to prevent: an environment-scoped Worker whose
 * production list holds a name the top-level list does not. Reading the
 * top-level list injected a set with a hole in it and exited 0, so the
 * consumer read an empty string and the vault reported success.
 */
describe("an environment-scoped contract", () => {
  function repository(vaultJson: Record<string, unknown>): string {
    const root = mkdtempSync(join(tmpdir(), "vault-inject-env-"));
    writeFileSync(
      join(root, "wrangler.jsonc"),
      `{
        "name": "demo",
        "secrets": { "required": ["NEED_A"] },
        "env": { "production": { "secrets": { "required": ["NEED_A", "NEED_B"] } } }
      }\n`,
    );
    writeFileSync(join(root, "vault.json"), JSON.stringify(vaultJson));
    return root;
  }

  test("errors on the environment's missing name instead of injecting nothing", async () => {
    const root = repository({ wranglerEnvironments: { prod: "production" } });
    expect(
      loadRequiredSecretValues({
        cwd: root,
        client: stubClient(),
        project: "bwf",
        env: "prod",
      }),
    ).rejects.toThrow(/NEED_B/u);
  });

  test("refuses to guess when nothing selects an environment", async () => {
    const root = repository({});
    expect(
      loadRequiredSecretValues({
        cwd: root,
        client: stubClient(),
        project: "bwf",
        env: "prod",
      }),
    ).rejects.toThrow(WranglerEnvironmentError);
  });

  test("still injects the top-level list for a vault environment mapped to it", async () => {
    const root = repository({ wranglerEnvironments: { dev: null } });
    expect(
      await loadRequiredSecretValues({
        cwd: root,
        client: stubClient(),
        project: "bwf",
        env: "dev",
      }),
    ).toEqual({ NEED_A: "one" });
  });
});
