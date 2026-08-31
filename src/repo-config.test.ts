import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "bun:test";

import { loadRepoContext, readRequiredSecretNames } from "./repo-config.ts";

describe("repo config", () => {
  test("reads secrets.required and github list", () => {
    const root = mkdtempSync(join(tmpdir(), "vault-repo-"));
    writeFileSync(
      join(root, "wrangler.jsonc"),
      `{
        "name": "demo-worker",
        "account_id": "abc",
        "secrets": { "required": ["ALPHA", "BETA"] }
      }\n`,
    );
    writeFileSync(
      join(root, "vault.json"),
      JSON.stringify({
        project: "bwf",
        env: "dev",
        github: { repo: "acme/app", secrets: ["CI_TOKEN"] },
      }),
    );
    const ctx = loadRepoContext(root);
    expect(ctx.vault.project).toBe("bwf");
    expect(ctx.wrangler?.required).toEqual(["ALPHA", "BETA"]);
    expect(ctx.wrangler?.name).toBe("demo-worker");
    expect(ctx.vault.github?.secrets).toEqual(["CI_TOKEN"]);
  });

  test("readRequiredSecretNames ignores non-strings", () => {
    expect(readRequiredSecretNames({ secrets: { required: ["A", 1, "B"] } })).toEqual([
      "A",
      "B",
    ]);
  });
});
