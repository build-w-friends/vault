import { describe, expect, test } from "bun:test";

import type { RepoContext, WranglerEnvironmentConfig } from "./repo-config.ts";
import { formatStatus, missingNames, requiredVaultNames, statusFails } from "./status.ts";

describe("status", () => {
  test("reports declared names missing from a listing", () => {
    expect(missingNames(["A", "B", "C"], ["A", "C"])).toEqual(["B"]);
  });

  test("checks only runtime names in an Infisical shadow environment", () => {
    expect(
      requiredVaultNames(
        repoContext("infisical-shadow", ["CI_SECRET"]),
        wranglerEnvironment(["WORKER_SECRET"]),
      ),
    ).toEqual(["WORKER_SECRET"]);
  });

  test("requires runtime and destination names when Vault is authoritative", () => {
    expect(
      requiredVaultNames(
        repoContext("vault", ["CI_SECRET"]),
        wranglerEnvironment(["WORKER_SECRET"]),
      ),
    ).toEqual(["WORKER_SECRET", "CI_SECRET"]);
  });

  test("fails when any destination is missing names", () => {
    expect(
      statusFails({
        vaultMissing: [],
        cloudflareMissing: ["X"],
        githubMissing: "skipped",
      }),
    ).toBe(true);
    expect(
      statusFails({
        vaultMissing: [],
        cloudflareMissing: [],
        githubMissing: [],
      }),
    ).toBe(false);
  });

  test("formats skipped destinations without failing them in the text", () => {
    const text = formatStatus({
      vaultMissing: [],
      cloudflareMissing: "skipped",
      githubMissing: [],
    });
    expect(text).toContain("cloudflare: skipped");
    expect(text).toContain("github: ok");
  });
});

function repoContext(
  authority: "vault" | "infisical-shadow",
  githubRequired: string[],
): RepoContext {
  return {
    root: "/repo",
    vaultJsonPath: "/repo/vault.json",
    vault: {
      authority,
      github: { repo: "owner/repo", secrets: githubRequired },
    },
    wrangler: {
      path: "/repo/wrangler.jsonc",
      topLevel: wranglerEnvironment([]),
      environments: [],
    },
  };
}

function wranglerEnvironment(required: string[]): WranglerEnvironmentConfig {
  return {
    environment: null,
    name: "worker",
    accountId: "account",
    required,
  };
}
