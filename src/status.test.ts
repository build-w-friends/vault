import { describe, expect, test } from "bun:test";

import type { VaultClient } from "./client.ts";
import type { RepoContext, WranglerEnvironmentConfig } from "./repo-config.ts";
import { collectStatus, formatStatus, missingNames, statusFails } from "./status.ts";

describe("status", () => {
  test("reports declared names missing from a listing", () => {
    expect(missingNames(["A", "B", "C"], ["A", "C"])).toEqual(["B"]);
  });

  test("checks runtime names in the session environment and GitHub names in github.env", async () => {
    const listings = new Map([
      ["dev-worker", ["WORKER_SECRET"]],
      ["prod-ci", ["CI_SECRET"]],
    ]);
    const client = {
      listSecretMeta: (project: string, env: string) => {
        expect(project).toBe("bwf");
        return Promise.resolve({
          secrets: (listings.get(env) ?? []).map((name) => ({
            name,
            kind: "secret" as const,
          })),
        });
      },
    } as unknown as VaultClient;
    const report = await collectStatus({
      client,
      repo: repoContext(["CI_SECRET", "CI_ONLY"]),
      wrangler: wranglerEnvironment(["WORKER_SECRET"]),
      project: "bwf",
      env: "dev-worker",
      processEnv: {},
    });
    expect(report.vaultMissing).toEqual(["CI_ONLY"]);
    expect(report.cloudflareMissing).toBe("skipped");
    expect(report.githubMissing).toBe("skipped");
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

function repoContext(githubRequired: string[]): RepoContext {
  return {
    root: "/repo",
    vaultJsonPath: "/repo/vault.json",
    vault: {
      github: { repo: "owner/repo", env: "prod-ci", secrets: githubRequired },
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
