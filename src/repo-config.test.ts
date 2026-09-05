import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "bun:test";

import {
  loadRepoContext,
  readRequiredSecretNames,
  readWranglerConfig,
  resolveWranglerEnvironment,
  WranglerEnvironmentError,
  type RepoContext,
} from "./repo-config.ts";

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
        github: { repo: "acme/app", env: "prod-ci", secrets: ["CI_TOKEN"] },
      }),
    );
    const ctx = loadRepoContext(root);
    expect(ctx.vault.project).toBe("bwf");
    expect(ctx.vault.authority).toBeUndefined();
    expect(ctx.vault.github?.env).toBe("prod-ci");
    expect(ctx.vault.github?.secrets).toEqual(["CI_TOKEN"]);
    const wrangler = resolveWranglerEnvironment(ctx, { vaultEnv: "dev" });
    expect(wrangler?.environment).toBe(null);
    expect(wrangler?.required).toEqual(["ALPHA", "BETA"]);
    expect(wrangler?.name).toBe("demo-worker");
    expect(wrangler?.accountId).toBe("abc");
  });

  test("readRequiredSecretNames ignores non-strings", () => {
    expect(readRequiredSecretNames({ secrets: { required: ["A", 1, "B"] } })).toEqual([
      "A",
      "B",
    ]);
  });

  test("keeps independent fields and environment entries when values are malformed", () => {
    const config = readWranglerConfig(
      {
        name: 42,
        account_id: "account",
        secrets: { required: ["TOKEN"] },
        env: [null, { name: "second" }],
      },
      "/repo/wrangler.jsonc",
    );
    expect(config.topLevel).toEqual({
      environment: null,
      name: null,
      accountId: "account",
      required: ["TOKEN"],
    });
    expect(config.environments).toEqual([
      { environment: "0", name: null, accountId: "account", required: [] },
      { environment: "1", name: "second", accountId: "account", required: [] },
    ]);
  });

  test("rejects malformed vault destinations at the configuration boundary", () => {
    const root = mkdtempSync(join(tmpdir(), "vault-repo-"));
    writeFileSync(
      join(root, "vault.json"),
      JSON.stringify({ github: { repo: "acme/app", secrets: [42] } }),
    );
    expect(() => loadRepoContext(root)).toThrow();
  });
});

/**
 * The shape `poc/analytics` actually ships: a top-level list for local
 * development and a longer one on `env.production`.
 */
const environmentScoped = {
  name: "demo",
  account_id: "top-account",
  secrets: { required: ["GATEWAY_TOKEN"] },
  env: {
    production: {
      name: "demo-prod",
      secrets: { required: ["API_TOKEN", "GATEWAY_TOKEN"] },
    },
    staging: {},
  },
};

function context(
  vault: RepoContext["vault"],
  config: Parameters<typeof readWranglerConfig>[0] = environmentScoped,
) {
  return {
    root: "/repo",
    vaultJsonPath: "/repo/vault.json",
    vault,
    wrangler: readWranglerConfig(config, "/repo/wrangler.jsonc"),
  } satisfies RepoContext;
}

describe("Wrangler environments", () => {
  test("reads each environment's own secrets.required, never the top level's", () => {
    const config = readWranglerConfig(environmentScoped, "/repo/wrangler.jsonc");
    expect(config.topLevel.required).toEqual(["GATEWAY_TOKEN"]);
    const production = config.environments.find((e) => e.environment === "production");
    expect(production?.required).toEqual(["API_TOKEN", "GATEWAY_TOKEN"]);
    // Wrangler inherits no secret or var into an environment, so an
    // environment that declares none requires none.
    const staging = config.environments.find((e) => e.environment === "staging");
    expect(staging?.required).toEqual([]);
  });

  test("derives the environment's Worker name and inherits the account", () => {
    const config = readWranglerConfig(environmentScoped, "/repo/wrangler.jsonc");
    const staging = config.environments.find((e) => e.environment === "staging");
    expect(staging?.name).toBe("demo-staging");
    expect(staging?.accountId).toBe("top-account");
    expect(config.environments.find((e) => e.environment === "production")?.name).toBe(
      "demo-prod",
    );
  });

  test("a top-level-only config resolves the top-level list", () => {
    const repo = context({}, { secrets: { required: ["ALPHA"] } });
    expect(resolveWranglerEnvironment(repo, { vaultEnv: "prod" })?.required).toEqual([
      "ALPHA",
    ]);
  });

  test("vault.json maps a vault environment onto a Wrangler one", () => {
    const repo = context({ wranglerEnvironments: { dev: null, prod: "production" } });
    expect(resolveWranglerEnvironment(repo, { vaultEnv: "prod" })?.required).toEqual([
      "API_TOKEN",
      "GATEWAY_TOKEN",
    ]);
    expect(resolveWranglerEnvironment(repo, { vaultEnv: "dev" })?.required).toEqual([
      "GATEWAY_TOKEN",
    ]);
  });

  test("--wrangler-env overrides the mapping", () => {
    const repo = context({ wranglerEnvironments: { prod: null } });
    expect(
      resolveWranglerEnvironment(repo, {
        vaultEnv: "prod",
        wranglerEnv: "production",
      })?.required,
    ).toEqual(["API_TOKEN", "GATEWAY_TOKEN"]);
  });

  test("an unmapped vault environment fails rather than falling back", () => {
    const repo = context({});
    expect(() => resolveWranglerEnvironment(repo, { vaultEnv: "prod" })).toThrow(
      WranglerEnvironmentError,
    );
    try {
      resolveWranglerEnvironment(repo, { vaultEnv: "prod" });
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      expect(message).toContain("production, staging");
      expect(message).toContain("--wrangler-env");
      expect(message).toContain('"prod"');
    }
  });

  test("naming an environment the config does not declare fails", () => {
    const repo = context({});
    expect(() =>
      resolveWranglerEnvironment(repo, { vaultEnv: "prod", wranglerEnv: "prod" }),
    ).toThrow(/does not declare/u);
    expect(() =>
      resolveWranglerEnvironment(context({ wranglerEnvironments: { prod: "prod" } }), {
        vaultEnv: "prod",
      }),
    ).toThrow(/wranglerEnvironments\.prod/u);
  });
});

/**
 * The live configuration, not a fixture. `poc/analytics` declares `API_TOKEN`
 * only on `env.production`, and reading the top-level list instead injected a
 * set that was wrong and reported success.
 */
describe("poc/analytics", () => {
  const analytics = join(
    dirname(dirname(dirname(fileURLToPath(import.meta.url)))),
    "analytics",
  );

  test("resolves the account and required secrets for the prod vault environment", () => {
    const repo = loadRepoContext(analytics);
    const wrangler = resolveWranglerEnvironment(repo, { vaultEnv: "prod" });
    expect(wrangler?.environment).toBe("production");
    expect(wrangler?.name).toBe("bwf-analytics");
    expect(wrangler?.accountId).toBe("00000000000000000000000000000000");
    expect(wrangler?.required).toEqual(["API_TOKEN", "CLOUDFLARE_GATEWAY_READ_TOKEN"]);
  });

  test("keeps the dev vault environment on the top-level list", () => {
    const repo = loadRepoContext(analytics);
    const wrangler = resolveWranglerEnvironment(repo, { vaultEnv: "dev" });
    expect(wrangler?.environment).toBe(null);
    expect(wrangler?.required).toEqual(["CLOUDFLARE_GATEWAY_READ_TOKEN"]);
  });
});
