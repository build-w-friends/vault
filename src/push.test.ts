import { describe, expect, test } from "bun:test";

import { pushDestinations } from "./push.ts";
import type { RepoContext } from "./repo-config.ts";

const repo: RepoContext = {
  root: "/workspace",
  vaultJsonPath: "/workspace/vault.json",
  vault: {
    github: { repo: "build-w-friends/buildwfriends", secrets: ["GITHUB_TOKEN"] },
  },
  wrangler: null,
};

describe("secret destinations", () => {
  test("requires the operator-trusted GitHub repository to match vault.json", async () => {
    expect(
      pushDestinations({
        repo,
        wrangler: null,
        values: { GITHUB_TOKEN: "secret" },
        githubRepo: "attacker/redirect",
        env: { GH_TOKEN: "ghp_operator_token" },
      }),
    ).rejects.toThrow("trusted GitHub repository must match vault.json github.repo");
  });

  test("reads the GitHub destination from its own values, not the session's", async () => {
    expect(
      pushDestinations({
        repo,
        wrangler: null,
        values: { GITHUB_TOKEN: "session-env-value" },
        githubValues: {},
        githubRepo: "build-w-friends/buildwfriends",
        env: { GH_TOKEN: "ghp_operator_token" },
      }),
    ).rejects.toThrow("vault missing names for GitHub: GITHUB_TOKEN");
  });
});
