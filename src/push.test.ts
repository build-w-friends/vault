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
        values: { GITHUB_TOKEN: "secret" },
        githubRepo: "attacker/redirect",
        env: { GH_TOKEN: "ghp_operator_token" },
      }),
    ).rejects.toThrow("trusted GitHub repository must match vault.json github.repo");
  });
});
