import { describe, expect, test } from "bun:test";

import { pushDestinations } from "./push.ts";
import type { RepoContext, WranglerEnvironmentConfig } from "./repo-config.ts";

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

describe("retiring a Cloudflare secret", () => {
  const wrangler: WranglerEnvironmentConfig = {
    environment: null,
    name: "demo-worker",
    accountId: "acct",
    required: ["KEPT"],
  };

  function recordingFetch(live: string[]) {
    const bodies: unknown[] = [];
    const fetchImpl: import("./push-cloudflare.ts").FetchLike = async (input, init) => {
      if (input.endsWith("/secrets")) {
        return new Response(
          JSON.stringify({ result: live.map((name) => ({ name, type: "secret_text" })) }),
          { status: 200 },
        );
      }
      bodies.push(await new Request(input, init).json());
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    };
    return { bodies, fetchImpl };
  }

  test("a full push deletes what secrets.required no longer declares", async () => {
    const { bodies, fetchImpl } = recordingFetch(["KEPT", "RETIRED"]);
    const report = await pushDestinations({
      repo: { ...repo, vault: {} },
      wrangler,
      values: { KEPT: "value" },
      env: { CLOUDFLARE_API_TOKEN: "cf_token" },
      fetchImpl,
    });
    expect(report.retired).toEqual(["RETIRED"]);
    expect(bodies).toEqual([
      {
        secrets: {
          KEPT: { type: "secret_text", name: "KEPT", text: "value" },
          RETIRED: null,
        },
      },
    ]);
  });

  test("a narrowed push retires nothing", async () => {
    const { bodies, fetchImpl } = recordingFetch(["KEPT", "RETIRED"]);
    const report = await pushDestinations({
      repo: { ...repo, vault: {} },
      wrangler,
      values: { KEPT: "value" },
      names: ["KEPT"],
      env: { CLOUDFLARE_API_TOKEN: "cf_token" },
      fetchImpl,
    });
    expect(report.retired).toEqual([]);
    expect(bodies).toEqual([
      { secrets: { KEPT: { type: "secret_text", name: "KEPT", text: "value" } } },
    ]);
  });

  test("a required name the vault cannot supply refuses before anything is written", async () => {
    const { bodies, fetchImpl } = recordingFetch(["KEPT", "RETIRED"]);
    expect(
      pushDestinations({
        repo: { ...repo, vault: {} },
        wrangler,
        values: {},
        env: { CLOUDFLARE_API_TOKEN: "cf_token" },
        fetchImpl,
      }),
    ).rejects.toThrow("vault missing names for Cloudflare: KEPT");
    expect(bodies).toEqual([]);
  });
  test("a full push still retires when nothing is left to write", async () => {
    // The Worker that retired its last required name is the one case where
    // the drift is total: no value to push, and a live secret nobody reports.
    const { bodies, fetchImpl } = recordingFetch(["RETIRED"]);
    const report = await pushDestinations({
      repo: { ...repo, vault: {} },
      wrangler: { ...wrangler, required: [] },
      values: {},
      env: { CLOUDFLARE_API_TOKEN: "cf_token" },
      fetchImpl,
    });
    expect(report.retired).toEqual(["RETIRED"]);
    expect(bodies).toEqual([{ secrets: { RETIRED: null } }]);
  });

  test("a narrowed push naming no Cloudflare secret touches Cloudflare at all", async () => {
    const { bodies, fetchImpl } = recordingFetch(["KEPT", "RETIRED"]);
    const report = await pushDestinations({
      repo: { ...repo, vault: {} },
      wrangler,
      values: { KEPT: "value" },
      names: ["SOMETHING_ELSE"],
      env: { CLOUDFLARE_API_TOKEN: "cf_token" },
      fetchImpl,
    });
    expect(report.cloudflare).toEqual([]);
    expect(report.retired).toEqual([]);
    expect(bodies).toEqual([]);
  });
});
