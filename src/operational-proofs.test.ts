import { describe, expect, test } from "bun:test";

import {
  assertGitHubAuthorizationPage,
  assertGitHubAuthorizationUrl,
  d1DatabaseIdFromListOutput,
  deployedWorkersDevUrl,
  secretsStoreSecretId,
} from "./operational-proofs.ts";

describe("operational proof parsers", () => {
  test("accepts an exact credential-free GitHub PKCE authorization", () => {
    const value =
      "https://github.com/login/oauth/authorize?client_id=client&redirect_uri=" +
      encodeURIComponent("http://127.0.0.1:5173/api/github-app/callback") +
      "&state=abcdefghijklmnopqrstuvwxyz&code_challenge_method=S256" +
      "&code_challenge=abcdefghijklmnopqrstuvwxyz0123456789";
    expect(
      assertGitHubAuthorizationUrl(value, {
        callbackUrl: "http://127.0.0.1:5173/api/github-app/callback",
        clientId: "client",
        pkce: true,
      }).hostname,
    ).toBe("github.com");
  });

  test("rejects a wrong callback or credential-bearing authorization URL", () => {
    expect(() =>
      assertGitHubAuthorizationUrl(
        "https://github.com/login/oauth/authorize?client_id=client&redirect_uri=https%3A%2F%2Fwrong.example&state=abcdefghijklmnopqrstuvwxyz&client_secret=nope",
        {
          callbackUrl: "http://127.0.0.1:5173/api/auth/callback/github",
          clientId: "client",
          pkce: false,
        },
      ),
    ).toThrow();
  });

  test("rejects GitHub's HTTP-200 invalid redirect page", () => {
    expect(() => {
      assertGitHubAuthorizationPage({
        status: 200,
        body: "<title>Invalid Redirect URI</title>",
      });
    }).toThrow(/rejected/u);
  });

  test("accepts a recognized GitHub authorization page", () => {
    expect(() => {
      assertGitHubAuthorizationPage({
        status: 200,
        body: "<title>Authorize Build With Friends</title>",
      });
    }).not.toThrow();
  });

  test("extracts disposable Cloudflare resource identities", () => {
    expect(
      d1DatabaseIdFromListOutput(
        '[{"name":"temporary","uuid":"123e4567-e89b-42d3-a456-426614174000"}]',
        "temporary",
      ),
    ).toBe("123e4567-e89b-42d3-a456-426614174000");
    expect(
      deployedWorkersDevUrl(
        "Deployed bwf-vault-recovery-abcd triggers\n  https://bwf-vault-recovery-abcd.example.workers.dev",
      ).origin,
    ).toBe("https://bwf-vault-recovery-abcd.example.workers.dev");
    expect(
      secretsStoreSecretId(
        "│ BWF_VAULT_MASTER_KEY_PRIMARY │ 22222222222222222222222222222222 │ workers │",
        "BWF_VAULT_MASTER_KEY_PRIMARY",
      ),
    ).toBe("22222222222222222222222222222222");
  });
});
