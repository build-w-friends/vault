import { describe, expect, test } from "bun:test";

import {
  assertGitHubAuthorizationPage,
  assertGitHubAuthorizationUrl,
  d1DatabaseIdFromListOutput,
  deployedWorkersDevUrl,
  diagnosticIdFromProofOutput,
  sentryCanaryEventsUrl,
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

  test("extracts only the opaque Sentry diagnostic id", () => {
    expect(
      diagnosticIdFromProofOutput(
        "[PASS] Packaged Sentry fault flushed (bwf_123e4567-e89b-42d3-a456-426614174000)",
      ),
    ).toBe("bwf_123e4567-e89b-42d3-a456-426614174000");
  });

  test("builds a bounded Sentry lookup", () => {
    const url = sentryCanaryEventsUrl({
      diagnosticId: "bwf_123e4567-e89b-42d3-a456-426614174000",
      organization: "bwf",
      project: "desktop",
      release: "build-with-friends@0.1.0+abc",
    });
    expect(url.pathname).toBe("/api/0/organizations/bwf/events/");
    expect(url.searchParams.get("dataset")).toBe("errors");
    expect(url.searchParams.get("statsPeriod")).toBe("1h");
    expect(url.searchParams.get("query")).toContain("bwf.diagnostic_id:");
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
