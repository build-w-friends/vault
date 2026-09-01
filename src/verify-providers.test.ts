import { describe, expect, test } from "bun:test";

import { cloudflareVerifyUrl } from "../scripts/verify-providers.ts";

describe("vault provider verification", () => {
  test("routes account tokens to the account-owned verification endpoint", () => {
    expect(cloudflareVerifyUrl("cfat_example")).toContain(
      "/accounts/00000000000000000000000000000000/tokens/verify",
    );
  });

  test("routes user and legacy tokens to the user verification endpoint", () => {
    expect(cloudflareVerifyUrl("cfut_example")).toBe(
      "https://api.cloudflare.com/client/v4/user/tokens/verify",
    );
    expect(cloudflareVerifyUrl("legacy-token")).toBe(
      "https://api.cloudflare.com/client/v4/user/tokens/verify",
    );
  });
});
