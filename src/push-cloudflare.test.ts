import { describe, expect, test } from "bun:test";

import {
  cloudflareBulkBody,
  namesFromCloudflareListing,
  pushCloudflareSecrets,
} from "./push-cloudflare.ts";

describe("cloudflare push", () => {
  test("bulk body is secret_text merge-patch entries", () => {
    expect(cloudflareBulkBody({ API_KEY: "x" })).toEqual({
      secrets: {
        API_KEY: { type: "secret_text", name: "API_KEY", text: "x" },
      },
    });
  });

  test("reads names from a script secrets listing", () => {
    expect(
      namesFromCloudflareListing({
        result: [
          { name: "API_KEY", type: "secret_text" },
          { name: "OTHER", type: "secret_text" },
        ],
      }),
    ).toEqual(["API_KEY", "OTHER"]);
  });

  test("PATCHes secrets-bulk with merge-patch json", async () => {
    const calls: Array<{ url: string; method?: string; contentType?: string }> = [];
    const fetchImpl: import("./push-cloudflare.ts").FetchLike = async (input, init) => {
      const url = input;
      const headers = new Headers(init?.headers);
      calls.push({
        url,
        method: init?.method,
        contentType: headers.get("content-type") ?? undefined,
      });
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    };
    await pushCloudflareSecrets(
      { accountId: "acct", scriptName: "demo-worker", token: "tok" },
      { API_KEY: "x" },
      fetchImpl,
    );
    expect(calls[0]?.method).toBe("PATCH");
    expect(calls[0]?.url).toContain("/workers/scripts/demo-worker/secrets-bulk");
    expect(calls[0]?.contentType).toBe("application/merge-patch+json");
  });
});
