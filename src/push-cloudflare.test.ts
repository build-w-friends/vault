import { describe, expect, test } from "bun:test";

import {
  cloudflareBulkBody,
  cloudflareSecretsToRetire,
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
  test("a retired name is a null merge-patch entry", () => {
    expect(cloudflareBulkBody({ API_KEY: "x" }, ["OLD_KEY"])).toEqual({
      secrets: {
        API_KEY: { type: "secret_text", name: "API_KEY", text: "x" },
        OLD_KEY: null,
      },
    });
  });

  test("a name being written is never also retired", () => {
    expect(cloudflareBulkBody({ API_KEY: "x" }, ["API_KEY"])).toEqual({
      secrets: { API_KEY: { type: "secret_text", name: "API_KEY", text: "x" } },
    });
  });

  test("retires exactly the live names the required list no longer declares", () => {
    expect(
      cloudflareSecretsToRetire(["API_KEY", "OLD_KEY", "GONE"], ["API_KEY", "NEW_KEY"]),
    ).toEqual(["OLD_KEY", "GONE"]);
    expect(cloudflareSecretsToRetire([], ["API_KEY"])).toEqual([]);
  });

  test("sends the deletion in the same request as the writes", async () => {
    const bodies: unknown[] = [];
    const fetchImpl: import("./push-cloudflare.ts").FetchLike = async (input, init) => {
      bodies.push(await new Request(input, init).json());
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    };
    await pushCloudflareSecrets(
      { accountId: "acct", scriptName: "demo-worker", token: "tok" },
      { API_KEY: "x" },
      fetchImpl,
      ["OLD_KEY"],
    );
    expect(bodies).toEqual([
      {
        secrets: {
          API_KEY: { type: "secret_text", name: "API_KEY", text: "x" },
          OLD_KEY: null,
        },
      },
    ]);
  });

  test("a retirement with nothing to write is still sent", async () => {
    const bodies: unknown[] = [];
    const fetchImpl: import("./push-cloudflare.ts").FetchLike = async (input, init) => {
      bodies.push(await new Request(input, init).json());
      return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
    };
    await pushCloudflareSecrets(
      { accountId: "acct", scriptName: "demo-worker", token: "tok" },
      {},
      fetchImpl,
      ["OLD_KEY"],
    );
    expect(bodies).toEqual([{ secrets: { OLD_KEY: null } }]);
  });

  test("creates and deletes share the hundred-operation allowance", async () => {
    const values = Object.fromEntries(
      Array.from({ length: 60 }, (_value, index) => [`NAME_${index}`, "x"]),
    );
    const retire = Array.from({ length: 41 }, (_value, index) => `OLD_${index}`);
    expect(
      pushCloudflareSecrets(
        { accountId: "acct", scriptName: "demo-worker", token: "tok" },
        values,
        async () => new Response("{}", { status: 200 }),
        retire,
      ),
    ).rejects.toThrow("at most 100 operations");
  });
});
