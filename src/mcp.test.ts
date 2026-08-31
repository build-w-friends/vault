import { describe, expect, test } from "bun:test";

import { authHeaders, bootstrapUser, createTestVault } from "./harness.ts";

describe("mcp", () => {
  test("lists names and refuses get_secret", async () => {
    const { app, env } = await createTestVault();
    const key = await bootstrapUser(app, env);
    await app.request(
      "/v1/projects",
      {
        method: "POST",
        headers: authHeaders(key, {}),
        body: JSON.stringify({ name: "demo" }),
      },
      env,
    );
    await app.request(
      "/v1/projects/demo/environments/dev/secrets",
      {
        method: "PATCH",
        headers: authHeaders(key, {}),
        body: JSON.stringify({
          set: [{ name: "GITHUB_TOKEN", value: "real-token", kind: "sealed" }],
        }),
      },
      env,
    );

    const listed = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: authHeaders(key, {}),
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "list_secrets", arguments: { project: "demo", env: "dev" } },
        }),
      },
      env,
    );
    const listedBody = (await listed.json()) as {
      result: { content: Array<{ text: string }> };
    };
    expect(listedBody.result.content[0]?.text.includes("GITHUB_TOKEN")).toBe(true);
    expect(listedBody.result.content[0]?.text.includes("real-token")).toBe(false);

    const got = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: authHeaders(key, {}),
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: {
            name: "get_secret",
            arguments: { project: "demo", env: "dev", name: "GITHUB_TOKEN" },
          },
        }),
      },
      env,
    );
    const gotBody = (await got.json()) as { error?: { message: string } };
    expect(gotBody.error?.message).toContain("get_secret is not available");
  });
});
