import { describe, expect, spyOn, test } from "bun:test";
import * as v from "valibot";

import { authHeaders, bootstrapUser, createTestVault } from "./harness.ts";
import { VaultStore } from "./db.ts";

const mcpContentSchema = v.looseObject({ text: v.string() });
const mcpResultSchema = v.looseObject({
  result: v.looseObject({ content: v.array(mcpContentSchema) }),
});
const mcpErrorSchema = v.looseObject({
  error: v.looseObject({ message: v.string() }),
});
const mcpProtocolErrorSchema = v.looseObject({
  id: v.nullable(v.union([v.string(), v.number()])),
  error: v.looseObject({ code: v.number(), message: v.string() }),
});
const keyResponseSchema = v.looseObject({ key: v.string() });

describe("mcp", () => {
  test("lists names and refuses get_secret", async () => {
    const { app, env } = await createTestVault();
    const key = await bootstrapUser(app, env);
    await app.request(
      "/v1/projects",
      {
        method: "POST",
        headers: authHeaders(key, "application/json"),
        body: JSON.stringify({ name: "demo" }),
      },
      env,
    );
    await app.request(
      "/v1/projects/demo/environments/dev/secrets",
      {
        method: "PATCH",
        headers: authHeaders(key, "application/json"),
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
        headers: authHeaders(key, "application/json"),
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "list_secrets", arguments: { project: "demo", env: "dev" } },
        }),
      },
      env,
    );
    const listedBody = v.parse(mcpResultSchema, await listed.json());
    expect(listedBody.result.content[0]?.text.includes("GITHUB_TOKEN")).toBe(true);
    expect(listedBody.result.content[0]?.text.includes("real-token")).toBe(false);

    const got = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: authHeaders(key, "application/json"),
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
    const gotBody = v.parse(mcpErrorSchema, await got.json());
    expect(gotBody.error?.message).toContain("get_secret is not available");
  });

  test("sealed creation still requires write permission", async () => {
    const { app, env } = await createTestVault();
    const user = await bootstrapUser(app, env);
    await app.request(
      "/v1/projects",
      {
        method: "POST",
        headers: authHeaders(user, "application/json"),
        body: JSON.stringify({ name: "demo" }),
      },
      env,
    );
    const created = await app.request(
      "/v1/keys",
      {
        method: "POST",
        headers: authHeaders(user, "application/json"),
        body: JSON.stringify({
          type: "system",
          mode: "broker",
          permission: "read",
          scopes: [{ project: "demo", env: "dev" }],
        }),
      },
      env,
    );
    const readOnly = v.parse(keyResponseSchema, await created.json()).key;
    const denied = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: authHeaders(readOnly, "application/json"),
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "create_sealed",
            arguments: { project: "demo", env: "dev", name: "CREATED" },
          },
        }),
      },
      env,
    );
    const body = v.parse(mcpErrorSchema, await denied.json());
    expect(body.error.message).toBe("API key cannot write secrets");
  });

  test("rejects malformed requests and typed arguments before mutation", async () => {
    const { app, env, store } = await createTestVault();
    const key = await bootstrapUser(app, env);
    await store.createProject("demo");
    const { environmentId } = await store.requireEnvironment("demo", "dev");
    const beforeSecrets = await store.listSecretMeta(environmentId);
    const requireEnvironment = spyOn(VaultStore.prototype, "requireEnvironment");
    const setSecret = spyOn(VaultStore.prototype, "setSecret");
    try {
      const malformed = await app.request(
        "/mcp",
        { method: "POST", headers: authHeaders(key), body: "{" },
        env,
      );
      const malformedBody = v.parse(mcpProtocolErrorSchema, await malformed.json());
      expect(malformedBody.error.code).toBe(-32700);

      const invalidEnvelope = await app.request(
        "/mcp",
        {
          method: "POST",
          headers: authHeaders(key, "application/json"),
          body: JSON.stringify({ jsonrpc: "2.0", id: true, method: "initialize" }),
        },
        env,
      );
      const invalidEnvelopeBody = v.parse(
        mcpProtocolErrorSchema,
        await invalidEnvelope.json(),
      );
      expect(invalidEnvelopeBody.error.code).toBe(-32600);

      const invalidArguments = await app.request(
        "/mcp",
        {
          method: "POST",
          headers: authHeaders(key, "application/json"),
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 3,
            method: "tools/call",
            params: { name: "create_sealed", arguments: { project: 42, env: "dev" } },
          }),
        },
        env,
      );
      const invalidArgumentsBody = v.parse(
        mcpProtocolErrorSchema,
        await invalidArguments.json(),
      );
      expect(invalidArgumentsBody.id).toBe(3);
      expect(invalidArgumentsBody.error.code).toBe(-32602);
      expect(await store.listSecretMeta(environmentId)).toEqual(beforeSecrets);
      expect(requireEnvironment).not.toHaveBeenCalled();
      expect(setSecret).not.toHaveBeenCalled();

      const valid = await app.request(
        "/mcp",
        {
          method: "POST",
          headers: authHeaders(key, "application/json"),
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: "valid-create",
            method: "tools/call",
            params: {
              name: "create_sealed",
              arguments: { project: "demo", env: "dev", name: "CREATED", extra: 42 },
            },
          }),
        },
        env,
      );
      const validBody = v.parse(mcpResultSchema, await valid.json());
      expect(validBody.result.content[0]?.text).toBe("created sealed secret CREATED");
      expect(requireEnvironment).toHaveBeenCalledWith("demo", "dev");
      expect(setSecret).toHaveBeenCalledTimes(1);
      expect(
        (await store.listSecretMeta(environmentId)).map((secret) => secret.name),
      ).toEqual(["CREATED"]);
    } finally {
      requireEnvironment.mockRestore();
      setSecret.mockRestore();
    }
  });

  test("supports initialized notification and mint_proxy_help with empty arguments", async () => {
    const { app, env } = await createTestVault();
    const key = await bootstrapUser(app, env);
    const initialized = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: authHeaders(key, "application/json"),
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      },
      env,
    );
    expect(initialized.status).toBe(202);

    const help = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: authHeaders(key, "application/json"),
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "help",
          method: "tools/call",
          params: { name: "mint_proxy_help", arguments: {} },
        }),
      },
      env,
    );
    const helpBody = v.parse(mcpResultSchema, await help.json());
    expect(helpBody.result.content[0]?.text).toContain("vault proxy");
  });

  test("rejects missing methods and array params", async () => {
    const { app, env } = await createTestVault();
    const key = await bootstrapUser(app, env);
    const missingMethod = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: authHeaders(key, "application/json"),
        body: JSON.stringify({ jsonrpc: "2.0", id: 1 }),
      },
      env,
    );
    const missingBody = v.parse(mcpProtocolErrorSchema, await missingMethod.json());
    expect(missingBody.error.code).toBe(-32600);

    const arrayParams = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: authHeaders(key, "application/json"),
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "mint_proxy_help", arguments: [] },
        }),
      },
      env,
    );
    const arrayBody = v.parse(mcpProtocolErrorSchema, await arrayParams.json());
    expect(arrayBody.error.code).toBe(-32602);

    const arrayInitializeParams = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: authHeaders(key, "application/json"),
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 3,
          method: "initialize",
          params: [],
        }),
      },
      env,
    );
    const arrayInitializeBody = v.parse(
      mcpProtocolErrorSchema,
      await arrayInitializeParams.json(),
    );
    expect(arrayInitializeBody.error.code).toBe(-32600);
  });
});
