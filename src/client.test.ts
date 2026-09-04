import { describe, expect, test } from "bun:test";

import { VaultClient, parseVaultApiUrl } from "./client.ts";
import { TEST_BOOTSTRAP_TOKEN, createTestVault } from "./harness.ts";

describe("vault API URL", () => {
  test("allows HTTPS and loopback HTTP endpoints", () => {
    expect(parseVaultApiUrl("https://vault.example.test").origin).toBe(
      "https://vault.example.test",
    );
    expect(parseVaultApiUrl("http://127.0.0.1:8787").origin).toBe(
      "http://127.0.0.1:8787",
    );
  });

  test("rejects credential-bearing and non-loopback HTTP endpoints", () => {
    expect(() => parseVaultApiUrl("https://key@example.test")).toThrow();
    expect(() => parseVaultApiUrl("http://vault.example.test")).toThrow();
  });
});

describe("VaultClient local HTTP integration", () => {
  test("covers the authenticated vault surface over loopback HTTP", async () => {
    const { app, env } = await createTestVault();
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: (request) => app.fetch(request, env),
    });
    try {
      const bootstrapClient = new VaultClient(
        server.url.origin,
        "unused-before-bootstrap",
      );
      const bootstrap = await bootstrapClient.bootstrap(
        TEST_BOOTSTRAP_TOKEN,
        "client-test",
      );
      expect(bootstrap.prefix).toMatch(/^vault_user_/u);
      const client = new VaultClient(server.url.origin, bootstrap.key);

      expect(await client.listProjects()).toEqual({ projects: [] });
      expect(await client.createProject("demo")).toEqual({
        id: expect.any(String),
        name: "demo",
      });
      expect(await client.listProjects()).toEqual({ projects: ["demo"] });
      expect(await client.createEnvironment("demo", "Staging")).toEqual({
        name: "staging",
      });
      expect(await client.listEnvironments("demo")).toEqual({
        environments: ["dev", "prod", "staging"],
      });

      await client.patchSecrets("demo", "staging", {
        set: [
          { name: "PUBLIC_VALUE", value: "visible", kind: "secret" },
          { name: "SEALED_VALUE", value: "sealed", kind: "sealed" },
        ],
      });
      expect(await client.listSecretMeta("demo", "staging")).toEqual({
        secrets: [
          { name: "PUBLIC_VALUE", kind: "secret" },
          { name: "SEALED_VALUE", kind: "sealed" },
        ],
      });
      expect(await client.listSecrets("demo", "staging")).toEqual({
        secrets: [
          { name: "PUBLIC_VALUE", kind: "secret", value: "visible" },
          { name: "SEALED_VALUE", kind: "sealed" },
        ],
      });
      expect(await client.exportSecrets("demo", "staging")).toEqual({
        secrets: [
          { name: "PUBLIC_VALUE", kind: "secret", value: "visible" },
          { name: "SEALED_VALUE", kind: "sealed", value: "sealed" },
        ],
      });
      expect(await client.getSecret("demo", "staging", "PUBLIC_VALUE")).toEqual({
        name: "PUBLIC_VALUE",
        kind: "secret",
        value: "visible",
      });

      expect(
        await client.putRoute("demo", "staging", {
          host: "api.example.test",
          secret: "PUBLIC_VALUE",
        }),
      ).toEqual({ ok: true, host: "api.example.test" });
      expect((await client.listRoutes("demo", "staging")).routes).toHaveLength(1);

      const createdKey = await client.createKey({ type: "user", label: "rotated" });
      expect(
        (await client.listKeys()).keys.some((key) => key.keyPrefix === createdKey.prefix),
      ).toBe(true);
      const rotatedKey = await client.rotateKey(createdKey.prefix, 30);
      expect(rotatedKey.prefix).not.toBe(createdKey.prefix);
      await client.revokeKey(rotatedKey.prefix);
      expect(
        (await client.listKeys(true)).keys.some(
          (key) => key.keyPrefix === rotatedKey.prefix && key.revoked,
        ),
      ).toBe(true);

      const audit = await client.listAudit(200);
      expect(audit.events.some((event) => event.action === "inject")).toBe(true);
      await client.patchSecrets("demo", "staging", { delete: ["SEALED_VALUE"] });
      await client.deleteEnvironment("demo", "staging");
      expect(await client.deleteProject("demo")).toEqual({ ok: true });
    } finally {
      await server.stop(true);
    }
  });

  test("rejects malformed successful responses without exposing the body", async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: () => Response.json({ projects: "malformed-secret-body" }),
    });
    try {
      const client = new VaultClient(server.url.origin, "test-key");
      await client.listProjects();
      throw new Error("Expected the vault request to fail");
    } catch (error) {
      expect(error).toMatchObject({
        name: "VaultClientError",
        status: 200,
        message: "vault API returned an invalid response",
      });
    } finally {
      await server.stop(true);
    }
  });

  test.each([
    {
      body: JSON.stringify({ error: "permission denied" }),
      message: "permission denied",
    },
    { body: JSON.stringify({ error: 42 }), message: "request failed: 403" },
    { body: "null", message: "request failed: 403" },
    { body: "", message: "request failed: 403" },
  ])("preserves HTTP error handling for $body", async ({ body, message }) => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: () => new Response(body, { status: 403 }),
    });
    try {
      const client = new VaultClient(server.url.origin, "test-key");
      await client.listProjects();
      throw new Error("Expected the vault request to fail");
    } catch (error) {
      expect(error).toMatchObject({
        name: "VaultClientError",
        status: 403,
        message,
      });
    } finally {
      await server.stop(true);
    }
  });
});
