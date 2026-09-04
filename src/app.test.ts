import { describe, expect, test } from "bun:test";
import { z } from "zod";

import { authHeaders, bootstrapUser, createTestVault } from "./harness.ts";

const secretsParser = z.looseObject({
  secrets: z.array(
    z.looseObject({ name: z.string(), kind: z.string(), value: z.optional(z.string()) }),
  ),
});
const keyParser = z.looseObject({ key: z.string() });
const errorParser = z.looseObject({ error: z.string() });

describe("worker api", () => {
  test("human can set a secret, list hides it, run-shaped get returns it", async () => {
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
    const set = await app.request(
      "/v1/projects/demo/environments/dev/secrets",
      {
        method: "PATCH",
        headers: authHeaders(key, "application/json"),
        body: JSON.stringify({
          set: [{ name: "DATABASE_URL", value: "postgres://x", kind: "secret" }],
        }),
      },
      env,
    );
    expect(set.status).toBe(200);

    const listed = await app.request(
      "/v1/projects/demo/environments/dev/secrets",
      {
        headers: authHeaders(key),
      },
      env,
    );
    const listedBody = z.parse(secretsParser, await listed.json());
    expect(listedBody.secrets).toEqual([{ name: "DATABASE_URL", kind: "secret" }]);

    const shown = await app.request(
      "/v1/projects/demo/environments/dev/secrets?show=1",
      {
        headers: authHeaders(key),
      },
      env,
    );
    const shownBody = z.parse(secretsParser, await shown.json());
    expect(shownBody.secrets[0]?.value).toBe("postgres://x");
  });

  test("empty values are rejected and ciphertext is not plaintext", async () => {
    const { app, env, store } = await createTestVault();
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
    const empty = await app.request(
      "/v1/projects/demo/environments/dev/secrets",
      {
        method: "PATCH",
        headers: authHeaders(key, "application/json"),
        body: JSON.stringify({ set: [{ name: "X", value: "", kind: "secret" }] }),
      },
      env,
    );
    expect(empty.status).toBe(400);

    await app.request(
      "/v1/projects/demo/environments/dev/secrets",
      {
        method: "PATCH",
        headers: authHeaders(key, "application/json"),
        body: JSON.stringify({
          set: [{ name: "TOKEN", value: "super-secret-value", kind: "sealed" }],
        }),
      },
      env,
    );
    const { environmentId } = await store.requireEnvironment("demo", "dev");
    const dump = await store.ciphertextDump(environmentId);
    const blob = JSON.stringify(dump);
    expect(blob.includes("super-secret-value")).toBe(false);
    expect(blob.includes("TOKEN")).toBe(false);
    const auditRow = await env.DB.prepare(
      "SELECT secret_name_encrypted FROM audit_events WHERE action = 'set' ORDER BY created_at DESC LIMIT 1",
    ).first<{ secret_name_encrypted: string }>();
    expect(auditRow).not.toBeNull();
    expect(auditRow!.secret_name_encrypted.includes("TOKEN")).toBe(false);
  });

  test("broker system key cannot GET values", async () => {
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
    await app.request(
      "/v1/projects/demo/environments/dev/secrets",
      {
        method: "PATCH",
        headers: authHeaders(user, "application/json"),
        body: JSON.stringify({
          set: [{ name: "GITHUB_TOKEN", value: "real-token", kind: "sealed" }],
        }),
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
    const broker = z.parse(keyParser, await created.json()).key;

    const shown = await app.request(
      "/v1/projects/demo/environments/dev/secrets?show=1",
      {
        headers: authHeaders(broker),
      },
      env,
    );
    expect(shown.status).toBe(403);

    const got = await app.request(
      "/v1/projects/demo/environments/dev/secrets/GITHUB_TOKEN",
      {
        headers: authHeaders(broker),
      },
      env,
    );
    expect(got.status).toBe(403);

    const listed = await app.request(
      "/v1/projects/demo/environments/dev/secrets",
      {
        headers: authHeaders(broker),
      },
      env,
    );
    expect(listed.status).toBe(200);
    const listedBody = z.parse(secretsParser, await listed.json());
    expect(listedBody.secrets[0]?.name).toBe("GITHUB_TOKEN");
  });

  test("export returns sealed values for a user key, not a broker key", async () => {
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
    await app.request(
      "/v1/projects/demo/environments/dev/secrets",
      {
        method: "PATCH",
        headers: authHeaders(user, "application/json"),
        body: JSON.stringify({
          set: [{ name: "GITHUB_TOKEN", value: "real-token", kind: "sealed" }],
        }),
      },
      env,
    );
    const exported = await app.request(
      "/v1/projects/demo/environments/dev/secrets?export=1",
      { headers: authHeaders(user) },
      env,
    );
    const exportedBody = z.parse(secretsParser, await exported.json());
    expect(exportedBody.secrets[0]?.value).toBe("real-token");

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
    const broker = z.parse(keyParser, await created.json()).key;
    const denied = await app.request(
      "/v1/projects/demo/environments/dev/secrets?export=1",
      { headers: authHeaders(broker) },
      env,
    );
    expect(denied.status).toBe(403);
  });

  test("creating a duplicate project is a 409 conflict, not a 500", async () => {
    const { app, env } = await createTestVault();
    const key = await bootstrapUser(app, env);
    const first = await app.request(
      "/v1/projects",
      {
        method: "POST",
        headers: authHeaders(key, "application/json"),
        body: JSON.stringify({ name: "demo" }),
      },
      env,
    );
    expect(first.status).toBe(201);

    const duplicate = await app.request(
      "/v1/projects",
      {
        method: "POST",
        headers: authHeaders(key, "application/json"),
        body: JSON.stringify({ name: "Demo" }),
      },
      env,
    );
    expect(duplicate.status).toBe(409);
    const conflictBody = z.parse(errorParser, await duplicate.json());
    expect(conflictBody).toEqual({ error: 'project "demo" already exists' });
  });

  test("creating a duplicate environment is a 409 conflict, not a 500", async () => {
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

    const duplicate = await app.request(
      "/v1/projects/demo/environments",
      {
        method: "POST",
        headers: authHeaders(key, "application/json"),
        body: JSON.stringify({ name: "dev" }),
      },
      env,
    );
    expect(duplicate.status).toBe(409);
    const conflictBody = z.parse(errorParser, await duplicate.json());
    expect(conflictBody).toEqual({ error: 'environment "dev" already exists' });

    const fresh = await app.request(
      "/v1/projects/demo/environments",
      {
        method: "POST",
        headers: authHeaders(key, "application/json"),
        body: JSON.stringify({ name: "staging" }),
      },
      env,
    );
    expect(fresh.status).toBe(201);
  });
});
