import { describe, expect, test } from "bun:test";

import { authHeaders, bootstrapUser, createTestVault } from "./harness.ts";

describe("worker api", () => {
  test("human can set a secret, list hides it, run-shaped get returns it", async () => {
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
    const set = await app.request(
      "/v1/projects/demo/environments/dev/secrets",
      {
        method: "PATCH",
        headers: authHeaders(key, {}),
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
    const listedBody = (await listed.json()) as {
      secrets: Array<{ name: string; kind: string; value?: string }>;
    };
    expect(listedBody.secrets).toEqual([{ name: "DATABASE_URL", kind: "secret" }]);

    const shown = await app.request(
      "/v1/projects/demo/environments/dev/secrets?show=1",
      {
        headers: authHeaders(key),
      },
      env,
    );
    const shownBody = (await shown.json()) as { secrets: Array<{ value?: string }> };
    expect(shownBody.secrets[0]?.value).toBe("postgres://x");
  });

  test("empty values are rejected and ciphertext is not plaintext", async () => {
    const { app, env, store } = await createTestVault();
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
    const empty = await app.request(
      "/v1/projects/demo/environments/dev/secrets",
      {
        method: "PATCH",
        headers: authHeaders(key, {}),
        body: JSON.stringify({ set: [{ name: "X", value: "", kind: "secret" }] }),
      },
      env,
    );
    expect(empty.status).toBe(400);

    await app.request(
      "/v1/projects/demo/environments/dev/secrets",
      {
        method: "PATCH",
        headers: authHeaders(key, {}),
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
  });

  test("broker system key cannot GET values", async () => {
    const { app, env } = await createTestVault();
    const user = await bootstrapUser(app, env);
    await app.request(
      "/v1/projects",
      {
        method: "POST",
        headers: authHeaders(user, {}),
        body: JSON.stringify({ name: "demo" }),
      },
      env,
    );
    await app.request(
      "/v1/projects/demo/environments/dev/secrets",
      {
        method: "PATCH",
        headers: authHeaders(user, {}),
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
        headers: authHeaders(user, {}),
        body: JSON.stringify({
          type: "system",
          mode: "broker",
          permission: "read",
          scopes: [{ project: "demo", env: "dev" }],
        }),
      },
      env,
    );
    const broker = ((await created.json()) as { key: string }).key;

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
    const listedBody = (await listed.json()) as { secrets: Array<{ name: string }> };
    expect(listedBody.secrets[0]?.name).toBe("GITHUB_TOKEN");
  });

  test("export returns sealed values for a user key, not a broker key", async () => {
    const { app, env } = await createTestVault();
    const user = await bootstrapUser(app, env);
    await app.request(
      "/v1/projects",
      {
        method: "POST",
        headers: authHeaders(user, {}),
        body: JSON.stringify({ name: "demo" }),
      },
      env,
    );
    await app.request(
      "/v1/projects/demo/environments/dev/secrets",
      {
        method: "PATCH",
        headers: authHeaders(user, {}),
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
    const exportedBody = (await exported.json()) as {
      secrets: Array<{ name: string; value?: string }>;
    };
    expect(exportedBody.secrets[0]?.value).toBe("real-token");

    const created = await app.request(
      "/v1/keys",
      {
        method: "POST",
        headers: authHeaders(user, {}),
        body: JSON.stringify({
          type: "system",
          mode: "broker",
          permission: "read",
          scopes: [{ project: "demo", env: "dev" }],
        }),
      },
      env,
    );
    const broker = ((await created.json()) as { key: string }).key;
    const denied = await app.request(
      "/v1/projects/demo/environments/dev/secrets?export=1",
      { headers: authHeaders(broker) },
      env,
    );
    expect(denied.status).toBe(403);
  });
});
