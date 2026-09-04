import { describe, expect, test } from "bun:test";
import * as v from "valibot";

import { auditRecordSchema } from "./client-schemas.ts";
import {
  authHeaders,
  bootstrapUser,
  createTestVault,
  TEST_BOOTSTRAP_TOKEN,
} from "./harness.ts";
import { randomApiKey } from "./keys.ts";

const keyResponseSchema = v.looseObject({
  key: v.string(),
  prefix: v.string(),
});

const auditPageSchema = v.looseObject({
  events: v.array(auditRecordSchema),
  nextCursor: v.string(),
});

const auditPageWithoutCursorSchema = v.looseObject({
  events: v.array(auditRecordSchema),
});

describe("operator lifecycle", () => {
  test("bootstrap is an atomic one-time claim", async () => {
    const { app, env } = await createTestVault();
    const request = () =>
      app.request(
        "/v1/bootstrap",
        {
          method: "POST",
          headers: { "X-Vault-Bootstrap-Token": TEST_BOOTSTRAP_TOKEN },
          body: "{}",
        },
        env,
      );
    const responses = await Promise.all([request(), request()]);
    expect(responses.map((response) => response.status).sort((a, b) => a - b)).toEqual([
      200, 409,
    ]);
  });

  test("expired keys fail and the last active user cannot be revoked", async () => {
    const { app, env, store } = await createTestVault();
    const user = await bootstrapUser(app, env);
    const current = await store.findKeyByPlaintext(user);
    expect(current).not.toBeNull();
    const lastUser = await app.request(
      `/v1/keys/${current!.keyPrefix}`,
      { method: "DELETE", headers: authHeaders(user) },
      env,
    );
    expect(lastUser.status).toBe(409);

    const expired = randomApiKey("system");
    await store.insertKey({
      plaintext: expired.plaintext,
      prefix: expired.prefix,
      type: "system",
      permission: "read",
      mode: "inject",
      label: "expired",
      scopes: [{ project: "demo", env: "dev" }],
      expiresAt: "2020-01-01T00:00:00.000Z",
    });
    const denied = await app.request(
      "/v1/projects",
      { headers: authHeaders(expired.plaintext) },
      env,
    );
    expect(denied.status).toBe(401);
  });

  test("rotation revokes the old key and audit cursors do not repeat rows", async () => {
    const { app, env } = await createTestVault();
    const bootstrap = await bootstrapUser(app, env);
    const created = await app.request(
      "/v1/keys",
      {
        method: "POST",
        headers: authHeaders(bootstrap, "application/json"),
        body: JSON.stringify({ type: "user", label: "rotating" }),
      },
      env,
    );
    const first = v.parse(keyResponseSchema, await created.json());
    const rotated = await app.request(
      `/v1/keys/${first.prefix}/rotate`,
      { method: "POST", headers: authHeaders(bootstrap, "application/json"), body: "{}" },
      env,
    );
    const second = v.parse(keyResponseSchema, await rotated.json());
    expect(second.prefix).not.toBe(first.prefix);
    expect(
      (await app.request("/v1/projects", { headers: authHeaders(first.key) }, env))
        .status,
    ).toBe(401);
    expect(
      (await app.request("/v1/projects", { headers: authHeaders(second.key) }, env))
        .status,
    ).toBe(200);

    const firstPageResponse = await app.request(
      "/v1/audit?limit=2",
      { headers: authHeaders(bootstrap) },
      env,
    );
    const firstPage = v.parse(auditPageSchema, await firstPageResponse.json());
    const secondPageResponse = await app.request(
      `/v1/audit?limit=2&cursor=${encodeURIComponent(firstPage.nextCursor)}`,
      { headers: authHeaders(bootstrap) },
      env,
    );
    const secondPage = v.parse(
      auditPageWithoutCursorSchema,
      await secondPageResponse.json(),
    );
    expect(firstPage.events).toHaveLength(2);
    expect(secondPage.events.length).toBeGreaterThan(0);
    expect(
      secondPage.events.some((event) =>
        firstPage.events.some((firstEvent) => firstEvent.id === event.id),
      ),
    ).toBe(false);
  });

  test("audit retention prunes rows older than its cutoff", async () => {
    const { app, env, store } = await createTestVault();
    await bootstrapUser(app, env);
    expect((await store.listAudit({ limit: 20 })).length).toBeGreaterThan(0);
    expect(await store.pruneAudit("2099-01-01T00:00:00.000Z")).toBeGreaterThan(0);
    expect(await store.listAudit({ limit: 20 })).toEqual([]);
  });
});
