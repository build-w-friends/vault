import { describe, expect, test } from "bun:test";
import * as v from "valibot";
import { startSecretCollection } from "./collection.ts";
import { collectionReceiptSchema } from "./collection-contract.ts";
import { createTestVault, bootstrapUser, authHeaders } from "./harness.ts";

const target = { project: "demo", env: "dev", name: "TEST_KEY", kind: "secret" as const };
const synthetic = "synthetic-collection-value";
function submit(url: string, value = synthetic, origin = new URL(url).origin) {
  return fetch(`${url}/submit`, {
    method: "POST",
    headers: { origin, "Content-Type": "application/json" },
    body: JSON.stringify({ value }),
  });
}
describe("local collection", () => {
  test("submits once, returns only metadata, and rejects cross-origin and hostile hosts", async () => {
    let calls = 0;
    let started!: () => void;
    const admitted = new Promise<void>((resolve) => {
      started = resolve;
    });
    let release!: () => void;
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    const helper = startSecretCollection({
      target,
      vaultOrigin: "https://vault.example",
      save: async (value) => {
        expect(value).toBe(synthetic);
        calls++;
        started();
        await barrier;
      },
    });
    try {
      expect((await submit(helper.url, synthetic, "https://evil.example")).status).toBe(
        403,
      );
      expect(
        (await fetch(helper.url, { headers: { Host: "evil.example" } })).status,
      ).toBe(403);
      const page = await fetch(helper.url);
      expect(page.headers.get("content-security-policy")).toContain(
        "frame-ancestors 'none'",
      );
      expect(page.headers.get("cache-control")).toBe("no-store");
      const first = submit(helper.url);
      await admitted;
      const repeated = v.parse(
        collectionReceiptSchema,
        await (await submit(helper.url, "different-value")).json(),
      );
      expect(repeated.state).toBe("saving");
      release();
      const text = await (await first).text();
      expect(text).not.toContain(synthetic);
      expect((await helper.completed).state).toBe("stored");
      expect(
        v.parse(collectionReceiptSchema, await (await submit(helper.url)).json()).state,
      ).toBe("stored");
      expect(calls).toBe(1);
    } finally {
      release();
      await helper.stop();
    }
  });
  test("cancel and expiry prevent later submission", async () => {
    for (const cancel of [true, false]) {
      let calls = 0;
      const helper = startSecretCollection({
        target,
        vaultOrigin: "https://vault.example",
        save: async () => {
          calls++;
        },
        timeoutMs: cancel ? 1000 : 5,
      });
      try {
        if (cancel)
          await fetch(`${helper.url}/cancel`, {
            method: "POST",
            headers: {
              origin: new URL(helper.url).origin,
              "Content-Type": "application/json",
            },
            body: "{}",
          });
        expect((await helper.completed).state).toBe(cancel ? "cancelled" : "expired");
        await submit(helper.url);
        expect(calls).toBe(0);
      } finally {
        await helper.stop();
      }
    }
  });
  test("lost reply remains unknown and cannot dispatch again or echo the error", async () => {
    let calls = 0;
    const helper = startSecretCollection({
      target,
      vaultOrigin: "https://vault.example",
      save: async () => {
        calls++;
        throw new Error(synthetic);
      },
    });
    try {
      const response = await submit(helper.url);
      const text = await response.text();
      expect(text).not.toContain(synthetic);
      expect((await helper.completed).state).toBe("unknown");
      await submit(helper.url);
      expect(calls).toBe(1);
    } finally {
      await helper.stop();
    }
  });
});

describe("create-only Vault API", () => {
  test("encrypts a new value, refuses races and system keys, and never echoes input", async () => {
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
    const path = "/v1/projects/demo/environments/dev/secrets/TEST_KEY";
    const write = (value: string) =>
      app.request(
        path,
        {
          method: "POST",
          headers: authHeaders(key, "application/json"),
          body: JSON.stringify({ kind: "secret", value }),
        },
        env,
      );
    const responses = await Promise.all([
      write(synthetic),
      write("synthetic-competitor"),
    ]);
    expect(responses.map((r) => r.status).sort((a, b) => a - b)).toEqual([201, 409]);
    for (const response of responses)
      expect(await response.text()).not.toContain(synthetic);
    const { environmentId } = await store.requireEnvironment("demo", "dev");
    const stored = await store.getSecretByName(environmentId, "TEST_KEY");
    expect([synthetic, "synthetic-competitor"]).toContain(stored?.value ?? "");
    const encrypted = await env.DB.prepare("SELECT value_encrypted FROM secrets").all();
    expect(JSON.stringify(encrypted)).not.toContain("synthetic-");
    expect((await write("overwrite")).status).toBe(409);
    expect((await store.getSecretByName(environmentId, "TEST_KEY"))?.value).toBe(
      stored?.value,
    );
    const system = v.parse(
      v.object({ key: v.string() }),
      await (
        await app.request(
          "/v1/keys",
          {
            method: "POST",
            headers: authHeaders(key, "application/json"),
            body: JSON.stringify({
              type: "system",
              mode: "inject",
              permission: "readwrite",
              scopes: [{ project: "demo", env: "dev" }],
            }),
          },
          env,
        )
      ).json(),
    );
    expect(
      (
        await app.request(
          path + "_SYSTEM",
          {
            method: "POST",
            headers: authHeaders(system.key, "application/json"),
            body: JSON.stringify({ kind: "secret", value: synthetic }),
          },
          env,
        )
      ).status,
    ).toBe(403);
    const malformed = await app.request(
      path,
      { method: "POST", headers: authHeaders(key, "application/json"), body: synthetic },
      env,
    );
    expect(malformed.status).toBe(400);
    expect(await malformed.text()).not.toContain(synthetic);
  });
});
