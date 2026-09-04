import { describe, expect, test } from "bun:test";

import { authHeaders, bootstrapUser, createTestVault } from "./harness.ts";

describe("human run inject", () => {
  test("trusted child sees the real secret and nothing is written to disk", async () => {
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
          set: [{ name: "DEMO_SECRET", value: "visible-to-run", kind: "secret" }],
        }),
      },
      env,
    );

    const shown = await app.request(
      "/v1/projects/demo/environments/dev/secrets?show=1",
      {
        headers: authHeaders(key),
      },
      env,
    );
    // SAFETY: The owned show=1 route projects SecretRecord names and optional values.
    const body = (await shown.json()) as {
      secrets: Array<{ name: string; value?: string }>;
    };
    const injected: Record<string, string> = {};
    for (const secret of body.secrets) {
      if (secret.value != null) injected[secret.name] = secret.value;
    }

    const child = Bun.spawn({
      cmd: [
        process.execPath,
        "-e",
        "process.stdout.write(process.env.DEMO_SECRET ?? '')",
      ],
      env: { ...process.env, ...injected, VAULT_API_KEY: undefined },
      stdout: "pipe",
      stderr: "pipe",
    });
    const output = await new Response(child.stdout).text();
    expect(await child.exited).toBe(0);
    expect(output).toBe("visible-to-run");
  });
});
