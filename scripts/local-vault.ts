/** Setup shared by the browser acceptance scripts: an in-process vault with a `demo` project. */
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { createTestVault, bootstrapUser, authHeaders } from "../src/harness.ts";
import { VaultClient } from "../src/client.ts";

/**
 * Serves a fresh test vault on a loopback port and creates `.wrangler/<name>`
 * for screenshots and receipts. Stop `api` when done.
 */
export async function startLocalVault(name: string) {
  const output = resolve(import.meta.dir, `../.wrangler/${name}`);
  await mkdir(output, { recursive: true });
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
  const api = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: (request) => app.fetch(request, env),
  });
  const origin = `http://127.0.0.1:${api.port}`;
  return { output, store, api, origin, client: new VaultClient(origin, key) };
}
