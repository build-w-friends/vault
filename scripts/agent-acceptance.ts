import { chromium } from "playwright";
import { generateKeyPairSync } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { createTestVault, bootstrapUser, authHeaders } from "../src/harness.ts";
import { VaultClient } from "../src/client.ts";
import { AgentTasks } from "../src/agent/tasks.ts";
import { AgentRuntime } from "../src/agent/runtime.ts";
const output = resolve(import.meta.dir, "../.wrangler/agent-acceptance");
await mkdir(output, { recursive: true });
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
const api = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  fetch: (request) => app.fetch(request, env),
});
const client = new VaultClient(`http://127.0.0.1:${api.port}`, key);
const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});
await client.patchSecrets("demo", "dev", {
  set: [
    {
      name: "VAULT_GITHUB_APP",
      kind: "secret",
      value: JSON.stringify({ appId: "123", privateKey }),
    },
  ],
});
let minted = 0;
const send: typeof fetch = Object.assign(
  async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    if (request.method === "POST") {
      minted++;
      return Response.json({
        token: "synthetic-github-access",
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });
    }
    if (request.url.endsWith("/installation")) return Response.json({ id: 123 });
    return Response.json({ repository: "demo/repo", echo: "synthetic-github-access" });
  },
  { preconnect: fetch.preconnect },
);
const tasks = new AgentTasks(":memory:");
const runtime = new AgentRuntime(client, "demo", "dev", tasks, send);
const browser = await chromium.launch({ headless: true });
try {
  for (const theme of ["light", "dark"] as const) {
    const task = await runtime.requestGithub(crypto.randomUUID(), "demo/repo");
    const context = await browser.newContext({
      colorScheme: theme,
      viewport:
        theme === "dark" ? { width: 390, height: 844 } : { width: 900, height: 850 },
    });
    const page = await context.newPage();
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.goto(task.url!);
    await page.screenshot({
      path: resolve(output, `${theme}-approval.png`),
      fullPage: true,
    });
    await page.getByRole("button", { name: "Allow read access" }).click();

    await page
      .getByRole("status")
      .filter({ hasText: "stored" })
      .waitFor({ timeout: 5000 });
    if (tasks.get(task.taskId).state !== "stored")
      throw new Error(
        `Approval failed: ${tasks.get(task.taskId).state}; provider calls ${minted}`,
      );
    const body = await runtime.readProvider(task.taskId, "/repos/demo/repo/contents");
    if (JSON.stringify(body).includes("synthetic-github-access"))
      throw new Error("Bearer leaked");
    if (errors.length) throw new Error("Browser errors");
    await page.screenshot({
      path: resolve(output, `${theme}-stored.png`),
      fullPage: true,
    });
    await context.close();
  }
  if (minted !== 2) throw new Error("Duplicate provider issuance");
  console.log(
    "Both themes: browser consent, repository-scoped issuance, Vault storage and brokered read passed; bearer echo redacted.",
  );
} finally {
  await browser.close();
  await runtime.close();
  tasks.close();
  await api.stop(true);
}
