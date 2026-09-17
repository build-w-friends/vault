import { test, expect } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { serveStdio, StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { PassThrough } from "node:stream";
import { z } from "zod";
import { taskTransport } from "./task-protocol.ts";
import { createTestVault, bootstrapUser, authHeaders } from "../harness.ts";
import { VaultClient } from "../client.ts";
import { AgentTasks } from "./tasks.ts";
import { AgentRuntime } from "./runtime.ts";
import { createAgentMcp } from "./mcp.ts";
import { githubAccess, exchangeCloudflare } from "./provider.ts";
import { cloudflareHandoff } from "./handoff.ts";

async function fixture() {
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
  const tasks = new AgentTasks(":memory:");
  const runtime = new AgentRuntime(client, "demo", "dev", tasks);
  return {
    client,
    tasks,
    runtime,
    close: async () => {
      await runtime.close();
      tasks.close();
      await api.stop(true);
    },
  };
}
test("durable receipts survive reopen; immutable IDs and expired dispatch never replay", () => {
  const directory = mkdtempSync(join(tmpdir(), "vault-agent-test-"));
  let now = 1000;
  const path = join(directory, "tasks.sqlite");
  const id = crypto.randomUUID();
  let tasks = new AgentTasks(path, () => now);
  tasks.create(id, "collection", "KEY");
  expect(tasks.claim(id)).toBe(true);
  expect(tasks.claim(id)).toBe(false);
  tasks.close();
  tasks = new AgentTasks(path, () => now);
  expect(tasks.get(id).state).toBe("saving");
  now += 60001;
  expect(tasks.get(id).state).toBe("unknown");
  expect(tasks.create(id, "collection", "KEY").created).toBe(false);
  expect(() => tasks.create(id, "collection", "OTHER")).toThrow();
  tasks.close();
  rmSync(directory, { recursive: true });
});
test("MCP discovers tools, elicits a URL and negotiates durable Tasks without secret output", async () => {
  const f = await fixture();
  const input = new PassThrough();
  const output = new PassThrough();
  const handle = serveStdio(() => createAgentMcp(f.runtime), {
    transport: taskTransport(new StdioServerTransport(input, output), f.runtime),
  });
  async function rpc(
    method: string,
    args: z.infer<ReturnType<typeof z.json>>,
    capabilities: z.infer<ReturnType<typeof z.json>> = { elicitation: { url: {} } },
  ) {
    const params = z.record(z.string(), z.json()).parse(args);
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("MCP response timed out")), 3000);
      output.once("data", (data: Buffer) => {
        clearTimeout(timer);
        resolve(data.toString());
      });
      input.write(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method,
          params: {
            ...params,
            _meta: {
              "io.modelcontextprotocol/protocolVersion": "2026-07-28",
              "io.modelcontextprotocol/clientInfo": { name: "test", version: "1" },
              "io.modelcontextprotocol/clientCapabilities": capabilities,
            },
          },
        }) + "\n",
      );
    });
  }
  try {
    expect(await rpc("tools/list", {})).toContain("connect_cloudflare");
    const first = crypto.randomUUID();
    expect(
      await rpc("tools/call", {
        name: "collect_secret",
        arguments: { requestId: first, name: "KEY" },
      }),
    ).toContain("input_required");
    const task = f.tasks.get(first);
    const url = task.url!;
    await fetch(url + "/submit", {
      method: "POST",
      headers: { Origin: new URL(url).origin, "Content-Type": "application/json" },
      body: JSON.stringify({ value: "synthetic-agent-secret" }),
    });
    await new Promise((done) => setTimeout(done, 5));
    const receipt = await rpc("tools/call", {
      name: "get_task",
      arguments: { requestId: first },
    });
    expect(receipt).toContain("stored");
    expect(receipt).not.toContain("synthetic-agent-secret");
    const second = crypto.randomUUID();
    const caps = {
      extensions: { "io.modelcontextprotocol/tasks": {} },
      elicitation: { url: {} },
    };
    const created = await rpc(
      "tools/call",
      { name: "collect_secret", arguments: { requestId: second, name: "SECOND" } },
      caps,
    );
    expect(created).toContain('"resultType":"task"');
    const pending = await rpc("tasks/get", { taskId: second }, caps);
    expect(pending).toContain("input_required");
    expect(pending).toContain("inputRequests");
    expect(
      await rpc(
        "tasks/update",
        { taskId: second, inputResponses: { vault: { action: "accept" } } },
        caps,
      ),
    ).toContain("input_required");
    expect(f.tasks.get(second).state).toBe("waiting");
    expect(await rpc("tasks/cancel", { taskId: second }, caps)).toContain("cancelled");
    const third = crypto.randomUUID();
    await rpc("tools/call", {
      name: "collect_secret",
      arguments: { requestId: third, name: "THIRD" },
    });
    const declined = await rpc("tools/call", {
      name: "collect_secret",
      arguments: { requestId: third, name: "THIRD" },
      inputResponses: { vault: { action: "cancel" } },
    });
    expect(declined).toContain("cancelled");
    expect(f.tasks.get(third).state).toBe("cancelled");
  } finally {
    await handle.close();
    await f.close();
  }
});
test("GitHub discovers installation and requests exactly one repository with read permissions", async () => {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const requests: Request[] = [];
  const send: typeof fetch = Object.assign(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      requests.push(request);
      return Response.json(
        request.method === "GET"
          ? { id: 17 }
          : {
              token: "synthetic-gh",
              expires_at: new Date(Date.now() + 3600000).toISOString(),
            },
      );
    },
    { preconnect: fetch.preconnect },
  );
  const access = await githubAccess(
    JSON.stringify({ appId: "123", privateKey }),
    "owner/repo",
    send,
  );
  expect(access.repository).toBe("owner/repo");
  expect(requests[0]?.url).toBe("https://api.github.com/repos/owner/repo/installation");
  expect(z.json().parse(await requests[1]!.json())).toEqual({
    repositories: ["repo"],
    permissions: { contents: "read", metadata: "read" },
  });
  expect(requests[1]?.redirect).toBe("error");
});
test("OAuth callback rejects invalid state; code exchanged once with PKCE and saved without reflection", async () => {
  const tasks = new AgentTasks(":memory:");
  const taskId = crypto.randomUUID();
  tasks.create(taskId, "cloudflare", "CF_TEST");
  const reserve = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () => new Response(),
  });
  const port = reserve.port;
  await reserve.stop(true);
  let calls = 0;
  let stored = "";
  const send: typeof fetch = Object.assign(
    async (_input: RequestInfo | URL, init?: RequestInit) => {
      calls++;
      const body = new URLSearchParams(
        await new Request("https://provider.test", init).text(),
      );
      expect(body.get("code_verifier")?.length).toBeGreaterThan(32);
      expect(body.get("client_secret")).toBeNull();
      return Response.json({
        access_token: "synthetic-oauth",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "workers-platform.read",
      });
    },
    { preconnect: fetch.preconnect },
  );
  const callback = `http://127.0.0.1:${port}/callback`;
  const helper = cloudflareHandoff({
    tasks,
    taskId,
    config: {
      clientId: "test",
      redirectUri: callback,
      scopes: ["workers-platform.read"],
    },
    save: async (value) => {
      stored = value;
    },
    send,
  });
  try {
    const auth = new URL(helper.url);
    expect(auth.searchParams.get("code_challenge_method")).toBe("S256");
    expect((await fetch(callback + "?state=bad&code=test")).status).toBe(400);
    expect(calls).toBe(0);
    const url = callback + `?state=${auth.searchParams.get("state")}&code=test`;
    const text = await (await fetch(url)).text();
    expect(text).toContain("stored");
    expect(text).not.toContain("synthetic-oauth");
    expect(stored).toContain("synthetic-oauth");
    await fetch(url);
    expect(calls).toBe(1);
  } finally {
    await helper.stop();
    tasks.close();
  }
});
test("OAuth rejects missing required scope", async () => {
  const send: typeof fetch = Object.assign(
    async () =>
      Response.json({
        access_token: "synthetic",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "different",
      }),
    { preconnect: fetch.preconnect },
  );
  expect(
    exchangeCloudflare(
      {
        clientId: "x",
        redirectUri: "http://127.0.0.1:1/callback",
        code: "code",
        verifier: "verifier",
        scopes: ["required"],
      },
      send,
    ),
  ).rejects.toThrow("Required OAuth scope");
});

test("pending collection resumes with the same request and a fresh browser URL after host restart", async () => {
  const f = await fixture();
  const id = crypto.randomUUID();
  const first = await f.runtime.collect(id, "RESUME");
  await f.runtime.close();
  expect(f.tasks.get(id).state).toBe("waiting");
  expect(f.tasks.get(id).url).toBeNull();
  const resumed = new AgentRuntime(f.client, "demo", "dev", f.tasks);
  try {
    const second = await resumed.resume(first.taskId);
    expect(second.taskId).toBe(first.taskId);
    expect(second.url).not.toBe(first.url);
    const url = second.url!;
    await fetch(url + "/submit", {
      method: "POST",
      headers: { Origin: new URL(url).origin, "Content-Type": "application/json" },
      body: JSON.stringify({ value: "synthetic-resume" }),
    });
    await new Promise((done) => setTimeout(done, 5));
    expect(f.tasks.get(id).state).toBe("stored");
    expect((await resumed.collect(id, "RESUME")).state).toBe("stored");
  } finally {
    await resumed.close();
    await f.close();
  }
});

test("Cloudflare connection persists in Vault, resumes broker reads, and refuses expired access", async () => {
  const f = await fixture();
  const reserve = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () => new Response(),
  });
  const callback = `http://127.0.0.1:${reserve.port}/callback`;
  await reserve.stop(true);
  await f.client.patchSecrets("demo", "dev", {
    set: [
      {
        name: "VAULT_CLOUDFLARE_OAUTH",
        kind: "config",
        value: JSON.stringify({
          clientId: "test",
          redirectUri: callback,
          scopes: ["workers-platform.read"],
        }),
      },
    ],
  });
  const send: typeof fetch = Object.assign(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      if (request.method === "POST")
        return Response.json({
          access_token: "synthetic-cf-runtime",
          token_type: "Bearer",
          expires_in: 3600,
        });
      expect(request.headers.get("Authorization")).toBe("Bearer synthetic-cf-runtime");
      return Response.json({ result: [], echo: "synthetic-cf-runtime" });
    },
    { preconnect: fetch.preconnect },
  );
  const runtime = new AgentRuntime(f.client, "demo", "dev", f.tasks, send);
  const id = crypto.randomUUID();
  try {
    const task = await runtime.connectCloudflare(id);
    const auth = new URL(task.url!);
    const response = await fetch(
      `${callback}?state=${auth.searchParams.get("state")}&code=test`,
    );
    expect(await response.text()).toContain("stored");
    await runtime.close();
    const restarted = new AgentRuntime(f.client, "demo", "dev", f.tasks, send);
    expect(
      JSON.stringify(await restarted.readProvider(task.taskId, "/client/v4/accounts")),
    ).not.toContain("synthetic-cf-runtime");
    expect(
      restarted.readProvider(task.taskId, "/client/v4/user/tokens"),
    ).rejects.toThrow();
    await f.client.patchSecrets("demo", "dev", {
      set: [
        {
          name: task.target,
          kind: "secret",
          value: JSON.stringify({
            accessToken: "synthetic-cf-runtime",
            expiresAt: 1,
            scopes: "workers-platform.read",
          }),
        },
      ],
    });
    expect(restarted.readProvider(task.taskId, "/client/v4/accounts")).rejects.toThrow(
      "expired",
    );
    await restarted.close();
  } finally {
    await runtime.close();
    await f.close();
  }
});
