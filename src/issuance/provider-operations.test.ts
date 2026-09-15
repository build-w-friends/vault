import { rejects } from "node:assert/strict";
import { expect, test } from "bun:test";
import { issuanceFixture, fixturePlan, fixtureIds } from "./fixture.ts";
import { CloudflareIssuer } from "./cloudflare.ts";
import { providerRequest } from "./provider-request.ts";
import { saveOutput, resolveSecrets } from "./outputs.ts";
import { IssuanceService } from "./service.ts";
import { apiRequestSchema, prepareSchema, type ApiRequest } from "./contracts.ts";

type Fixture = Awaited<ReturnType<typeof issuanceFixture>>;
type Session = Awaited<ReturnType<Fixture["connect"]>>;

test("native token creation and cleanup preserve the fetch receiver contract", async () => {
  const plan = {
    ...fixturePlan(),
    accountId: fixtureIds.account,
    expiresAt: new Date(Date.now() + 3600000).toISOString(),
  };
  const token = {
    id: "d".repeat(32),
    name: `vault-issuance-${plan.requestId}`,
    expires_on: plan.expiresAt,
    policies: plan.operation.policies,
    status: "active",
    value: "synthetic-child",
  };
  const methods: string[] = [];
  const send: typeof fetch = Object.assign(
    async function (this: void, input: RequestInfo | URL, init?: RequestInit) {
      // Workers rejects an unrelated receiver before making an outbound request.
      if (this !== undefined) throw new TypeError("Illegal invocation");
      const request = new Request(input, init);
      expect(request.headers.get("Authorization")).toBe("Bearer synthetic-parent");
      expect(request.redirect).toBe("manual");
      methods.push(request.method);
      if (request.method === "POST")
        return Response.json({ success: true, result: token });
      if (request.method === "GET")
        return Response.json({ success: true, result: [token] });
      expect(new URL(request.url).pathname.endsWith(`/tokens/${token.id}`)).toBe(true);
      return Response.json({ success: true, result: { id: token.id } });
    },
    { preconnect: fetch.preconnect },
  );
  const provider = new CloudflareIssuer(send);
  expect(await provider.create("synthetic-parent", plan)).toEqual({
    id: token.id,
    value: token.value,
  });
  await provider.revokeUncertain("synthetic-parent", plan);
  expect(methods).toEqual(["POST", "GET", "DELETE"]);
});

test.each(["not JSON", "x".repeat(2000001)])(
  "unreadable rejection details preserve the definite provider outcome",
  async (body) => {
    const provider = new CloudflareIssuer(
      Object.assign(async () => new Response(body, { status: 400 }), {
        preconnect: fetch.preconnect,
      }),
    );
    await rejects(
      provider.create("synthetic-parent", {
        ...fixturePlan(),
        accountId: fixtureIds.account,
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      }),
      {
        outcome: "rejected",
        status: 400,
        message: "Cloudflare rejected the operation (HTTP 400)",
      },
    );
  },
);

async function approve(f: Fixture, session: Session, requestId: string) {
  const path = `/issuance/approve/${requestId}`;
  expect(
    (
      await f.request(path, {
        method: "POST",
        headers: { Cookie: session.cookie, Origin: "https://vault.test" },
        body: new URLSearchParams({
          csrf: await f.csrf(path, session.cookie),
          decision: "approve",
        }),
      })
    ).status,
  ).toBe(303);
}
async function prepareApi(f: Fixture, session: Session, request: ApiRequest) {
  const plan = prepareSchema.parse({
    ...fixturePlan(),
    operation: { kind: "api-request", request },
  });
  await f.service.prepare(session.auth, plan);
  await approve(f, session, plan.requestId);
  return plan;
}
function withSend(f: Fixture, send: (request: Request) => Promise<Response>) {
  return new IssuanceService(
    f.store,
    f.service.provider,
    Object.assign(
      async (input: RequestInfo | URL, init?: RequestInit) =>
        send(new Request(input, init)),
      { preconnect: fetch.preconnect },
    ),
  );
}

test.each([
  ["D1 database", "d1/database", { name: "app-data" }],
  ["R2 bucket", "r2/buckets", { name: "app-assets" }],
  ["KV namespace", "storage/kv/namespaces", { title: "app-cache" }],
])("approved parent creates a %s once", async (_, path, payload) => {
  const f = await issuanceFixture();
  const session = await f.connect();
  const request = apiRequestSchema.parse({
    method: "POST",
    path: `/accounts/${fixtureIds.account}/${path}`,
    body: { kind: "json", value: payload },
  });
  const plan = await prepareApi(f, session, request);
  let calls = 0;
  const service = withSend(f, async (incoming) => {
    calls++;
    expect(incoming.headers.get("Authorization")).toBe(
      "Bearer synthetic-parent-never-export",
    );
    expect(new URL(incoming.url).pathname).toBe(`/client/v4${request.path}`);
    expect(await incoming.text()).toBe(JSON.stringify(payload));
    return Response.json({ success: true, result: { id: "new-resource-id" } });
  });
  const result = await service.execute(session.auth, plan.requestId);
  expect(result.status).toBe("completed");
  expect(result.result?.body).toEqual({
    success: true,
    result: { id: "new-resource-id" },
  });
  expect(await service.execute(session.auth, plan.requestId)).toEqual(result);
  expect(calls).toBe(1);
});

test("Worker upload preserves approved multipart metadata and code", async () => {
  const f = await issuanceFixture();
  const session = await f.connect();
  const metadata = JSON.stringify({
    main_module: "worker.js",
    compatibility_date: "2026-09-05",
  });
  const script = 'export default { fetch() { return new Response("Hello"); } };';
  const plan = await prepareApi(
    f,
    session,
    apiRequestSchema.parse({
      method: "PUT",
      path: `/accounts/${fixtureIds.account}/workers/scripts/example`,
      body: {
        kind: "multipart",
        parts: [
          {
            name: "metadata",
            content: metadata,
            filename: "metadata.json",
            contentType: "application/json",
          },
          {
            name: "worker.js",
            content: script,
            filename: "worker.js",
            contentType: "application/javascript+module",
          },
        ],
      },
    }),
  );
  const page = await f.request(`/issuance/approve/${plan.requestId}`, {
    headers: { Cookie: session.cookie },
  });
  expect(await page.text()).toContain("compatibility_date");
  const service = withSend(f, async (incoming) => {
    const form = await incoming.formData();
    const meta = form.get("metadata");
    const worker = form.get("worker.js");
    expect(meta instanceof File && (await meta.text())).toBe(metadata);
    expect(worker instanceof File && (await worker.text())).toBe(script);
    return Response.json({ success: true, result: { id: "example" } });
  });
  expect((await service.execute(session.auth, plan.requestId)).status).toBe("completed");
});

test("native service and token-management policies replace the capability list", async () => {
  const f = await issuanceFixture();
  const session = await f.connect();
  const plan = fixturePlan();
  plan.operation.policies = [
    {
      effect: "allow",
      permission_groups: [{ id: "9".repeat(32) }, { id: "8".repeat(32) }],
      resources: { [`com.cloudflare.api.account.${fixtureIds.account}`]: "*" },
    },
  ];
  await f.service.prepare(session.auth, plan);
  await approve(f, session, plan.requestId);
  expect((await f.service.execute(session.auth, plan.requestId)).status).toBe("issued");
  expect([...f.tokens.values()][0]?.policies).toEqual(plan.operation.policies);
});

test("child DNS reads forward pagination and filters", async () => {
  const f = await issuanceFixture();
  const session = await f.connect();
  const plan = fixturePlan();
  await f.service.prepare(session.auth, plan);
  await approve(f, session, plan.requestId);
  await f.service.execute(session.auth, plan.requestId);
  const service = withSend(f, async (incoming) => {
    const url = new URL(incoming.url);
    expect(url.searchParams.get("page")).toBe("2");
    expect(url.searchParams.get("name")).toBe("api.example.test");
    expect(incoming.headers.get("Authorization")).toBe("Bearer synthetic-child-1");
    return Response.json({
      result: [{ name: "api.example.test" }],
      result_info: { page: 2 },
    });
  });
  expect(
    JSON.stringify(
      (
        await service.use(
          session.auth,
          plan.requestId,
          apiRequestSchema.parse({
            method: "GET",
            path: `/zones/${fixtureIds.zone}/dns_records`,
            query: { page: "2", name: "api.example.test" },
          }),
        )
      ).body,
    ),
  ).toContain('"page":2');
});

test("cancellation revokes when issuance advances after the initial read", async () => {
  const f = await issuanceFixture();
  const session = await f.connect();
  const plan = fixturePlan();
  await f.service.prepare(session.auth, plan);
  await approve(f, session, plan.requestId);
  const request = f.store.request.bind(f.store);
  let raced = false;
  f.store.request = async (...args) => {
    const row = await request(...args);
    if (!raced) {
      raced = true;
      await f.service.execute(session.auth, plan.requestId);
    }
    return row;
  };
  expect((await f.service.revoke(session.auth, plan.requestId)).status).toBe("revoked");
  expect(f.tokens.size).toBe(0);
  const rejected = await f.service
    .use(
      session.auth,
      plan.requestId,
      apiRequestSchema.parse({
        method: "GET",
        path: `/zones/${fixtureIds.zone}/dns_records`,
      }),
    )
    .then(
      () => "unexpected success",
      (error) => String(error),
    );
  expect(rejected).toContain("unavailable");
});

test("unknown service creation is never retried or reported expired", async () => {
  const f = await issuanceFixture();
  const session = await f.connect();
  const plan = await prepareApi(
    f,
    session,
    apiRequestSchema.parse({
      method: "POST",
      path: `/accounts/${fixtureIds.account}/d1/database`,
      body: { kind: "json", value: { name: "example" } },
    }),
  );
  let calls = 0;
  const service = withSend(f, async () => {
    calls++;
    throw new Error("lost response");
  });
  expect(
    await service.execute(session.auth, plan.requestId).then(
      () => "unexpected success",
      (error) => String(error),
    ),
  ).toContain("unknown");
  f.advance(3600001);
  await service.reconcile();
  expect((await f.store.request(plan.requestId)).status).toBe("unknown");
  expect(
    await service.execute(session.auth, plan.requestId).then(
      () => "unexpected success",
      (error) => String(error),
    ),
  ).toContain("approval");
  expect(calls).toBe(1);
});

test("credential results stay encrypted and inject into a later approved request", async () => {
  const f = await issuanceFixture();
  const session = await f.connect();
  const plan = await prepareApi(
    f,
    session,
    apiRequestSchema.parse({
      method: "PUT",
      path: `/accounts/${fixtureIds.account}/tokens/${"9".repeat(32)}/value`,
    }),
  );
  const result = await withSend(f, async () =>
    Response.json({ success: true, result: { value: "synthetic-rotated-token" } }),
  ).execute(session.auth, plan.requestId);
  expect(JSON.stringify(result)).not.toContain("synthetic-rotated-token");
  const outputId = result.result?.outputId;
  if (!outputId) throw new Error("missing output");
  const raw = await f.env.DB.prepare(
    "SELECT encrypted FROM issuance_outputs WHERE id = ?",
  )
    .bind(outputId)
    .first<{ encrypted: string }>();
  expect(raw?.encrypted).not.toContain("synthetic-rotated-token");
  const reference = { $vaultSecret: { outputId, pointer: "/result/value" } };
  const next = await prepareApi(
    f,
    session,
    apiRequestSchema.parse({
      method: "PUT",
      path: `/accounts/${fixtureIds.account}/workers/scripts/example/secrets`,
      body: {
        kind: "json",
        value: { name: "PROVIDER_TOKEN", type: "secret_text", text: reference },
      },
    }),
  );
  const injector = withSend(f, async (incoming) => {
    expect(await incoming.text()).toBe(
      JSON.stringify({
        name: "PROVIDER_TOKEN",
        type: "secret_text",
        text: "synthetic-rotated-token",
      }),
    );
    return Response.json({ success: true, message: "echo synthetic-rotated-token" });
  });
  const injected = await injector.execute(session.auth, next.requestId);
  expect(injected.status).toBe("completed");
  expect(JSON.stringify(injected)).not.toContain("synthetic-rotated-token");
});

test.each([
  { method: "GET", path: "/accounts/" + "a".repeat(32) + "/../tokens" },
  { method: "GET", path: "/accounts/" + "a".repeat(32) + "/%2e%2e/tokens" },
  { method: "GET", path: "/accounts/" + "a".repeat(32), host: "evil.test" },
])("request rejects URL escapes", (input) => {
  expect(apiRequestSchema.safeParse(input).success).toBe(false);
});

test.each([
  {
    host: "api.cloudflare.com",
    path: `/accounts/${fixtureIds.account}/ai/run/@cf/meta/llama-example`,
    header: "Authorization",
  },
  {
    host: "api.cloudflare.com",
    path: `/accounts/${fixtureIds.account}/ai/v1/chat/completions`,
    header: "Authorization",
  },
  {
    host: "gateway.ai.cloudflare.com",
    path: `/v1/${fixtureIds.account}/default/compat/chat/completions`,
    header: "cf-aig-authorization",
  },
])("AI requests use the correct provider host and auth header", async (input) => {
  const f = await issuanceFixture();
  const session = await f.connect();
  const plan = await prepareApi(
    f,
    session,
    apiRequestSchema.parse({
      method: "POST",
      host: input.host,
      path: input.path,
      body: {
        kind: "json",
        value: {
          model: "dynamic/example",
          messages: [{ role: "user", content: "Hello" }],
          stream: false,
        },
      },
    }),
  );
  const service = withSend(f, async (request) => {
    expect(new URL(request.url).hostname).toBe(input.host);
    expect(request.headers.get(input.header)).toBe(
      "Bearer synthetic-parent-never-export",
    );
    return Response.json({ result: { response: "Hello" } });
  });
  expect((await service.execute(session.auth, plan.requestId)).result?.body).toEqual({
    result: { response: "Hello" },
  });
});

test("scalar provider token results are sealed references", async () => {
  const f = await issuanceFixture();
  const session = await f.connect();
  const plan = await prepareApi(
    f,
    session,
    apiRequestSchema.parse({
      method: "GET",
      path: `/accounts/${fixtureIds.account}/cfd_tunnel/example/token`,
    }),
  );
  const result = await withSend(f, async () =>
    Response.json({ success: true, result: "synthetic-tunnel-token" }),
  ).execute(session.auth, plan.requestId);
  expect(JSON.stringify(result)).not.toContain("synthetic-tunnel-token");
  expect(JSON.stringify(result)).toContain("$vaultSecret");
});

test("provider redirects never forward the credential or return a success", async () => {
  let redirected = 0;
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      if (new URL(request.url).pathname === "/redirected") {
        redirected++;
        return Response.json({ success: true });
      }
      return new Response(null, { status: 302, headers: { Location: "/redirected" } });
    },
  });
  const send: typeof fetch = Object.assign(
    (input: RequestInfo | URL, init?: RequestInit) =>
      fetch(
        new URL(
          new URL(input instanceof Request ? input.url : input).pathname,
          server.url,
        ),
        init,
      ),
    { preconnect: fetch.preconnect },
  );
  try {
    await rejects(
      providerRequest(
        send,
        "synthetic-redirect-token",
        apiRequestSchema.parse({
          method: "GET",
          path: `/accounts/${fixtureIds.account}/workers/scripts`,
        }),
      ),
      new RegExp("Provider redirects are not allowed"),
    );
    await rejects(
      new CloudflareIssuer(send).create("synthetic-redirect-token", {
        ...fixturePlan(),
        accountId: fixtureIds.account,
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      }),
      { outcome: "unknown" },
    );
    expect(redirected).toBe(0);
  } finally {
    await server.stop(true);
  }
});

test("invalid secret references fail before a provider request and retain rejection evidence", async () => {
  const f = await issuanceFixture();
  const session = await f.connect();
  const plan = await prepareApi(
    f,
    session,
    apiRequestSchema.parse({
      method: "POST",
      path: `/accounts/${fixtureIds.account}/d1/database`,
      body: {
        kind: "json",
        value: {
          value: { $vaultSecret: { outputId: crypto.randomUUID(), pointer: "/value" } },
        },
      },
    }),
  );
  let calls = 0;
  const service = withSend(f, async () => {
    calls++;
    return Response.json({ success: true });
  });
  await rejects(service.execute(session.auth, plan.requestId), /rejected/);
  expect(calls).toBe(0);
  const result = await service.view(await f.store.request(plan.requestId));
  expect(result.status).toBe("failed");
  expect(result.result?.body).toEqual({
    outcome: "rejected",
    reason: "provider output not found",
  });
});

test("short request lifetimes bound the displayed approval deadline", async () => {
  const f = await issuanceFixture();
  const session = await f.connect();
  const result = await f.service.prepare(session.auth, {
    ...fixturePlan(),
    ttlSeconds: 60,
  });
  expect(result.approvalExpiresAt).toBe(result.plan.expiresAt);
  f.advance(60001);
  const page = await f.request(`/issuance/approve/${result.requestId}`, {
    headers: { Cookie: session.cookie },
  });
  expect(page.status).toBe(200);
  expect(await page.text()).not.toContain("Approve once");
});

test("credential use is rate limited before provider effects", async () => {
  const f = await issuanceFixture();
  const session = await f.connect();
  const plan = fixturePlan();
  await f.service.prepare(session.auth, plan);
  await approve(f, session, plan.requestId);
  await f.service.execute(session.auth, plan.requestId);
  const input = apiRequestSchema.parse({
    method: "GET",
    path: `/zones/${fixtureIds.zone}/dns_records`,
  });
  for (let i = 0; i < 60; i++) await f.service.use(session.auth, plan.requestId, input);
  const calls = f.counts().providerUses;
  await rejects(
    f.service.use(session.auth, plan.requestId, input),
    /too many credential uses/,
  );
  expect(f.counts().providerUses).toBe(calls);
  f.advance(60000);
  await f.service.use(session.auth, plan.requestId, input);
});

test("revoking a session removes its stored outputs without breaking request status", async () => {
  const f = await issuanceFixture();
  const session = await f.connect();
  const plan = await prepareApi(
    f,
    session,
    apiRequestSchema.parse({
      method: "GET",
      path: `/accounts/${fixtureIds.account}/d1/database`,
    }),
  );
  const service = withSend(f, async () =>
    Response.json({ result: { value: "synthetic-output" } }),
  );
  const result = await service.execute(session.auth, plan.requestId);
  const outputId = result.result?.outputId;
  if (!outputId) throw new Error("missing output");
  const beforeCleanup = await f.store.request(plan.requestId);
  await f.admin({ action: "revoke-session", sessionId: session.auth.hash });
  await service.reconcile();
  expect((await service.view(beforeCleanup)).result).toBeNull();
  expect(
    await f.env.DB.prepare("SELECT id FROM issuance_outputs WHERE id = ?")
      .bind(outputId)
      .first(),
  ).toBeNull();
  expect((await service.view(await f.store.request(plan.requestId))).result).toBeNull();
  await rejects(
    resolveSecrets(f.store, session.auth, {
      $vaultSecret: { outputId, pointer: "/result/value" },
    }),
    /not found/,
  );
});

test("oversized persisted output is rejected before a D1 value exceeds its limit", async () => {
  const f = await issuanceFixture();
  const session = await f.connect();
  const plan = fixturePlan();
  await f.service.prepare(session.auth, plan);
  await rejects(
    saveOutput(f.store, plan.requestId, { status: 200, body: "x".repeat(1500000) }),
    /output storage limit/,
  );
});

test("concurrent outputs cannot overfill the shared storage budget", async () => {
  const f = await issuanceFixture();
  const session = await f.connect();
  const plan = fixturePlan();
  await f.service.prepare(session.auth, plan);
  const encrypted = await f.crypto.encrypt(
    JSON.stringify({ status: 200, body: "x".repeat(1050000) }),
  );
  for (let i = 0; i < 47; i++)
    await f.env.DB.prepare("INSERT INTO issuance_outputs VALUES (?, ?, ?, ?)")
      .bind(crypto.randomUUID(), plan.requestId, encrypted, f.store.now())
      .run();
  const results = await Promise.allSettled([
    saveOutput(f.store, plan.requestId, { status: 200, body: "y".repeat(800000) }),
    saveOutput(f.store, plan.requestId, { status: 200, body: "z".repeat(800000) }),
  ]);
  expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
  const total = await f.env.DB.prepare(
    "SELECT sum(length(encrypted)) AS bytes FROM issuance_outputs",
  ).first<{ bytes: number }>();
  expect(total?.bytes).toBeLessThanOrEqual(67108864);
});

test("output retention expires old references and preserves eligible recent results", async () => {
  const f = await issuanceFixture();
  const session = await f.connect();
  await f.env.DB.prepare("UPDATE issuance_auth SET expires_at = ? WHERE hash = ?")
    .bind(f.store.now() + 172800000, session.auth.hash)
    .run();
  const plan = fixturePlan();
  await f.service.prepare(session.auth, plan);
  const old = await saveOutput(f.store, plan.requestId, {
    status: 200,
    body: { value: "old" },
  });
  f.advance(86400001);
  const recent = await saveOutput(f.store, plan.requestId, {
    status: 200,
    body: { value: "recent" },
  });
  await rejects(
    resolveSecrets(f.store, session.auth, {
      $vaultSecret: { outputId: old, pointer: "/value" },
    }),
    /no longer available/,
  );
  await f.service.reconcile();
  expect(
    await f.env.DB.prepare("SELECT id FROM issuance_outputs WHERE id = ?")
      .bind(old)
      .first(),
  ).toBeNull();
  expect(
    await resolveSecrets(f.store, session.auth, {
      $vaultSecret: { outputId: recent, pointer: "/value" },
    }),
  ).toBe("recent");
});
