import { describe, expect, spyOn, test } from "bun:test";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { z } from "zod";
import { PassThrough } from "node:stream";
import { serveStdio, StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { apiRequestSchema } from "./contracts.ts";
import { IssuanceService } from "./service.ts";
import { authHeaders } from "../harness.ts";
import { runIssuanceCli } from "./cli.ts";
import { createIssuanceMcp, IssuanceClient } from "./mcp.ts";
import { issuanceFixture, fixtureIds, fixturePlan } from "./fixture.ts";

async function expectRejected<T>(operation: Promise<T>, message: string) {
  const failure = await operation.then(() => null, z.instanceof(Error).parse);
  if (!(failure instanceof Error)) throw new Error("expected the operation to reject");
  expect(failure.message).toContain(message);
}

type Fixture = Awaited<ReturnType<typeof issuanceFixture>>;
type Session = Awaited<ReturnType<Fixture["connect"]>>;
async function prepare(f: Fixture, session: Session) {
  const plan = fixturePlan();
  const response = await f.request("/issuance/requests", {
    method: "POST",
    headers: authHeaders(session.token, "application/json"),
    body: JSON.stringify(plan),
  });
  expect(response.status).toBe(201);
  return plan;
}
async function approve(
  f: Fixture,
  session: Session,
  requestId: string,
  decision = "approve",
) {
  const path = `/issuance/approve/${requestId}`;
  const csrf = await f.csrf(path, session.cookie);
  return f.request(path, {
    method: "POST",
    headers: { Cookie: session.cookie, Origin: "https://vault.test" },
    body: new URLSearchParams({ csrf, decision }),
  });
}

describe("approved issuer credentials", () => {
  test("browser-approved connection, discover, approve, issue once, and use without revealing either secret", async () => {
    const f = await issuanceFixture();
    const session = await f.connect();
    const list = await f.request("/issuance/issuers", {
      headers: authHeaders(session.token),
    });
    const text = await list.text();
    expect(text).toContain("approvalRequired");
    expect(text).not.toContain("synthetic-parent");
    const plan = await prepare(f, session);
    expect(f.counts().providerPosts).toBe(0);
    expect((await approve(f, session, plan.requestId)).status).toBe(303);
    const path = `/issuance/requests/${plan.requestId}/execute`;
    const issued = await f.request(path, {
      method: "POST",
      headers: authHeaders(session.token),
    });
    expect(issued.status).toBe(200);
    expect(await issued.text()).not.toContain("synthetic-child");
    expect(
      (await f.request(path, { method: "POST", headers: authHeaders(session.token) }))
        .status,
    ).toBe(200);
    expect(f.counts().providerPosts).toBe(1);
    const used = await f.request(`/issuance/requests/${plan.requestId}/use`, {
      method: "POST",
      headers: authHeaders(session.token, "application/json"),
      body: JSON.stringify(
        apiRequestSchema.parse({
          method: "GET",
          path: `/zones/${fixtureIds.zone}/dns_records`,
        }),
      ),
    });
    expect(used.status).toBe(200);
    expect(await used.text()).toContain("example.test");
    const parent = await f.env.DB.prepare(
      "SELECT parent_encrypted FROM issuance_issuers",
    ).first<{ parent_encrypted: string }>();
    expect(parent?.parent_encrypted).not.toContain("synthetic-parent");
    const child = await f.env.DB.prepare(
      "SELECT token_encrypted FROM issuance_requests",
    ).first<{ token_encrypted: string }>();
    expect(child?.token_encrypted).not.toContain("synthetic-child");
    const events = (
      await f.env.DB.prepare(
        "SELECT action FROM issuance_events WHERE request_id = ? ORDER BY created_at, rowid",
      )
        .bind(plan.requestId)
        .all<{ action: string }>()
    ).results.map((event) => event.action);
    expect(events).toEqual([
      "prepared",
      "approved",
      "executing",
      "issued",
      `use:GET:/zones/${fixtureIds.zone}/dns_records`,
    ]);
  });
  test("agent bearer and operator key cannot approve; CSRF, wrong user and missing approval all deny", async () => {
    const f = await issuanceFixture();
    const session = await f.connect();
    const plan = await prepare(f, session);
    const path = `/issuance/approve/${plan.requestId}`;
    for (const key of [session.token, f.operator]) {
      expect(
        (
          await f.request(path, {
            method: "POST",
            headers: authHeaders(key, "application/json"),
            body: JSON.stringify({ decision: "approve" }),
          })
        ).status,
      ).toBe(401);
    }
    expect(
      (
        await f.request(path, {
          method: "POST",
          headers: { Cookie: session.cookie, Origin: "https://evil.test" },
          body: new URLSearchParams({
            csrf: await f.csrf(path, session.cookie),
            decision: "approve",
          }),
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await f.request(path, {
          method: "POST",
          headers: { Cookie: session.cookie, Origin: "https://vault.test" },
          body: new URLSearchParams({ csrf: "forged", decision: "approve" }),
        })
      ).status,
    ).toBe(403);
    const other = await f.login("202");
    expect((await f.request(path, { headers: { Cookie: other } })).status).toBe(404);
    expect(
      (
        await f.request(`/issuance/requests/${plan.requestId}/execute`, {
          method: "POST",
          headers: authHeaders(session.token),
        })
      ).status,
    ).toBe(409);
    expect(f.counts().providerPosts).toBe(0);
  });
  test("GitHub state requires matching browser and cannot be replayed", async () => {
    const f = await issuanceFixture();
    const login = await f.request(
      `/issuance/auth/login?returnTo=${encodeURIComponent(`/issuance/connect/${crypto.randomUUID()}`)}`,
    );
    const location = login.headers.get("location");
    expect(location).toBeTruthy();
    const state = new URL(location ?? "https://invalid.test").searchParams.get("state");
    const path = `/issuance/auth/callback?state=${state}&code=101`;
    expect((await f.request(path)).status).toBe(401);
    expect(
      (await f.request(path, { headers: { Cookie: `__Host-vault-login=${state}` } }))
        .status,
    ).toBe(302);
    expect(
      (await f.request(path, { headers: { Cookie: `__Host-vault-login=${state}` } }))
        .status,
    ).toBe(401);
    expect(
      (await f.request("/issuance/auth/login?returnTo=https://evil.test")).status,
    ).toBe(400);
  });
  test("issuer audience filters current tenant members and never adds membership", async () => {
    const f = await issuanceFixture();
    await f.admin({
      action: "member",
      tenantId: fixtureIds.tenant,
      subject: "202",
      operation: "add",
    });
    const first = await f.connect();
    const second = await f.connect("202");
    const restricted = crypto.randomUUID();
    await f.admin({
      action: "issuer",
      id: restricted,
      tenantId: fixtureIds.tenant,
      label: "Private issuer",
      policy: {
        accountId: fixtureIds.account,
        zoneIds: [fixtureIds.zone],
        maxTtlSeconds: 600,
      },
      parentToken: "synthetic-private",
      audience: ["101"],
    });
    expect((await f.store.issuers(first.auth)).map((item) => item.id)).toContain(
      restricted,
    );
    expect((await f.store.issuers(second.auth)).map((item) => item.id)).not.toContain(
      restricted,
    );
    await expectRejected(
      f.service.prepare(second.auth, { ...fixturePlan(), issuerId: restricted }),
      "not available",
    );
    await f.admin({
      action: "member",
      tenantId: fixtureIds.tenant,
      subject: "101",
      operation: "remove",
    });
    expect(
      (await f.request("/issuance/issuers", { headers: authHeaders(first.token) }))
        .status,
    ).toBe(403);
  });
  test("scope escalation and changing an existing request are rejected", async () => {
    const f = await issuanceFixture();
    const session = await f.connect();
    const plan = await prepare(f, session);
    await expectRejected(
      f.service.prepare(session.auth, { ...plan, ttlSeconds: 600 }),
      "another plan",
    );
    await expectRejected(
      f.service.prepare(session.auth, {
        ...fixturePlan(),
        operation: {
          kind: "api-request",
          request: apiRequestSchema.parse({
            method: "POST",
            path: `/accounts/${"e".repeat(32)}/d1/database`,
            body: { kind: "json", value: { name: "app" } },
          }),
        },
      }),
      "exceeds",
    );
    const escaped = fixturePlan();
    escaped.operation.policies = [
      {
        effect: "allow",
        permission_groups: [{ id: fixtureIds.permission }],
        resources: { [`com.cloudflare.api.account.zone.${"e".repeat(32)}`]: "*" },
      },
    ];
    await expectRejected(f.service.prepare(session.auth, escaped), "exceeds");
    await expectRejected(
      f.service.prepare(session.auth, { ...fixturePlan(), ttlSeconds: 86400 }),
      "exceeds",
    );
    expect(f.counts().providerPosts).toBe(0);
  });
  test("nested all-zone grants cannot escape the issuer's listed zones", async () => {
    const f = await issuanceFixture();
    const session = await f.connect();
    const plan = fixturePlan();
    await expectRejected(
      f.service.prepare(session.auth, {
        ...plan,
        operation: {
          kind: "create-token",
          policies: [
            {
              effect: "allow",
              permission_groups: [{ id: fixtureIds.permission }],
              resources: {
                [`com.cloudflare.api.account.${fixtureIds.account}`]: {
                  "com.cloudflare.api.account.zone.*": "*",
                },
              },
            },
          ],
        },
      }),
      "exceeds",
    );
    expect(f.counts().providerPosts).toBe(0);
  });
  test("admitted token creation can finish after the approval deadline", async () => {
    const f = await issuanceFixture();
    const session = await f.connect();
    const plan = await prepare(f, session);
    await approve(f, session, plan.requestId);
    f.advance(599000);
    f.onCreate(async () => {
      f.advance(2000);
    });
    const result = await f.service.execute(session.auth, plan.requestId);
    expect(result.status).toBe("issued");
    expect(result.credentialRef).toBe(plan.requestId);
    expect(f.tokens.size).toBe(1);
    expect(f.revoked).toHaveLength(0);
  });
  test.each(["session", "issuer", "token expiry"] as const)(
    "%s revocation during creation still prevents credential delivery",
    async (boundary) => {
      const f = await issuanceFixture();
      const session = await f.connect();
      const plan = await prepare(f, session);
      await approve(f, session, plan.requestId);
      f.onCreate(async () => {
        if (boundary === "session")
          await f.admin({ action: "revoke-session", sessionId: session.auth.hash });
        else if (boundary === "issuer")
          await f.admin({ action: "revoke-issuer", issuerId: fixtureIds.issuer });
        else f.advance(3600001);
      });
      const result = await f.service.execute(session.auth, plan.requestId);
      expect(result.credentialRef).toBeNull();
      if (boundary === "token expiry") {
        expect(result.status).toBe("expired");
        expect((await f.store.request(plan.requestId)).token_encrypted).toBeNull();
      } else {
        expect(f.revoked).toHaveLength(1);
        expect(f.tokens.size).toBe(0);
      }
    },
  );
  test.each([400, 403, 503])(
    "HTTP %s token failures retain safe evidence",
    async (status) => {
      const f = await issuanceFixture();
      const session = await f.connect();
      const plan = await prepare(f, session);
      await approve(f, session, plan.requestId);
      const service = new IssuanceService(f.store, async () =>
        Response.json(
          {
            success: false,
            result: { value: "synthetic-provider-secret" },
            errors: [
              {
                code: 1001,
                message: "Policy rejected: synthetic-parent-never-export",
              },
            ],
          },
          { status },
        ),
      );
      const outcome = status < 500 ? "rejected" : "unknown";
      await expectRejected(service.execute(session.auth, plan.requestId), outcome);
      const result = await service.view(await f.store.request(plan.requestId));
      expect(result.status).toBe(status < 500 ? "failed" : "unknown");
      expect(result.result?.status).toBe(status);
      expect(result.result?.body).toEqual({
        outcome,
        reason: `Cloudflare rejected the operation (HTTP ${status}): 1001: Policy rejected: [REDACTED]`,
      });
      expect(JSON.stringify(result)).not.toContain("synthetic-parent");
      expect(JSON.stringify(result)).not.toContain("synthetic-provider-secret");
    },
  );
  test("parallel calls can consume the approval only once", async () => {
    const f = await issuanceFixture();
    const session = await f.connect();
    const plan = await prepare(f, session);
    await approve(f, session, plan.requestId);
    const results = await Promise.allSettled([
      f.service.execute(session.auth, plan.requestId),
      f.service.execute(session.auth, plan.requestId),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(f.counts().providerPosts).toBe(1);
  });
  test("declined and expired approvals cannot create credentials", async () => {
    const f = await issuanceFixture();
    const session = await f.connect();
    const declined = await prepare(f, session);
    await approve(f, session, declined.requestId, "decline");
    await expectRejected(f.service.execute(session.auth, declined.requestId), "approval");
    const expired = await prepare(f, session);
    await approve(f, session, expired.requestId);
    f.advance(600001);
    await expectRejected(f.service.execute(session.auth, expired.requestId), "approval");
    expect(f.counts().providerPosts).toBe(0);
  });
  test.each(["lost", "malformed"] as const)(
    "%s provider response is reconciled without another creation",
    async (behavior) => {
      const f = await issuanceFixture();
      const session = await f.connect();
      const plan = await prepare(f, session);
      await approve(f, session, plan.requestId);
      f.setBehavior(behavior);
      await expectRejected(f.service.execute(session.auth, plan.requestId), "unknown");
      expect((await f.store.request(plan.requestId)).status).toBe("unknown");
      await expectRejected(f.service.execute(session.auth, plan.requestId), "approval");
      await f.service.reconcile();
      expect(f.tokens.size).toBe(0);
      expect(f.counts().providerPosts).toBe(1);
      expect((await f.store.request(plan.requestId)).status).toBe("unknown");
      f.advance(3600001);
      await f.service.reconcile();
      expect((await f.store.request(plan.requestId)).status).toBe("expired");
    },
  );
  test("membership removed during external creation revokes the returned credential", async () => {
    const f = await issuanceFixture();
    const session = await f.connect();
    const plan = await prepare(f, session);
    await approve(f, session, plan.requestId);
    f.onCreate(() =>
      f.admin({
        action: "member",
        tenantId: fixtureIds.tenant,
        subject: "101",
        operation: "remove",
      }),
    );
    const result = await f.service.execute(session.auth, plan.requestId);
    expect(result.credentialRef).toBeNull();
    expect(f.tokens.size).toBe(0);
    expect((await f.store.request(plan.requestId)).status).toBe("revoked");
  });
  test("scope mismatch revokes; child use rejects token management and stops immediately on session revocation", async () => {
    const f = await issuanceFixture();
    const session = await f.connect();
    const plan = await prepare(f, session);
    await approve(f, session, plan.requestId);
    await f.service.execute(session.auth, plan.requestId);
    await expectRejected(
      f.service.use(
        session.auth,
        plan.requestId,
        apiRequestSchema.parse({
          method: "POST",
          path: `/accounts/${fixtureIds.account}/tokens`,
          body: { kind: "json", value: {} },
        }),
      ),
      "new parent-token approval",
    );
    await f.admin({ action: "revoke-session", sessionId: session.auth.hash });
    await expectRejected(
      f.service.use(
        session.auth,
        plan.requestId,
        apiRequestSchema.parse({
          method: "GET",
          path: `/zones/${fixtureIds.zone}/dns_records`,
        }),
      ),
      "unavailable",
    );
    await f.service.reconcile();
    expect(f.tokens.size).toBe(0);
    const next = await f.connect();
    const mismatch = await prepare(f, next);
    await approve(f, next, mismatch.requestId);
    f.setBehavior("mismatch");
    await expectRejected(f.service.execute(next.auth, mismatch.requestId), "rejected");
    expect(f.tokens.size).toBe(0);
    expect((await f.store.request(mismatch.requestId)).status).toBe("failed");
    const evidence = await f.service.view(await f.store.request(mismatch.requestId));
    expect(evidence.result?.body).toEqual({
      outcome: "rejected",
      reason: "Cloudflare returned a different token scope; the token was revoked",
    });
  });
  test("MCP tools discover and prepare using the authenticated session, with no approve tool", async () => {
    const f = await issuanceFixture();
    const session = await f.connect();
    const transport = async (input: RequestInfo | URL, init?: RequestInit) =>
      f.app.fetch(new Request(input, init), f.env);
    const client = new IssuanceClient("https://vault.test", session.token, transport);
    const handler = createMcpHandler(() => createIssuanceMcp(client));
    const rpc = async (method: string, params: z.infer<ReturnType<typeof z.json>>) => {
      const response = await handler.fetch(
        new Request("https://local.test/mcp", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25",
          },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        }),
      );
      const body = await response.text();
      const message =
        body.startsWith("event:") || body.startsWith("data:")
          ? body
              .split("\n")
              .find((line) => line.startsWith("data: "))
              ?.slice(6)
          : body;
      return z.object({ result: z.unknown() }).parse(JSON.parse(message ?? "{}")).result;
    };
    const listed = z
      .object({ tools: z.array(z.object({ name: z.string() })) })
      .parse(await rpc("tools/list", {}));
    expect(listed.tools.map((tool) => tool.name)).toContain("request_approval");
    expect(listed.tools.map((tool) => tool.name)).not.toContain("approve");
    const discovered = JSON.stringify(
      await rpc("tools/call", { name: "list_issuers", arguments: {} }),
    );
    expect(discovered).toContain("Test Cloudflare issuer");
    expect(discovered).not.toContain("synthetic-parent");
    const plan = fixturePlan();
    expect(
      JSON.stringify(
        await rpc("tools/call", { name: "prepare_request", arguments: plan }),
      ),
    ).toContain("prepared");
    const approval = JSON.stringify(
      await rpc("tools/call", {
        name: "request_approval",
        arguments: { requestId: plan.requestId },
      }),
    );
    expect(approval).toContain(`/issuance/approve/${plan.requestId}`);
    expect(f.counts().providerPosts).toBe(0);
    const modern = await handler.fetch(
      new Request("https://local.test/mcp", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
          "MCP-Protocol-Version": "2026-07-28",
          "Mcp-Method": "tools/call",
          "Mcp-Name": "request_approval",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: {
            _meta: {
              "io.modelcontextprotocol/protocolVersion": "2026-07-28",
              "io.modelcontextprotocol/clientInfo": { name: "acceptance", version: "1" },
              "io.modelcontextprotocol/clientCapabilities": { elicitation: { url: {} } },
            },
            name: "request_approval",
            arguments: { requestId: plan.requestId },
          },
        }),
      }),
    );
    const modernBody = await modern.text();
    expect(modernBody).toContain("input_required");
    expect(modernBody).toContain("inputRequests");
    expect(modernBody).toContain(`/issuance/approve/${plan.requestId}`);
  });
  test("the local stdio MCP transport completes a handshake and returns tenant issuers", async () => {
    const f = await issuanceFixture();
    const session = await f.connect();
    const send = async (input: RequestInfo | URL, init?: RequestInit) =>
      f.app.fetch(new Request(input, init), f.env);
    const input = new PassThrough();
    const output = new PassThrough();
    const transport = new StdioServerTransport(input, output);
    const handle = serveStdio(
      () =>
        createIssuanceMcp(new IssuanceClient("https://vault.test", session.token, send)),
      { transport },
    );
    const rpc = (message: string) =>
      new Promise<string>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error("stdio response timed out"));
        }, 3000);
        output.once("data", (data: Buffer) => {
          clearTimeout(timeout);
          resolve(data.toString());
        });
        input.write(message + "\n");
      });
    try {
      const initialized = await rpc(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-11-25",
            capabilities: {},
            clientInfo: { name: "acceptance", version: "1" },
          },
        }),
      );
      expect(initialized).toContain("vault-issuance");
      input.write(
        JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n",
      );
      const listed = await rpc(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "list_issuers", arguments: {} },
        }),
      );
      expect(listed).toContain("Test Cloudflare issuer");
      expect(listed).not.toContain("synthetic-parent");
    } finally {
      await handle.close();
    }
  });
  test("operator inspection exposes evidence but never credentials", async () => {
    const f = await issuanceFixture();
    const session = await f.connect();
    const plan = await prepare(f, session);
    const path = `/v1/issuance/requests/${plan.requestId}`;
    expect((await f.request(path, { headers: authHeaders(session.token) })).status).toBe(
      401,
    );
    const inspected = await f.request(path, { headers: authHeaders(f.operator) });
    expect(inspected.status).toBe(200);
    const body = await inspected.text();
    expect(body).toContain('"subject":"101"');
    expect(body).toContain('"events":');
    expect(body).not.toContain("synthetic-parent");
  });
  test("old broker header-return endpoint is absent", async () => {
    const f = await issuanceFixture();
    expect(
      (
        await f.request("/v1/broker/apply", {
          method: "POST",
          headers: authHeaders(f.operator, "application/json"),
          body: "{}",
        })
      ).status,
    ).toBe(404);
  });
});

describe("issuance login polling", () => {
  const deviceId = "00000000-0000-4000-8000-0000000000aa";
  const io = { log: () => {}, error: () => {} };
  /** Answers the device request, then each poll with the next scripted reply. */
  function vault(polls: Array<() => Response>) {
    let calls = 0;
    const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(
      Object.assign(
        async (input: RequestInfo | URL) => {
          const url = new URL(input instanceof Request ? input.url : input);
          if (url.pathname === "/issuance/devices")
            return Response.json({
              deviceId,
              verificationUrl: `https://vault.test/issuance/connect/${deviceId}`,
            });
          const reply = polls[Math.min(calls++, polls.length - 1)];
          if (!reply) throw new Error("no scripted poll reply");
          return reply();
        },
        { preconnect: fetch.preconnect },
      ),
    );
    const sleepSpy = spyOn(Bun, "sleep").mockResolvedValue(undefined);
    return {
      polls: () => calls,
      [Symbol.dispose]: () => {
        fetchSpy.mockRestore();
        sleepSpy.mockRestore();
      },
    };
  }
  const lostReply = () => {
    throw new TypeError("lost reply");
  };

  test("a lost reply or busy Vault is retried; a rejected verifier is not", async () => {
    using server = vault([
      lostReply,
      () => new Response(null, { status: 503 }),
      () => Response.json({ error: "invalid connection verifier" }, { status: 401 }),
    ]);
    await expectRejected(
      runIssuanceCli(["login"], "https://vault.test", io),
      "invalid connection verifier",
    );
    expect(server.polls()).toBe(3);
  });

  test("temporary failures stop at the ten-minute expiry", async () => {
    using server = vault([lostReply]);
    let clock = 0;
    const now = spyOn(Date, "now").mockImplementation(() => (clock += 60000));
    try {
      await expectRejected(
        runIssuanceCli(["login"], "https://vault.test", io),
        "expired",
      );
    } finally {
      now.mockRestore();
    }
    expect(server.polls()).toBeGreaterThan(1);
  });
});
