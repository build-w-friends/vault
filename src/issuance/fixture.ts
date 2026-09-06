import { z } from "zod";
import { createTestVault, bootstrapUser, authHeaders } from "../harness.ts";
import { adminSchema } from "./contracts.ts";
import { IssuanceStore } from "./store.ts";
import { IssuanceService } from "./service.ts";
import { CloudflareIssuer } from "./cloudflare.ts";

export const fixtureIds = {
  tenant: "00000000-0000-4000-8000-000000000001",
  issuer: "00000000-0000-4000-8000-000000000002",
  account: "a".repeat(32),
  zone: "b".repeat(32),
  permission: "c".repeat(32),
};
export async function issuanceFixture() {
  let clock = Date.now();
  let providerPosts = 0;
  let providerUses = 0;
  let behavior: "ok" | "lost" | "malformed" | "mismatch" = "ok";
  let onCreate: (() => Promise<void>) | undefined;
  const revoked: string[] = [];
  const tokens = new Map<
    string,
    {
      id: string;
      name: string;
      expires_on: string;
      policies: unknown;
      status: string;
      value: string;
    }
  >();
  const send: typeof fetch = Object.assign(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      if (request.redirect === "error")
        throw new TypeError("Workers fetch supports only manual and follow redirects");
      const url = new URL(request.url);
      if (url.href === "https://github.com/login/oauth/access_token") {
        const body = new URLSearchParams(await request.text());
        if (!body.get("code_verifier")) throw new Error("missing PKCE verifier");
        return Response.json({ access_token: `github-${body.get("code")}` });
      }
      if (url.href === "https://api.github.com/user") {
        const subject = request.headers.get("authorization")?.split("github-")[1];
        return Response.json({ id: Number(subject), login: `user-${subject}` });
      }
      if (url.pathname.endsWith("/tokens/permission_groups"))
        return Response.json({
          success: true,
          result: [
            {
              id: fixtureIds.permission,
              name: "DNS Read",
              scopes: ["com.cloudflare.api.account.zone"],
            },
            {
              id: "d".repeat(32),
              name: "DNS Write",
              scopes: ["com.cloudflare.api.account.zone"],
            },
            {
              id: "e".repeat(32),
              name: "Workers AI Read",
              scopes: ["com.cloudflare.api.account"],
            },
            {
              id: "f".repeat(32),
              name: "AI Gateway Run",
              scopes: ["com.cloudflare.api.account"],
            },
          ],
        });
      if (url.pathname.endsWith("/tokens") && request.method === "POST") {
        providerPosts++;
        const body = z
          .object({ name: z.string(), expires_on: z.string(), policies: z.unknown() })
          .parse(await request.json());
        const token = {
          ...body,
          id: providerPosts.toString(16).padStart(32, "0"),
          status: "active",
          value: `synthetic-child-${providerPosts}`,
        };
        tokens.set(token.id, token);
        await onCreate?.();
        if (behavior === "lost") throw new Error("synthetic lost reply");
        if (behavior === "malformed") return Response.json({ unexpected: true });
        if (behavior === "mismatch")
          return Response.json({ success: true, result: { ...token, policies: [] } });
        return Response.json({ success: true, result: token });
      }
      if (url.pathname.endsWith("/tokens") && request.method === "GET")
        return Response.json({ success: true, result: [...tokens.values()] });
      if (request.method === "DELETE") {
        const id = url.pathname.split("/").at(-1) ?? "";
        revoked.push(id);
        tokens.delete(id);
        return Response.json({ success: true, result: { id } });
      }
      if (url.pathname.endsWith("/d1/database") && request.method === "POST") {
        if (
          request.headers.get("authorization") !== "Bearer synthetic-parent-never-export"
        )
          throw new Error("incorrect parent token injection");
        return Response.json({
          success: true,
          result: { uuid: "synthetic-database-id", name: "app-data" },
        });
      }
      if (url.pathname.endsWith("/dns_records")) {
        providerUses++;
        if (request.headers.get("authorization") !== "Bearer synthetic-child-1")
          throw new Error("incorrect child token injection");
        return Response.json({ success: true, result: [{ name: "example.test" }] });
      }
      if (
        url.pathname.includes("/ai/") ||
        url.pathname.endsWith("/compat/chat/completions")
      ) {
        const header =
          url.hostname === "gateway.ai.cloudflare.com"
            ? "cf-aig-authorization"
            : "authorization";
        if (request.headers.get(header) !== "Bearer synthetic-child-1")
          throw new Error("incorrect AI token injection");
        providerUses++;
        const body = await request.json();
        return Response.json({
          result: "synthetic-inference",
          endpoint: url.pathname,
          body,
        });
      }
      throw new Error("unexpected synthetic provider request");
    },
    { preconnect: fetch.preconnect },
  );
  const vault = await createTestVault({ issuanceFetch: send, now: () => clock });
  const operator = await bootstrapUser(vault.app, vault.env);
  const store = new IssuanceStore(vault.env.DB, vault.crypto, () => clock);
  const service = new IssuanceService(store, new CloudflareIssuer(send), send);
  const request = (path: string, init?: RequestInit) =>
    vault.app.request(`https://vault.test${path}`, init, vault.env);
  async function admin(body: z.infer<typeof adminSchema>) {
    const response = await request("/v1/issuance/admin", {
      method: "POST",
      headers: authHeaders(operator, "application/json"),
      body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`fixture configuration failed: ${response.status}`);
  }
  await admin({
    action: "identity",
    config: {
      origin: "https://vault.test",
      clientId: "synthetic-client",
      clientSecret: "synthetic-github-secret",
    },
  });
  await admin({ action: "tenant", id: fixtureIds.tenant, label: "Test tenant" });
  await admin({
    action: "member",
    tenantId: fixtureIds.tenant,
    subject: "101",
    operation: "add",
  });
  await admin({
    action: "issuer",
    id: fixtureIds.issuer,
    tenantId: fixtureIds.tenant,
    label: "Test Cloudflare issuer",
    policy: {
      accountId: fixtureIds.account,
      zoneIds: [fixtureIds.zone],
      maxTtlSeconds: 3600,
    },
    parentToken: "synthetic-parent-never-export",
    audience: "tenant",
  });
  async function login(
    subject = "101",
    returnTo = `/issuance/connect/${crypto.randomUUID()}`,
  ) {
    const startedLogin = await request(
      `/issuance/auth/login?returnTo=${encodeURIComponent(returnTo)}`,
    );
    const location = startedLogin.headers.get("location");
    if (!location) throw new Error("missing GitHub redirect");
    const state = new URL(location).searchParams.get("state");
    const callback = await request(
      `/issuance/auth/callback?state=${state}&code=${subject}`,
      { headers: { Cookie: `__Host-vault-login=${state}` } },
    );
    const cookie = callback.headers
      .getSetCookie()
      .find((value) => value.startsWith("__Host-vault-approval="))
      ?.split(";")[0];
    if (!cookie) throw new Error(`fixture browser login failed: ${callback.status}`);
    return cookie;
  }
  async function csrf(path: string, cookie: string) {
    const response = await request(path, { headers: { Cookie: cookie } });
    const text = await response.text();
    const token = /name="csrf" value="([^"]+)"/.exec(text)?.[1];
    if (!token) throw new Error(`fixture approval form absent: ${response.status}`);
    return token;
  }
  async function connect(subject = "101") {
    const verifier = "d".repeat(64);
    const response = await request("/issuance/devices", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challenge: await vault.crypto.sha256(verifier),
        label: "Fixture MCP",
      }),
    });
    const { deviceId } = z.object({ deviceId: z.string() }).parse(await response.json());
    const cookie = await login(subject, `/issuance/connect/${deviceId}`);
    const token = await csrf(`/issuance/connect/${deviceId}`, cookie);
    const approved = await request(`/issuance/connect/${deviceId}`, {
      method: "POST",
      headers: { Cookie: cookie, Origin: "https://vault.test" },
      body: new URLSearchParams({ csrf: token, tenantId: fixtureIds.tenant }),
    });
    if (approved.status !== 303)
      throw new Error(`fixture connection approval failed: ${approved.status}`);
    const polled = await request("/issuance/devices/poll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ deviceId, verifier }),
    });
    const session = z.object({ token: z.string() }).parse(await polled.json());
    return {
      cookie,
      token: session.token,
      auth: await store.auth(session.token, "agent"),
    };
  }
  return {
    ...vault,
    request,
    store,
    service,
    admin,
    login,
    csrf,
    connect,
    operator,
    send,
    tokens,
    revoked,
    advance: (ms: number) => {
      clock += ms;
    },
    setBehavior: (value: typeof behavior) => {
      behavior = value;
    },
    onCreate: (callback: () => Promise<void>) => {
      onCreate = callback;
    },
    counts: () => ({ providerPosts, providerUses }),
  };
}
export const fixturePlan = () => ({
  requestId: crypto.randomUUID(),
  issuerId: fixtureIds.issuer,
  operation: {
    kind: "create-token" as const,
    policies: [
      {
        effect: "allow" as const,
        permission_groups: [{ id: fixtureIds.permission }],
        resources: {
          [`com.cloudflare.api.account.zone.${fixtureIds.zone}`]: "*" as const,
        },
      },
    ],
  },
  ttlSeconds: 3600,
  purpose: "Inspect application DNS",
  consumer: "Current local AI task",
});
