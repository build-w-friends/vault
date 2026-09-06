import { rejects } from "node:assert/strict";
import { describe, expect, test } from "bun:test";
import { z } from "zod";
import { adminSchema } from "./contracts.ts";
import { authHeaders } from "../harness.ts";
import { issuanceFixture } from "./fixture.ts";
import {
  CloudflareDiscovery,
  cloudflareTokenTemplate,
  connectCloudflare,
  setupIssuance,
  type ConnectPrompts,
} from "./connect-cloudflare.ts";

const account = "a".repeat(32),
  zone = "b".repeat(32),
  tokenId = "c".repeat(32);
const token = "synthetic-secret-never-printed";
function provider(
  options: {
    denied?: boolean;
    inactive?: boolean;
    noManagement?: boolean;
    paginated?: boolean;
  } = {},
) {
  const calls: Request[] = [];
  const send: typeof fetch = Object.assign(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      calls.push(request);
      const url = new URL(request.url);
      expect(request.method).toBe("GET");
      expect(request.redirect).toBe("error");
      if (url.hostname === "api.github.com") {
        expect(request.headers.has("authorization")).toBe(false);
        return Response.json({
          id: url.pathname.endsWith("outsider") ? 202 : 101,
          login: url.pathname.split("/").at(-1),
          type: "User",
        });
      }
      expect(url.origin).toBe("https://api.cloudflare.com");
      expect(request.headers.get("authorization")).toBe(`Bearer ${token}`);
      if (options.denied) return Response.json({ error: token }, { status: 403 });
      if (url.pathname.endsWith("/accounts")) {
        const page = Number(url.searchParams.get("page"));
        return Response.json({
          success: true,
          result: [
            { id: page === 2 ? "d".repeat(32) : account, name: `Account ${page}` },
          ],
          result_info: { total_pages: options.paginated ? 2 : 1 },
        });
      }
      if (url.pathname.endsWith("/verify"))
        return Response.json({
          success: true,
          result: { id: tokenId, status: options.inactive ? "expired" : "active" },
        });
      if (url.pathname.endsWith(`/tokens/${tokenId}`))
        return Response.json({
          success: true,
          result: {
            policies: [
              {
                effect: "allow",
                permission_groups: [
                  {
                    name: options.noManagement
                      ? "Account API Tokens Read"
                      : "Account API Tokens Write",
                  },
                ],
              },
            ],
          },
        });
      if (url.pathname.endsWith("/zones")) {
        expect(url.searchParams.get("account.id")).toBe(account);
        return Response.json({
          success: true,
          result: [{ id: zone, name: "example.test" }],
          result_info: { total_pages: 1 },
        });
      }
      throw new Error(`Unexpected test request: ${url.pathname}`);
    },
    { preconnect: fetch.preconnect },
  );
  return { send, calls };
}
function prompts(answers: Array<string | boolean | string[]>) {
  const messages: string[] = [],
    opened: string[] = [];
  let cursor = 0;
  const say = (message: string) => {
    messages.push(message);
  };
  const next = (message: string) => {
    say(message);
    const value = answers[cursor++];
    if (value === undefined) throw new Error(`Missing test answer for ${message}`);
    return value;
  };
  const ui: ConnectPrompts = {
    say,
    intro: say,
    outro: say,
    cancel: say,
    ask: async (message, validate) => {
      const value = z.string().parse(next(message));
      expect(validate?.(value)).toBeUndefined();
      return value;
    },
    select: async (message, entries, label) => {
      const value = z.string().parse(next(message));
      const entry = entries.find((candidate) => label(candidate) === value);
      if (entry === undefined) throw new Error(`Unknown choice: ${value}`);
      return entry;
    },
    multiselect: async (message, entries, label) => {
      const values = next(message);
      if (!Array.isArray(values)) throw new Error("Expected checkbox answer");
      return entries.filter((entry) => values.includes(label(entry)));
    },
    confirm: async (message) => {
      const value = z.boolean().parse(next(message));
      return value;
    },
    secret: async (message) => {
      say(message);
      return token;
    },
    open: async (url) => {
      opened.push(url);
    },
  };
  return { ui, messages, opened };
}
const setup = {
  identityConfigured: true,
  tenants: [
    { id: "00000000-0000-4000-8000-000000000001", label: "Team", members: ["101"] },
  ],
};

describe("Cloudflare connection", () => {
  test("template opens account-token creation with documented permissions and no credential", () => {
    const url = new URL(cloudflareTokenTemplate());
    expect(url.origin).toBe("https://dash.cloudflare.com");
    expect(url.searchParams.get("to")).toBe("/:account/api-tokens");
    expect(url.searchParams.get("permissionGroupKeys")).toContain(
      '"key":"account_api_tokens","type":"edit"',
    );
    expect(url.href).not.toContain(token);
  });
  test("discovers accounts across pages and checks active account token permissions", async () => {
    const p = provider({ paginated: true });
    const discovery = new CloudflareDiscovery(token, p.send);
    expect(await discovery.accounts()).toHaveLength(2);
    expect(await discovery.verify(account)).toContain("Account API Tokens Write");
  });
  test.each([{ inactive: true }, { noManagement: true }])(
    "rejects unusable parent token %j",
    async (options) => {
      const p = provider(options);
      await rejects(new CloudflareDiscovery(token, p.send).verify(account));
    },
  );
  test("does not expose a credential echoed in a provider error", async () => {
    const p = provider({ denied: true });
    try {
      await new CloudflareDiscovery(token, p.send).accounts();
      throw new Error("expected failure");
    } catch (error) {
      expect(String(error)).toContain("HTTP 403");
      expect(String(error)).not.toContain(token);
    }
  });
  test("registers the discovered account and selected zone after review without printing the token", async () => {
    const f = await issuanceFixture();
    const p = provider(),
      terminal = prompts([
        "Team",
        true,
        ["example.test"],
        "Everyone in this team",
        "1 hour",
        "Production",
        true,
      ]);
    const saved: z.infer<typeof adminSchema>[] = [];
    await connectCloudflare({
      ui: terminal.ui,
      setup,
      send: p.send,
      save: async (record) => {
        saved.push(record);
        await f.admin(record);
      },
    });
    expect(saved).toHaveLength(1);
    const record = saved[0];
    if (record?.action !== "issuer") throw new Error("expected issuer");
    expect(record.policy).toEqual({
      accountId: account,
      zoneIds: [zone],
      maxTtlSeconds: 3600,
    });
    expect((await f.store.issuer(record.id)).parent_encrypted).not.toBe(token);
    expect(record.parentToken).toBe(token);
    expect(record.audience).toBe("tenant");
    expect(terminal.opened).toEqual([cloudflareTokenTemplate()]);
    expect(terminal.messages.join("\n")).not.toContain(token);
  });
  test("cancellation saves neither a new tenant, member nor issuer", async () => {
    const p = provider(),
      terminal = prompts([
        "Create a team",
        "New team",
        "example",
        false,
        [],
        "Everyone in this team",
        "1 hour",
        "Production",
        false,
      ]);
    const saved: z.infer<typeof adminSchema>[] = [];
    await connectCloudflare({
      ui: terminal.ui,
      setup,
      send: p.send,
      save: async (record) => {
        saved.push(record);
      },
    });
    expect(saved).toEqual([]);
  });
  test("first connection asks for a team name directly and allows account-only access", async () => {
    const p = provider();
    const terminal = prompts([
      "New team",
      "example",
      false,
      [],
      "Everyone in this team",
      "4 hours",
      "Production",
      true,
    ]);
    const saved: z.infer<typeof adminSchema>[] = [];
    await connectCloudflare({
      ui: terminal.ui,
      setup: { identityConfigured: true, tenants: [] },
      send: p.send,
      save: async (record) => {
        saved.push(record);
      },
    });
    expect(terminal.messages[0]).toBe("Name your team");
    expect(saved.map((record) => record.action)).toEqual(["tenant", "member", "issuer"]);
    const issuer = saved.at(-1);
    if (issuer?.action !== "issuer") throw new Error("expected issuer");
    expect(issuer.policy.zoneIds).toEqual([]);
    expect(issuer.policy.maxTtlSeconds).toBe(14400);
  });
  test("selected sharing resolves usernames and refuses nonmembers", async () => {
    const p = provider(),
      terminal = prompts(["Team", false, [], "Selected current members", "outsider"]);
    await rejects(
      connectCloudflare({
        ui: terminal.ui,
        setup,
        send: p.send,
        save: async () => {
          throw new Error("must not save");
        },
      }),
      new RegExp("not a member"),
    );
  });
  test("GitHub setup records credentials only after review and does not print the secret", async () => {
    const terminal = prompts([true, "example-client", true]),
      saved: z.infer<typeof adminSchema>[] = [];
    await setupIssuance({
      ui: terminal.ui,
      setup: { identityConfigured: false, tenants: [] },
      origin: "https://vault.example.com",
      save: async (record) => {
        saved.push(record);
      },
    });
    expect(saved[0]?.action).toBe("identity");
    expect(terminal.opened[0]).toContain(
      "https%3A%2F%2Fvault.example.com%2Fissuance%2Fauth%2Fcallback",
    );
    expect(terminal.messages.join("\n")).not.toContain(token);
  });
  test("setup discovery is operator-only and returns no credentials", async () => {
    const f = await issuanceFixture();
    expect((await f.request("/v1/issuance/setup")).status).toBe(401);
    const member = await f.connect();
    expect(
      (await f.request("/v1/issuance/setup", { headers: authHeaders(member.token) }))
        .status,
    ).toBe(401);
    const result = await f.request("/v1/issuance/setup", {
      headers: authHeaders(f.operator),
    });
    const body = await result.text();
    expect(result.status).toBe(200);
    expect(body).toContain('"identityConfigured":true');
    expect(body).not.toContain("synthetic-parent");
    expect(body).not.toContain("clientSecret");
  });
});
