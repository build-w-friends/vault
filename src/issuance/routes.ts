import { Hono, type Context } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { html } from "hono/html";
import { bodyLimit } from "hono/body-limit";
import { z } from "zod";
import type { VaultCrypto } from "../crypto.ts";
import { timingSafeStringEqual } from "../crypto.ts";
import { PolicyError } from "../policy.ts";
import { CloudflareIssuer } from "./cloudflare.ts";
import {
  id,
  loginStateSchema,
  prepareSchema,
  apiRequestSchema,
  type Auth,
} from "./contracts.ts";
import { IssuanceStore } from "./store.ts";
import { IssuanceService } from "./service.ts";

type Environment = {
  Bindings: { DB: D1Database };
  Variables: { issuance: IssuanceStore };
};
const browserCookie = "__Host-vault-approval";
const stateCookie = "__Host-vault-login";
const cookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "Lax",
  path: "/",
} as const;
const nonce = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
const localPath = z.string().regex(/^\/issuance\/(?:connect|approve)\/[a-f0-9-]{36}$/);

const deviceSchema = z
  .object({
    challenge: z.string().regex(/^[a-f0-9]{64}$/),
    label: z.string().trim().min(1).max(120),
  })
  .strict();
const pollSchema = z
  .object({ deviceId: id, verifier: z.string().regex(/^[a-f0-9]{64}$/) })
  .strict();
type Device = {
  id: string;
  challenge: string;
  label: string;
  expires_at: number;
  created_at: number;
  subject: string | null;
  tenant_id: string | null;
};

function page(title: string, body: ReturnType<typeof html>) {
  return html`<!doctype html>
    <html lang="en">
      <meta charset="utf-8" /><meta
        name="viewport"
        content="width=device-width,initial-scale=1"
      /><title>${title} · Vault</title
      ><style>
        :root {
          font-family: system-ui;
          color: #e8eaf0;
          background: #11151c;
          color-scheme: dark;
        }
        body {
          max-width: 680px;
          margin: 8vh auto;
          padding: 24px;
        }
        h1 {
          font-size: 28px;
        }
        p,
        dd {
          line-height: 1.6;
        }
        dt {
          color: #aeb9ce;
          margin-top: 18px;
        }
        dd {
          margin: 4px 0;
          overflow-wrap: anywhere;
        }
        button,
        a,
        select {
          font: inherit;
        }
        button {
          padding: 12px 20px;
          margin: 16px 8px 0 0;
          border-radius: 8px;
          border: 1px solid #577185;
          cursor: pointer;
        }
        button[value="approve"] {
          background: #135c45;
        }
        a {
          color: #9bc9ff;
        }
        pre {
          white-space: pre-wrap;
          overflow-wrap: anywhere;
        }
        code {
          overflow-wrap: anywhere;
        }
        .notice {
          padding: 16px;
          background: #202b3a;
          border-radius: 8px;
        }
        label {
          display: block;
          margin-top: 16px;
        }
        select {
          padding: 8px;
          width: 100%;
        }
      </style>
      <main>
        <p>Vault</p>
        <h1>${title}</h1>
        ${body}
      </main>
    </html>`;
}

export function issuanceRoutes(
  vaultCrypto: VaultCrypto,
  send: typeof fetch = fetch,
  now = () => Date.now(),
) {
  const app = new Hono<Environment>();
  app.use("*", bodyLimit({ maxSize: 1000000 }));
  app.use("*", async (c, next) => {
    c.set("issuance", new IssuanceStore(c.env.DB, vaultCrypto, now));
    c.header("Cache-Control", "no-store");
    c.header("Referrer-Policy", "same-origin");
    c.header(
      "Content-Security-Policy",
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    );
    c.header("X-Content-Type-Options", "nosniff");
    if (Number(c.req.header("Content-Length") ?? "0") > 1000000)
      throw new PolicyError(413, "request is too large");
    if (
      c.req.path === "/issuance/auth/login" ||
      c.req.path === "/issuance/devices" ||
      c.req.path === "/issuance/devices/poll"
    ) {
      const key = await vaultCrypto.lookupHash(
        `${c.req.path}:${c.req.header("CF-Connecting-IP") ?? "local"}`,
      );
      const limit = c.req.path.endsWith("/poll") ? 120 : 60;
      const admitted = await c.env.DB.prepare(
        "INSERT INTO issuance_limits VALUES (?, ?, 1) ON CONFLICT(key, window) DO UPDATE SET count = count + 1 WHERE count < ? RETURNING count",
      )
        .bind(key, Math.floor(now() / 60000), limit)
        .first();
      if (!admitted)
        throw new PolicyError(429, "too many sign-in requests; retry after one minute");
    }
    await next();
  });
  const service = (c: Context<Environment>) =>
    new IssuanceService(c.get("issuance"), new CloudflareIssuer(send), send);
  const agent = (c: Context<Environment>) =>
    c
      .get("issuance")
      .auth(c.req.header("Authorization")?.replace(/^Bearer /, ""), "agent");
  async function browser(c: Context<Environment>): Promise<Auth> {
    return c.get("issuance").auth(getCookie(c, browserCookie), "browser");
  }
  async function form(c: Context<Environment>, auth: Auth) {
    const origin = (await c.get("issuance").identity()).origin;
    if (c.req.header("Origin") !== origin)
      throw new PolicyError(403, "approval must come from the Vault page");
    const input = await c.req.parseBody();
    const csrf = z.string().safeParse(input.csrf);
    if (!csrf.success || !(await timingSafeStringEqual(auth.csrf, csrf.data)))
      throw new PolicyError(403, "invalid approval form");
    return input;
  }
  function loginLink(path: string) {
    return `/issuance/auth/login?returnTo=${encodeURIComponent(path)}`;
  }
  async function requireBrowser(c: Context<Environment>) {
    try {
      return await browser(c);
    } catch (error) {
      if (error instanceof PolicyError && error.status === 401) return null;
      throw error;
    }
  }
  async function device(c: Context<Environment>, deviceId: string) {
    const row = await c
      .get("issuance")
      .db.prepare("SELECT * FROM issuance_devices WHERE id = ? AND expires_at > ?")
      .bind(id.parse(deviceId), now())
      .first<Device>();
    if (!row) throw new PolicyError(404, "connection request is missing or expired");
    return row;
  }

  app.get("/auth/login", async (c) => {
    const store = c.get("issuance");
    const returnTo = localPath.parse(c.req.query("returnTo"));
    const config = await store.identity();
    const state = nonce();
    const verifier = nonce();
    await store.putEphemeral(
      `github:${state}`,
      {
        returnTo,
        verifier,
        configHash: await vaultCrypto.sha256(JSON.stringify(config)),
      },
      600000,
    );
    setCookie(c, stateCookie, state, { ...cookieOptions, maxAge: 600 });
    const challenge = btoa(
      String.fromCharCode(
        ...new Uint8Array(
          await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
        ),
      ),
    )
      .replaceAll("=", "")
      .replaceAll("+", "-")
      .replaceAll("/", "_");
    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: `${config.origin}/issuance/auth/callback`,
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    return c.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
  });
  app.get("/auth/callback", async (c) => {
    const state = z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .parse(c.req.query("state"));
    const cookie = getCookie(c, stateCookie);
    if (!cookie || !(await timingSafeStringEqual(cookie, state)))
      throw new PolicyError(401, "sign-in state does not match this browser");
    deleteCookie(c, stateCookie, cookieOptions);
    const store = c.get("issuance");
    const saved = loginStateSchema.parse(await store.takeEphemeral(`github:${state}`));
    const config = await store.identity();
    if (saved.configHash !== (await vaultCrypto.sha256(JSON.stringify(config))))
      throw new PolicyError(401, "identity configuration changed; sign in again");
    const code = z.string().min(1).max(500).parse(c.req.query("code"));
    const exchange = await send("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      redirect: "manual",
      signal: AbortSignal.timeout(20000),
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        code,
        redirect_uri: `${config.origin}/issuance/auth/callback`,
        code_verifier: saved.verifier,
      }),
    });
    const token = z
      .object({ access_token: z.string().min(1) })
      .safeParse(await exchange.json().catch(() => null));
    if (!exchange.ok || !token.success)
      throw new PolicyError(401, "GitHub sign-in failed");
    const response = await send("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${token.data.access_token}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "Vault",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      redirect: "manual",
      signal: AbortSignal.timeout(20000),
    });
    const user = z
      .object({ id: z.number().int().positive().safe(), login: z.string() })
      .safeParse(await response.json().catch(() => null));
    if (!response.ok || !user.success)
      throw new PolicyError(401, "GitHub identity could not be verified");
    const session = nonce();
    await store.db
      .prepare("INSERT INTO issuance_auth VALUES (?, 'browser', ?, NULL, ?, ?, ?, NULL)")
      .bind(
        await vaultCrypto.sha256(session),
        String(user.data.id),
        user.data.login,
        nonce(),
        now() + 8 * 3600000,
      )
      .run();
    setCookie(c, browserCookie, session, { ...cookieOptions, maxAge: 8 * 3600 });
    return c.redirect(saved.returnTo);
  });
  app.post("/devices", async (c) => {
    const store = c.get("issuance");
    const config = await store.identity();
    const input = deviceSchema.parse(await c.req.json());
    const ipHash = await vaultCrypto.lookupHash(
      c.req.header("CF-Connecting-IP") ?? "local",
    );
    const count = await store.db
      .prepare(
        "SELECT count(*) AS n FROM issuance_devices WHERE ip_hash = ? AND created_at > ?",
      )
      .bind(ipHash, now() - 600000)
      .first<{ n: number }>();
    if ((count?.n ?? 0) >= 20)
      throw new PolicyError(429, "too many connection attempts; retry later");
    const deviceId = crypto.randomUUID();
    await store.db
      .prepare("INSERT INTO issuance_devices VALUES (?, ?, ?, ?, ?, NULL, NULL, ?)")
      .bind(deviceId, input.challenge, input.label, ipHash, now() + 600000, now())
      .run();
    return c.json({
      deviceId,
      verificationUrl: `${config.origin}/issuance/connect/${deviceId}`,
      expiresIn: 600,
      interval: 5,
    });
  });
  app.post("/devices/poll", async (c) => {
    const input = pollSchema.parse(await c.req.json());
    const row = await device(c, input.deviceId);
    if (
      !(await timingSafeStringEqual(
        row.challenge,
        await vaultCrypto.sha256(input.verifier),
      ))
    )
      throw new PolicyError(401, "invalid connection verifier");
    if (!row.subject || !row.tenant_id) return c.json({ status: "pending" });
    const store = c.get("issuance");
    const token = await vaultCrypto.sha256(`vault-agent:${row.id}:${input.verifier}`);
    const hash = await vaultCrypto.sha256(token);
    await store.db
      .prepare(
        "INSERT OR IGNORE INTO issuance_auth VALUES (?, 'agent', ?, ?, ?, '', ?, NULL)",
      )
      .bind(hash, row.subject, row.tenant_id, row.label, row.created_at + 8 * 3600000)
      .run();
    await store.auth(token, "agent");
    return c.json({
      status: "connected",
      token,
      expiresAt: new Date(row.created_at + 8 * 3600000).toISOString(),
      sessionId: hash,
    });
  });
  app.get("/connect/:id", async (c) => {
    const row = await device(c, c.req.param("id"));
    const auth = await requireBrowser(c);
    if (!auth)
      return c.html(
        page(
          "Connect your AI to Vault",
          html`<p>Sign in to choose a tenant and review this connection.</p>
            <a href="${loginLink(c.req.path)}">Continue with GitHub</a>`,
        ),
      );
    const tenants = await c.get("issuance").membersTenants(auth.subject);
    if (row.subject)
      return c.html(
        page(
          "Connection approved",
          html`<p>
            Return to the Vault command. Token creation will require separate approval.
          </p>`,
        ),
      );
    return c.html(
      page(
        "Allow this AI connection?",
        html`<p>
            Signed in as <strong>${auth.label}</strong> (GitHub ID ${auth.subject}).
          </p>
          <p>Application name supplied by the caller: <strong>${row.label}</strong></p>
          <p>Verify this connection ID matches the command you started:</p>
          <code>${row.id}</code>
          <p class="notice">
            This connection can discover credentials available to you and request service
            provisioning, resource changes, and new tokens. It cannot approve its own
            requests or read parent tokens. Access lasts up to eight hours.
          </p>
          <form method="post">
            <input type="hidden" name="csrf" value="${auth.csrf}" /><label
              >Tenant<select required name="tenantId">
                ${tenants.map((tenant) => html`<option value="${tenant.id}">${tenant.label}</option>`)}
              </select></label
            ><button name="decision" value="approve">Connect</button>
          </form>
          ${tenants.length ? "" : html`<p>Your GitHub identity has no Vault tenant membership. Ask a Vault operator to add GitHub ID ${auth.subject}.</p>`}`,
      ),
    );
  });
  app.post("/connect/:id", async (c) => {
    const auth = await browser(c);
    const input = await form(c, auth);
    const row = await device(c, c.req.param("id"));
    const tenantId = id.parse(input.tenantId);
    const updated = await c
      .get("issuance")
      .db.prepare(`UPDATE issuance_devices SET subject = ?, tenant_id = ? WHERE id = ? AND subject IS NULL AND expires_at > ?
      AND EXISTS (SELECT 1 FROM issuance_members WHERE tenant_id = ? AND subject = ?)`)
      .bind(auth.subject, tenantId, row.id, now(), tenantId, auth.subject)
      .run();
    if (updated.meta.changes !== 1)
      throw new PolicyError(
        409,
        "connection expired, already approved, or tenant unavailable",
      );
    return c.redirect(c.req.path, 303);
  });
  app.get("/approve/:id", async (c) => {
    id.parse(c.req.param("id"));
    const auth = await requireBrowser(c);
    if (!auth)
      return c.html(
        page(
          "Review provider request",
          html`<p>Sign in to review the operation and approve or decline.</p>
            <a href="${loginLink(c.req.path)}">Continue with GitHub</a>`,
        ),
      );
    const store = c.get("issuance");
    const row = await store.request(c.req.param("id"), auth);
    const view = await service(c).view(row);
    const canApprove =
      row.status === "prepared" &&
      row.approve_before > now() &&
      row.expires_at > now() &&
      (await store.eligibleRequest(row));
    return c.html(
      page(
        "Allow Vault to use this credential?",
        html`<p>Signed in as ${auth.label} (GitHub ID ${auth.subject}).</p>
          <dl>
            <dt>Issuer</dt>
            <dd>${view.issuer}</dd>
            <dt>Tenant</dt>
            <dd>${view.tenantId}</dd>
            <dt>Permission</dt>
            <dd>${view.effect}</dd>
            <dt>Account</dt>
            <dd>${view.plan.accountId}</dd>
            <dt>Exact operation</dt>
            <dd><pre>${JSON.stringify(view.plan.operation, null, 2)}</pre></dd>
            <dt>Purpose supplied by the AI</dt>
            <dd>${view.plan.purpose}</dd>
            <dt>Consumer supplied by the AI</dt>
            <dd>${view.plan.consumer}</dd>
            <dt>Request or token expires</dt>
            <dd>${view.plan.expiresAt}</dd>
            <dt>Request</dt>
            <dd>${row.id}</dd>
            <dt>Status</dt>
            <dd>${row.status}</dd>
          </dl>
          <p class="notice">
            Approval lets Vault use the parent token for this exact operation once.
            Service creation, changes, deletion, and AI calls can incur charges.
            Cancelling an admitted API operation does not undo its effects. A created
            token stays in Vault for this AI session until expiry or revocation. Token
            cleanup is included. Another parent-token operation requires new approval.
          </p>
          ${canApprove ? html`<form method="post"><input type="hidden" name="csrf" value="${auth.csrf}" /><button name="decision" value="approve">Approve once</button><button name="decision" value="decline">Decline</button></form>` : html`<p>Return to your AI to continue.</p>`}`,
      ),
    );
  });
  app.post("/approve/:id", async (c) => {
    const auth = await browser(c);
    const input = await form(c, auth);
    const decision = z.enum(["approve", "decline"]).parse(input.decision);
    await service(c).approve(auth, id.parse(c.req.param("id")), decision === "approve");
    return c.redirect(c.req.path, 303);
  });
  app.post("/logout", async (c) => {
    const auth = await browser(c);
    await form(c, auth);
    await c
      .get("issuance")
      .db.prepare("UPDATE issuance_auth SET revoked_at = ? WHERE hash = ?")
      .bind(now(), auth.hash)
      .run();
    deleteCookie(c, browserCookie, cookieOptions);
    return c.html(
      page("Signed out", html`<p>This browser can no longer approve requests.</p>`),
    );
  });
  app.post("/session/revoke", async (c) => {
    const auth = await agent(c);
    await c
      .get("issuance")
      .admin({ action: "revoke-session", sessionId: auth.hash }, auth.subject);
    return c.json({ ok: true });
  });
  app.get("/issuers", async (c) =>
    c.json({ issuers: await c.get("issuance").issuers(await agent(c)) }),
  );
  app.post("/requests", async (c) =>
    c.json(
      await service(c).prepare(await agent(c), prepareSchema.parse(await c.req.json())),
      201,
    ),
  );
  app.get("/requests/:id", async (c) =>
    c.json(
      await service(c).view(
        await c.get("issuance").request(id.parse(c.req.param("id")), await agent(c)),
      ),
    ),
  );
  app.post("/requests/:id/execute", async (c) =>
    c.json(await service(c).execute(await agent(c), id.parse(c.req.param("id")))),
  );
  app.post("/requests/:id/revoke", async (c) =>
    c.json(await service(c).revoke(await agent(c), id.parse(c.req.param("id")))),
  );
  app.post("/requests/:id/use", async (c) =>
    c.json(
      await service(c).use(
        await agent(c),
        id.parse(c.req.param("id")),
        apiRequestSchema.parse(await c.req.json()),
      ),
    ),
  );
  return app;
}
