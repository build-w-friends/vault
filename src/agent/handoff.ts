import { randomBytes, createHash } from "node:crypto";
import * as v from "valibot";
import { buildCollectionAssets } from "../collection/assets.ts" with { type: "macro" };
import { VaultClientError } from "../client.ts";
import { AgentTasks } from "./tasks.ts";
import { cloudflareConfigSchema, exchangeCloudflare } from "./provider.ts";
const assets = buildCollectionAssets();
const headers = {
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy":
    "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
};
const escape = (value: string) =>
  value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll('"', "&quot;");
const page = (title: string, body: string, approval = false) =>
  new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escape(title)} · Vault</title><link rel="stylesheet" href="/style.css">${approval ? '<script type="module" src="/approval.js"></script>' : ""}</head><body><main><h1>${escape(title)}</h1>${body}</main></body></html>`,
    {
      headers: {
        ...headers,
        "Referrer-Policy": "no-referrer",
        "Content-Type": "text/html; charset=utf-8",
      },
    },
  );

export function githubHandoff(input: {
  tasks: AgentTasks;
  taskId: string;
  repository: string;
  save: () => Promise<void>;
}) {
  const nonce = randomBytes(24).toString("hex");
  const path = `/${nonce}`;
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    development: false,
    maxRequestBodySize: 1024,
    idleTimeout: 60,
    async fetch(request) {
      const url = new URL(request.url);
      if (
        request.headers.get("host") !== `127.0.0.1:${server.port}` ||
        url.origin !== origin
      )
        return new Response("Forbidden", { status: 403, headers });
      if (request.method === "GET" && url.pathname === "/approval.js")
        return new Response(
          assets.find((asset) => asset.name === "approval.js")?.content,
          { headers: { ...headers, "Content-Type": "text/javascript" } },
        );
      if (url.pathname === "/style.css")
        return new Response(
          assets.find((asset) => asset.name.endsWith(".css"))?.content,
          { headers: { ...headers, "Content-Type": "text/css" } },
        );
      if (url.pathname !== path)
        return new Response("Not found", { status: 404, headers });
      if (request.method === "GET")
        return page(
          "Repository access",
          `<p class="lede">Allow Vault to read <code>${escape(input.repository)}</code> for this task.</p><p>Contents and metadata only. Access expires within one hour. The agent receives a reference, never the token.</p><form id="approval"><div class="actions"><button name="decision" value="approve" disabled>Allow read access</button><button name="decision" value="cancel" disabled>Cancel</button></div></form><p id="result" role="status"></p><noscript>Enable JavaScript to submit your decision.</noscript>`,
          true,
        );
      if (request.method !== "POST" || request.headers.get("origin") !== origin)
        return new Response("Forbidden", { status: 403, headers });
      const form = new URLSearchParams(await request.text());
      if (form.get("decision") === "cancel")
        input.tasks.transition(input.taskId, "waiting", "cancelled");
      else if (form.get("decision") === "approve" && input.tasks.claim(input.taskId)) {
        try {
          await input.save();
          input.tasks.transition(input.taskId, "saving", "stored");
        } catch (error) {
          input.tasks.transition(
            input.taskId,
            "saving",
            error instanceof VaultClientError && error.status === 409
              ? "conflict"
              : "unknown",
          );
        }
      }
      return Response.json({ state: input.tasks.get(input.taskId).state }, { headers });
    },
    error() {
      return new Response("Request failed", { status: 500, headers });
    },
  });
  const origin = `http://127.0.0.1:${server.port}`;
  return { url: origin + path, stop: () => server.stop(true) };
}

export function cloudflareHandoff(input: {
  tasks: AgentTasks;
  taskId: string;
  config: v.InferOutput<typeof cloudflareConfigSchema>;
  save: (value: string) => Promise<void>;
  send?: typeof fetch;
}) {
  const redirect = new URL(input.config.redirectUri);
  if (
    redirect.protocol !== "http:" ||
    redirect.hostname !== "127.0.0.1" ||
    !redirect.port ||
    redirect.username ||
    redirect.password ||
    redirect.search ||
    redirect.hash
  )
    throw new Error(
      "Register a fixed http://127.0.0.1:PORT/callback redirect for the public Cloudflare OAuth client",
    );
  const verifier = randomBytes(32).toString("base64url");
  const state = randomBytes(32).toString("hex");
  const authorization = new URL("https://dash.cloudflare.com/oauth2/auth");
  authorization.search = new URLSearchParams({
    client_id: input.config.clientId,
    redirect_uri: redirect.href,
    response_type: "code",
    scope: input.config.scopes.join(" "),
    state,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
  }).toString();
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: Number(redirect.port),
    development: false,
    idleTimeout: 60,
    async fetch(request) {
      const url = new URL(request.url);
      if (
        request.method === "GET" &&
        request.headers.get("host") === redirect.host &&
        url.origin === redirect.origin &&
        url.pathname === "/style.css"
      )
        return new Response(
          assets.find((asset) => asset.name.endsWith(".css"))?.content,
          { headers: { ...headers, "Content-Type": "text/css" } },
        );
      if (
        request.method !== "GET" ||
        request.headers.get("host") !== redirect.host ||
        url.origin !== redirect.origin ||
        url.pathname !== redirect.pathname ||
        url.searchParams.getAll("state").length !== 1 ||
        url.searchParams.get("state") !== state
      )
        return new Response("Invalid callback", { status: 400, headers });
      if (url.searchParams.has("error")) {
        input.tasks.transition(input.taskId, "waiting", "cancelled");
        return page("Connection cancelled", "<p>Return to your agent.</p>");
      }
      const code = url.searchParams.get("code");
      if (!code || code.length > 4096 || url.searchParams.getAll("code").length !== 1)
        return new Response("Invalid callback", { status: 400, headers });
      if (input.tasks.claim(input.taskId)) {
        try {
          const value = await exchangeCloudflare(
            { ...input.config, code, verifier },
            input.send,
          );
          await input.save(JSON.stringify(value));
          input.tasks.transition(input.taskId, "saving", "stored");
        } catch (error) {
          input.tasks.transition(
            input.taskId,
            "saving",
            error instanceof VaultClientError && error.status === 409
              ? "conflict"
              : "unknown",
          );
        }
      }
      return page(
        "Connection result",
        `<p role="status">${escape(input.tasks.get(input.taskId).state)}. Return to your agent.</p>`,
      );
    },
    error() {
      return new Response("Connection failed", { status: 500, headers });
    },
  });
  return { url: authorization.href, stop: () => server.stop(true) };
}
