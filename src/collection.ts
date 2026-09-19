import * as v from "valibot";
import { spawn } from "node:child_process";
import { buildCollectionAssets } from "./collection/assets.ts" with { type: "macro" };
import { VaultClientError } from "./client.ts";
import {
  collectionTargetSchema,
  collectionReceiptSchema,
  type CollectionTarget,
} from "./collection-contract.ts";
const assets = buildCollectionAssets();

/** One local, human-submitted request. No secret is returned or persisted locally. */
export function startSecretCollection(input: {
  target: CollectionTarget;
  vaultOrigin: string;
  save(value: string): Promise<void>;
  timeoutMs?: number;
}) {
  const target = v.parse(collectionTargetSchema, input.target);
  const requestId = crypto.randomUUID();
  const path = `/${requestId}`;
  let state: v.InferOutput<typeof collectionReceiptSchema>["state"] = "waiting";
  const receipt = () => ({ requestId, target, state });
  let finish!: (value: ReturnType<typeof receipt>) => void;
  const completed = new Promise<ReturnType<typeof receipt>>((resolve) => {
    finish = resolve;
  });
  const terminal = (next: typeof state) => {
    if (state !== "waiting" && state !== "saving") return;
    state = next;
    clearTimeout(timer);
    finish(receipt());
  };
  const headers = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy":
      "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
  };
  const json = () => Response.json(receipt(), { headers });
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    development: false,
    maxRequestBodySize: 65536,
    idleTimeout: 40,
    async fetch(request) {
      const url = new URL(request.url);
      if (
        request.headers.get("host") !== `127.0.0.1:${server.port}` ||
        url.origin !== origin
      )
        return new Response("Forbidden", { status: 403, headers });
      if (request.method === "GET") {
        const asset = assets.find(
          (entry) =>
            url.pathname === (entry.name === "index.html" ? path : `/${entry.name}`),
        );
        if (asset)
          return new Response(asset.content, {
            headers: { ...headers, "Content-Type": asset.type },
          });
      }
      if (
        url.pathname !== `${path}/context` &&
        url.pathname !== `${path}/submit` &&
        url.pathname !== `${path}/cancel`
      )
        return new Response("Not found", { status: 404, headers });
      if (request.method === "GET" && url.pathname === `${path}/context`)
        return Response.json(
          { receipt: receipt(), vaultOrigin: input.vaultOrigin },
          { headers },
        );
      if (
        request.method !== "POST" ||
        request.headers.get("origin") !== origin ||
        request.headers.get("content-type") !== "application/json"
      )
        return new Response("Forbidden", { status: 403, headers });
      if (state !== "waiting") return json();
      if (url.pathname === `${path}/cancel`) {
        terminal("cancelled");
        return json();
      }
      let body: unknown;
      try {
        body = await request.json();
      } catch {
        return new Response("Invalid input", { status: 400, headers });
      }
      const parsed = v.safeParse(
        v.strictObject({ value: v.pipe(v.string(), v.minLength(1), v.maxLength(16384)) }),
        body,
      );
      if (!parsed.success)
        return new Response("Enter a secret of 1–16384 characters.", {
          status: 400,
          headers,
        });
      // Recheck after body I/O: expiry, cancellation, or another POST may have won.
      if (state !== "waiting") return json();
      state = "saving";
      clearTimeout(timer);
      try {
        await input.save(parsed.output.value);
        terminal("stored");
      } catch (error) {
        terminal(
          error instanceof VaultClientError && error.status === 409
            ? "conflict"
            : "unknown",
        );
      }
      return json();
    },
    error() {
      return new Response("Collection request failed", { status: 500, headers });
    },
  });
  const origin = `http://127.0.0.1:${server.port}`;
  const timer = setTimeout(() => {
    terminal("expired");
  }, input.timeoutMs ?? 600000);
  return {
    url: `${origin}${path}`,
    completed,
    receipt,
    stop() {
      if (state === "waiting") terminal("cancelled");
      else if (state === "saving") terminal("unknown");
      clearTimeout(timer);
      return server.stop(true);
    },
  };
}

export async function openCollectionBrowser(url: string): Promise<boolean> {
  const command =
    process.platform === "darwin"
      ? "open"
      : process.platform === "win32"
        ? "explorer.exe"
        : "xdg-open";
  return new Promise((resolve) => {
    const child = spawn(command, [url], { stdio: "ignore" });
    child.once("error", () => {
      resolve(false);
    });
    child.once("exit", (code) => {
      resolve(code === 0);
    });
  });
}
