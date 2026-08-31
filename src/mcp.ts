import type { Context } from "hono";

import { StoreError, VaultStore } from "./db.ts";
import { randomSecretValue } from "./keys.ts";
import { PolicyError, assertCanWrite, assertScope } from "./policy.ts";
import type { ApiKeyRecord } from "./types.ts";

type Rpc = {
  jsonrpc: "2.0";
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
};

export async function handleMcp(
  c: Context<{
    Bindings: { DB: D1Database };
    Variables: { store: VaultStore; key: ApiKeyRecord };
  }>,
): Promise<Response> {
  const key = c.get("key");
  const store = c.get("store");
  const rpc = (await c.req.json()) as Rpc;
  const id = rpc.id ?? null;

  const result = async (value: unknown) => c.json({ jsonrpc: "2.0", id, result: value });
  const error = (code: number, message: string) =>
    c.json({ jsonrpc: "2.0", id, error: { code, message } });

  if (rpc.method === "initialize") {
    return result({
      protocolVersion: "2026-07-28",
      capabilities: { tools: {} },
      serverInfo: { name: "poc-vault", version: "0.0.0" },
    });
  }
  if (rpc.method === "notifications/initialized") {
    return c.body(null, 202);
  }
  if (rpc.method === "tools/list") {
    return result({
      tools: [
        {
          name: "list_secrets",
          description: "List secret names and kinds. Never returns values.",
          inputSchema: {
            type: "object",
            properties: { project: { type: "string" }, env: { type: "string" } },
            required: ["project", "env"],
          },
        },
        {
          name: "list_routes",
          description: "List broker routes for a project environment.",
          inputSchema: {
            type: "object",
            properties: { project: { type: "string" }, env: { type: "string" } },
            required: ["project", "env"],
          },
        },
        {
          name: "create_sealed",
          description:
            "Create a sealed secret with a random value. The value is not returned.",
          inputSchema: {
            type: "object",
            properties: {
              project: { type: "string" },
              env: { type: "string" },
              name: { type: "string" },
            },
            required: ["project", "env", "name"],
          },
        },
        {
          name: "mint_proxy_help",
          description: "How to wrap an agent with vault proxy. Does not return secrets.",
          inputSchema: { type: "object", properties: {} },
        },
      ],
    });
  }
  if (rpc.method !== "tools/call") {
    return error(-32601, `unknown method ${rpc.method ?? ""}`);
  }
  const rawName = rpc.params?.name;
  const name = typeof rawName === "string" ? rawName : "";
  const args = (rpc.params?.arguments ?? {}) as Record<string, string>;
  try {
    if (name === "mint_proxy_help") {
      return result({
        content: [
          {
            type: "text",
            text: "vault proxy --project P --env E -- <agent>. Dummy env only; values attach on HTTPS_PROXY.",
          },
        ],
      });
    }
    if (args.project == null || args.env == null) {
      throw new PolicyError(400, "project and env are required");
    }
    assertScope(key, args.project, args.env);
    const { environmentId } = await store.requireEnvironment(args.project, args.env);
    if (name === "list_secrets") {
      const secrets = await store.listSecretMeta(environmentId);
      await store.audit({ keyPrefix: key.keyPrefix, action: "list", status: "ok" });
      return result({ content: [{ type: "text", text: JSON.stringify(secrets) }] });
    }
    if (name === "list_routes") {
      const routes = await store.listRoutes(environmentId);
      await store.audit({
        keyPrefix: key.keyPrefix,
        action: "route_list",
        status: "ok",
      });
      return result({
        content: [
          {
            type: "text",
            text: JSON.stringify(
              routes.map((route) => ({ host: route.host, secret: route.secretName })),
            ),
          },
        ],
      });
    }
    if (name === "create_sealed") {
      if (args.name == null) throw new PolicyError(400, "name is required");
      assertCanWrite(key);
      await store.setSecret(environmentId, args.name, randomSecretValue(), "sealed");
      await store.audit({
        keyPrefix: key.keyPrefix,
        action: "set",
        status: "ok",
        secretName: args.name,
      });
      return result({
        content: [{ type: "text", text: `created sealed secret ${args.name}` }],
      });
    }
    if (name === "get_secret") {
      return error(-32601, "get_secret is not available");
    }
    return error(-32601, `unknown tool ${name}`);
  } catch (caught) {
    if (caught instanceof PolicyError || caught instanceof StoreError) {
      return error(-32000, caught.message);
    }
    console.error(
      JSON.stringify({
        message: "vault MCP request failed",
        error: caught instanceof Error ? caught.message : "internal error",
      }),
    );
    return error(-32603, "internal error");
  }
}
