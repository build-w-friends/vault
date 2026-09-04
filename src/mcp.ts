/**
 * The MCP surface, built so an agent can safely hold a key to it.
 *
 * Four tools: `list_secrets` (names and kinds), `list_routes`, `create_sealed`
 * (random value, not returned), and `mint_proxy_help`. None returns a secret
 * value, and that is the design rather than an omission — `get_secret` is
 * answered with an explicit "not available" so its absence cannot read as an
 * oversight to be fixed later.
 *
 * Authentication, scope, and permission come from the same middleware and the
 * same `policy.ts` decisions as the HTTP routes; this is a second transport,
 * not a second authority.
 *
 * @see {@link https://vault.buildwithfriends.dev/concepts/brokering/}
 */
import type { Context } from "hono";

import { StoreError, VaultStore } from "./db.ts";
import { randomSecretValue } from "./keys.ts";
import { PolicyError, assertCanWrite, assertScope } from "./policy.ts";
import type { ApiKeyRecord } from "./types.ts";
import * as v from "valibot";

const rpcRequestSchema = v.object({
  jsonrpc: v.literal("2.0"),
  id: v.optional(v.union([v.string(), v.number(), v.null()])),
  method: v.string(),
  params: v.optional(
    v.pipe(
      v.unknown(),
      v.check(
        (value) => value !== null && !Array.isArray(value),
        "params must be an object",
      ),
      v.looseObject({
        name: v.optional(v.unknown()),
        arguments: v.optional(v.unknown()),
      }),
    ),
  ),
});
const toolCallParamsSchema = v.object({
  name: v.string(),
  arguments: v.optional(
    v.pipe(
      v.unknown(),
      v.check((value) => !Array.isArray(value), "arguments must be an object"),
      v.looseObject({}),
    ),
  ),
});
const projectEnvironmentArgsSchema = v.object({
  project: v.string(),
  env: v.string(),
});
const createSealedArgsSchema = v.object({
  project: v.string(),
  env: v.string(),
  name: v.string(),
});

type RpcId = string | number | null;
type ToolArgs = { project: string; env: string; name?: string };
type McpContent = { type: "text"; text: string };
type McpResult =
  | {
      protocolVersion: string;
      capabilities: { tools: Record<string, never> };
      serverInfo: { name: string; version: string };
    }
  | {
      tools: Array<{
        name: string;
        description: string;
        inputSchema: {
          type: "object";
          properties: Record<string, { type: string }>;
          required?: string[];
        };
      }>;
    }
  | { content: McpContent[] };

export async function handleMcp(
  c: Context<{
    Bindings: { DB: D1Database };
    Variables: { store: VaultStore; key: ApiKeyRecord };
  }>,
): Promise<Response> {
  const key = c.get("key");
  const store = c.get("store");
  let input: unknown;
  try {
    input = await c.req.json();
  } catch {
    return c.json({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32700, message: "parse error" },
    });
  }
  const parsed = v.safeParse(rpcRequestSchema, input);
  if (!parsed.success) {
    return c.json({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32600, message: "invalid request" },
    });
  }
  const rpc = parsed.output;
  const id: RpcId = rpc.id ?? null;

  const result = async (value: McpResult) =>
    c.json({ jsonrpc: "2.0", id, result: value });
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
  const callParams = v.safeParse(toolCallParamsSchema, rpc.params);
  if (!callParams.success) return error(-32602, "invalid params");
  const name = callParams.output.name ?? "";
  const rawArgs = callParams.output.arguments ?? {};
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
    const args =
      name === "create_sealed"
        ? v.safeParse(createSealedArgsSchema, rawArgs)
        : v.safeParse(projectEnvironmentArgsSchema, rawArgs);
    if (!args.success) return error(-32602, "invalid params");
    const normalizedArgs: ToolArgs = args.output;
    assertScope(key, normalizedArgs.project, normalizedArgs.env);
    const { environmentId } = await store.requireEnvironment(
      normalizedArgs.project,
      normalizedArgs.env,
    );
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
      const secretName = normalizedArgs.name;
      if (secretName == null) return error(-32602, "invalid params");
      assertCanWrite(key);
      await store.setSecret(environmentId, secretName, randomSecretValue(), "sealed");
      await store.audit({
        keyPrefix: key.keyPrefix,
        action: "set",
        status: "ok",
        secretName,
      });
      return result({
        content: [{ type: "text", text: `created sealed secret ${secretName}` }],
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
