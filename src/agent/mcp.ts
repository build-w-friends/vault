import {
  McpServer,
  inputRequired,
  CLIENT_CAPABILITIES_META_KEY,
  type ServerContext,
} from "@modelcontextprotocol/server";
import { z } from "zod";
import * as v from "valibot";
import { AgentRuntime } from "./runtime.ts";
import type { AgentTask } from "./tasks.ts";
import {
  capabilitySchema,
  registerTaskProtocol,
  parseTaskCapability,
  taskHandle,
} from "./task-protocol.ts";
const requestSchema = z.object({ requestId: z.string().uuid() }).strict();
const envelopeSchema = z.object({
  [CLIENT_CAPABILITIES_META_KEY]: z
    .object({ elicitation: z.object({ url: z.object({}).optional() }).optional() })
    .optional(),
});
const result = (data: z.infer<ReturnType<typeof z.json>>) => ({
  content: [{ type: "text" as const, text: JSON.stringify(data) }],
});
export function createAgentMcp(runtime: AgentRuntime) {
  const server = new McpServer(
    { name: "vault", version: "1.0.0" },
    {
      instructions:
        "Use describe_context first. Request missing secrets with collect_secret; the user enters them in a browser, never chat. Call connect_cloudflare for provider authorization or request_github_access for temporary repository reads. Reuse request IDs after reconnect; get_task recovers receipts without repeating effects. stored is Vault acknowledgement, not deployment. Unknown outcomes must be inspected, never retried automatically. Provider configuration prerequisites are documented in the Vault CLI reference.",
    },
  );
  const parsePrompt = async (task: AgentTask, ctx: ServerContext) => {
    const decline = v.safeParse(
      v.object({ vault: v.object({ action: v.picklist(["decline", "cancel"]) }) }),
      ctx.mcpReq.inputResponses,
    );
    if (decline.success) return result(await runtime.cancel(task.taskId));
    const envelope = v.parse(capabilitySchema, ctx.mcpReq.envelope ?? {});
    if (parseTaskCapability(envelope)) return taskHandle(task);
    const parsed = envelopeSchema.safeParse(envelope);
    if (
      task.state === "waiting" &&
      task.url &&
      parsed.success &&
      parsed.data[CLIENT_CAPABILITIES_META_KEY]?.elicitation?.url
    )
      return inputRequired({
        inputRequests: {
          vault: inputRequired.elicitUrl({
            url: task.url,
            message: `Complete the ${task.kind} request in your browser. Return here after finishing. Request: ${task.taskId}`,
          }),
        },
      });
    return result(task);
  };
  server.registerTool(
    "describe_context",
    {
      description:
        "List secret names and provider setup availability for the configured Vault scope. No values.",
      inputSchema: z.object({}).strict(),
      annotations: { readOnlyHint: true },
    },
    async () => result(await runtime.context()),
  );
  server.registerTool(
    "collect_secret",
    {
      description:
        "Ask the user for a missing secret in a browser. Generate a UUID requestId once and reuse it. Never accepts or returns the value.",
      inputSchema: requestSchema.extend({
        name: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,255}$/u),
      }),
    },
    async ({ requestId, name }, ctx) =>
      parsePrompt(await runtime.collect(requestId, name), ctx),
  );
  server.registerTool(
    "connect_cloudflare",
    {
      description:
        "Authorize Cloudflare through its OAuth consent screen. Requires VAULT_CLOUDFLARE_OAUTH config in Vault (public clientId, registered loopback redirectUri, scopes). Tokens stay in Vault. Reuse the UUID requestId.",
      inputSchema: requestSchema,
    },
    async ({ requestId }, ctx) =>
      parsePrompt(await runtime.connectCloudflare(requestId), ctx),
  );
  server.registerTool(
    "request_github_access",
    {
      description:
        "Ask the user to approve read-only contents/metadata access to one installed repository for up to one hour. Requires VAULT_GITHUB_APP in Vault. Returns a reference, not a token. Reuse requestId.",
      inputSchema: requestSchema.extend({
        repository: z
          .string()
          .regex(/^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/u),
      }),
    },
    async ({ requestId, repository }, ctx) =>
      parsePrompt(await runtime.requestGithub(requestId, repository), ctx),
  );
  server.registerTool(
    "get_task",
    {
      description:
        "Resume a request after reconnect or restart. Returns its persisted receipt; never dispatches a provider operation.",
      inputSchema: requestSchema,
      annotations: { readOnlyHint: true },
    },
    async ({ requestId }) => result(runtime.tasks.get(requestId)),
  );
  server.registerTool(
    "cancel_task",
    {
      description:
        "Cancel a request before submission. An admitted save or provider operation cannot be undone by cancellation.",
      inputSchema: requestSchema,
    },
    async ({ requestId }) => result(await runtime.cancel(requestId)),
  );
  server.registerTool(
    "read_provider",
    {
      description:
        "Read a GitHub repository or Cloudflare account/zone API through approved temporary access. No redirects; provider tokens never enter the result. Expired access requires a new user request.",
      inputSchema: requestSchema.extend({ path: z.string().startsWith("/").max(2000) }),
    },
    async ({ requestId, path }) => {
      try {
        return result(await runtime.readProvider(requestId, path));
      } catch {
        return {
          isError: true,
          ...result({
            error:
              "Provider read failed. Inspect access state, scope and expiry; no mutation was requested.",
          }),
        };
      }
    },
  );
  registerTaskProtocol(server);
  return server;
}
