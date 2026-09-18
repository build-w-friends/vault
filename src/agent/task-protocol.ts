import {
  McpServer,
  inputRequired,
  CLIENT_CAPABILITIES_META_KEY,
  type Transport,
} from "@modelcontextprotocol/server";
import * as v from "valibot";
import type { AgentTask } from "./tasks.ts";
import type { AgentRuntime } from "./runtime.ts";
const taskExtension = "io.modelcontextprotocol/tasks";
export const capabilitySchema = v.object({
  [CLIENT_CAPABILITIES_META_KEY]: v.optional(
    v.object({
      extensions: v.optional(v.record(v.string(), v.unknown())),
      elicitation: v.optional(v.object({ url: v.optional(v.object({})) })),
    }),
  ),
});
export function parseTaskCapability(envelope: v.InferOutput<typeof capabilitySchema>) {
  const parsed = v.safeParse(capabilitySchema, envelope);
  return (
    parsed.success &&
    Object.hasOwn(
      parsed.output[CLIENT_CAPABILITIES_META_KEY]?.extensions ?? {},
      taskExtension,
    )
  );
}
function taskView(task: AgentTask) {
  const pending = task.state === "waiting" || task.state === "saving";
  const status =
    task.state === "cancelled" || task.state === "expired"
      ? "cancelled"
      : pending
        ? task.url
          ? "input_required"
          : "working"
        : "completed";
  const base = {
    taskId: task.taskId,
    status,
    createdAt: new Date(task.createdAt).toISOString(),
    lastUpdatedAt: new Date(task.updatedAt).toISOString(),
    ttlMs: null,
    pollIntervalMs: 2000,
    statusMessage: task.state,
  };
  if (status === "input_required" && task.url)
    return {
      ...base,
      inputRequests: {
        vault: inputRequired.elicitUrl({
          url: task.url,
          message:
            "Complete this Vault request in your browser. Acceptance here does not authorize the operation.",
        }),
      },
    };
  if (status === "completed")
    return {
      ...base,
      result: {
        content: [{ type: "text", text: JSON.stringify(task) }],
        isError: task.state !== "stored",
      },
    };
  return base;
}
export function taskHandle(task: AgentTask) {
  const view = taskView(task);
  // content satisfies the SDK's generic result envelope; task clients use the discriminator.
  return {
    resultType: "task",
    content: [],
    taskId: view.taskId,
    status: view.status,
    createdAt: view.createdAt,
    lastUpdatedAt: view.lastUpdatedAt,
    ttlMs: null,
    pollIntervalMs: 2000,
  };
}
export function registerTaskProtocol(server: McpServer) {
  server.server.registerCapabilities({ extensions: { [taskExtension]: {} } });
}
const taskMessageSchema = v.object({
  jsonrpc: v.literal("2.0"),
  id: v.union([v.string(), v.number()]),
  method: v.picklist(["tasks/get", "tasks/update", "tasks/cancel"]),
  params: v.object({
    taskId: v.pipe(v.string(), v.uuid()),
    _meta: v.object({
      "io.modelcontextprotocol/protocolVersion": v.literal("2026-07-28"),
      [CLIENT_CAPABILITIES_META_KEY]: v.object({
        extensions: v.record(v.string(), v.unknown()),
      }),
    }),
    inputResponses: v.optional(v.record(v.string(), v.unknown())),
  }),
});
/** The SDK 2.0 core rejects tasks/get as removed legacy vocabulary before
 * custom handlers run. This extension transport owns only the three modern
 * Tasks methods; the SDK still owns framing and every core method. */
export function taskTransport(inner: Transport, runtime: AgentRuntime): Transport {
  const transport: Transport = {
    async start() {
      // MCP Transport has callback properties, not EventTarget methods.
      // eslint-disable-next-line unicorn/prefer-add-event-listener
      inner.onmessage = (message, extra) => {
        if (
          !("method" in message) ||
          !["tasks/get", "tasks/update", "tasks/cancel"].includes(message.method)
        ) {
          transport.onmessage?.(message, extra);
          return;
        }
        void (async () => {
          if (!("id" in message)) return;
          const parsed = v.safeParse(taskMessageSchema, message);
          if (!parsed.success) {
            await inner.send({
              jsonrpc: "2.0",
              id: message.id,
              error: { code: -32602, message: "Invalid MCP Tasks request" },
            });
            return;
          }
          if (!parseTaskCapability(parsed.output.params["_meta"])) {
            await inner.send({
              jsonrpc: "2.0",
              id: message.id,
              error: { code: -32021, message: "MCP Tasks capability is required" },
            });
            return;
          }
          try {
            const declined = v.safeParse(
              v.object({
                vault: v.object({ action: v.picklist(["decline", "cancel"]) }),
              }),
              parsed.output.params.inputResponses,
            ).success;
            const task =
              message.method === "tasks/cancel" ||
              (message.method === "tasks/update" && declined)
                ? await runtime.cancel(parsed.output.params.taskId)
                : message.method === "tasks/update"
                  ? await runtime.resume(parsed.output.params.taskId)
                  : runtime.tasks.get(parsed.output.params.taskId);
            await inner.send({
              jsonrpc: "2.0",
              id: message.id,
              result: {
                ...taskView(task),
                _meta: {
                  "io.modelcontextprotocol/serverInfo": {
                    name: "vault",
                    version: "1.0.0",
                  },
                },
              },
            });
          } catch {
            await inner.send({
              jsonrpc: "2.0",
              id: message.id,
              error: { code: -32602, message: "Task unavailable" },
            });
          }
        })().catch(() => transport.onerror?.(new Error("Vault task transport failed")));
      };
      // eslint-disable-next-line unicorn/prefer-add-event-listener -- MCP Transport callback API
      inner.onclose = () => transport.onclose?.();
      // eslint-disable-next-line unicorn/prefer-add-event-listener -- MCP Transport callback API
      inner.onerror = (error) => transport.onerror?.(error);
      await inner.start();
    },
    send: (message) => inner.send(message),
    close: () => inner.close(),
  };
  return transport;
}
