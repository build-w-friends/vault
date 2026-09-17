import { serveStdio, StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";
import { VaultClient } from "../client.ts";
import { AgentTasks } from "./tasks.ts";
import { AgentRuntime } from "./runtime.ts";
import { taskTransport } from "./task-protocol.ts";
import { createAgentMcp } from "./mcp.ts";
export async function serveAgentMcp(client: VaultClient, project: string, env: string) {
  const scope = createHash("sha256")
    .update(JSON.stringify([client.apiUrl, project, env]))
    .digest("hex");
  const tasks = new AgentTasks(
    join(homedir(), ".config", "poc-vault", "agent-tasks", `${scope}.sqlite`),
  );
  const runtime = new AgentRuntime(client, project, env, tasks);
  try {
    await new Promise<void>((resolve) => {
      const handle = serveStdio(() => createAgentMcp(runtime), {
        transport: taskTransport(new StdioServerTransport(), runtime),
        onerror: () => {
          console.error("Vault MCP transport error");
        },
      });
      const stop = () => {
        void runtime
          .close()
          .then(() => handle.close())
          .then(resolve);
      };
      process.stdin.once("end", stop);
      process.once("SIGTERM", stop);
      process.once("SIGINT", stop);
    });
  } finally {
    await runtime.close();
    tasks.close();
  }
}
