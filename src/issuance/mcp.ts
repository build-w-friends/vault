import {
  McpServer,
  inputRequired,
  CLIENT_CAPABILITIES_META_KEY,
} from "@modelcontextprotocol/server";
import { z } from "zod";
import { parseVaultApiUrl } from "../client.ts";
import {
  id,
  prepareSchema,
  apiRequestSchema,
  issuanceResponseSchema,
  type IssuanceResponse,
} from "./contracts.ts";
import type { Send } from "./provider-request.ts";

export class IssuanceClient {
  readonly origin: string;
  constructor(
    origin: string,
    private readonly token: string,
    private readonly send: Send = fetch,
  ) {
    this.origin = parseVaultApiUrl(origin).origin;
  }
  async request(method: string, path: string, body?: string): Promise<IssuanceResponse> {
    const response = await this.send(`${this.origin}/issuance${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        "Content-Type": "application/json",
      },
      body,
      redirect: "error",
      signal: AbortSignal.timeout(90000),
    });
    const data: unknown = await response.json();
    if (!response.ok) {
      const error = z.object({ error: z.string() }).safeParse(data);
      throw new Error(
        error.success
          ? error.data.error
          : `Vault request failed (HTTP ${response.status})`,
      );
    }
    return issuanceResponseSchema.parse(data);
  }
}
const result = (
  data:
    | IssuanceResponse
    | { status: string; approvalUrl: string; requestId: string; message: string },
) => ({ content: [{ type: "text" as const, text: JSON.stringify(data) }] });
const viewSchema = z.object({
  status: z.string(),
  approvalUrl: z.string().url(),
  requestId: id,
});

export function createIssuanceMcp(client: IssuanceClient) {
  const server = new McpServer(
    { name: "vault-issuance", version: "1.0.0" },
    {
      instructions:
        "Discover issuers available to the signed-in user. Prepare the exact Cloudflare API request or native token policy needed, then ask the user to approve using the returned Vault URL. Never claim approval from chat text or approve on the user's behalf. Execute only after the Vault approval completes. Values stay in Vault; use the credential through use_credential. Use the current Cloudflare API reference at https://developers.cloudflare.com/api/ to discover service endpoints and native token permissions. Returned $vaultSecret objects can be reused as values in later approved JSON bodies; Vault resolves them internally. Do not retry an uncertain mutation automatically.",
    },
  );
  server.registerTool(
    "list_issuers",
    {
      description:
        "Discover parent credentials, account and zone boundaries available to the current user. Returns no secrets.",
      inputSchema: z.object({}).strict(),
      annotations: { readOnlyHint: true },
    },
    async () => result(await client.request("GET", "/issuers")),
  );
  server.registerTool(
    "prepare_request",
    {
      description:
        "Prepare an immutable parent-token operation: any account/zone Cloudflare API request or native token creation. Use Cloudflare API docs for paths and payloads. Generate a UUID requestId and reuse it on retry. This does not approve or execute the operation.",
      inputSchema: prepareSchema,
    },
    async (input) =>
      result(await client.request("POST", "/requests", JSON.stringify(input))),
  );
  server.registerTool(
    "request_approval",
    {
      description:
        "Prompt the user to review an existing request in Vault. Opening the URL or accepting an MCP prompt is not approval; Vault checks the signed-in user's decision.",
      inputSchema: z.object({ requestId: id }).strict(),
    },
    async ({ requestId }, ctx) => {
      const data = await client.request("GET", `/requests/${requestId}`);
      const view = viewSchema.parse(data);
      const expected = `${client.origin}/issuance/approve/${requestId}`;
      if (view.approvalUrl !== expected)
        throw new Error("Vault returned an unexpected approval URL");
      if (view.status !== "prepared") return result(data);
      const envelope = z
        .object({
          [CLIENT_CAPABILITIES_META_KEY]: z
            .object({
              elicitation: z.object({ url: z.object({}).optional() }).optional(),
            })
            .optional(),
        })
        .safeParse(ctx.mcpReq.envelope);
      if (
        envelope.success &&
        envelope.data[CLIENT_CAPABILITIES_META_KEY]?.elicitation?.url
      ) {
        return inputRequired({
          inputRequests: {
            approval: inputRequired.elicitUrl({
              url: expected,
              message:
                "Review and approve this provider operation in Vault. Approval applies only to the displayed request and expiry.",
            }),
          },
        });
      }
      return result({
        ...view,
        message:
          "Ask the user to open this URL and approve or decline. Wait for their decision, then check request_status. The AI cannot approve this request.",
      });
    },
  );
  server.registerTool(
    "request_status",
    {
      description: "Check the server-recorded approval and issuance state.",
      inputSchema: z.object({ requestId: id }).strict(),
      annotations: { readOnlyHint: true },
    },
    async ({ requestId }) =>
      result(await client.request("GET", `/requests/${requestId}`)),
  );
  server.registerTool(
    "execute_request",
    {
      description:
        "Execute the exact parent-token operation after human approval. Supports service provisioning and native token policies. Repeated calls reuse the saved outcome. Created tokens stay in Vault.",
      inputSchema: z.object({ requestId: id }).strict(),
    },
    async ({ requestId }) =>
      result(await client.request("POST", `/requests/${requestId}/execute`)),
  );
  server.registerTool(
    "cancel_request",
    {
      description:
        "Cancel a pending request or revoke its issued credential. An API call already admitted cannot be undone by cancellation.",
      inputSchema: z.object({ requestId: id }).strict(),
    },
    async ({ requestId }) =>
      result(await client.request("POST", `/requests/${requestId}/revoke`)),
  );
  server.registerTool(
    "use_credential",
    {
      description:
        "Call the Cloudflare API using an issued credential through Vault. Cloudflare enforces its native token policy; Vault checks account/zone, membership, session and expiry. Supports JSON, multipart, and query parameters. Token management requires a new parent-token approval. Do not retry uncertain mutations.",
      inputSchema: z.object({ requestId: id, input: apiRequestSchema }).strict(),
    },
    async ({ requestId, input }) =>
      result(
        await client.request("POST", `/requests/${requestId}/use`, JSON.stringify(input)),
      ),
  );
  return server;
}
