import { chmodSync, mkdirSync, readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { z } from "zod";
import { resolveClientOptions } from "../config.ts";
import { parseVaultApiUrl } from "../client.ts";
import { randomSecretValue } from "../keys.ts";
import { readSecretValue } from "../prompt.ts";
import { connectCloudflare, setupIssuance, setupSchema } from "./connect-cloudflare.ts";
import { PromptCancelledError, terminalPrompts } from "./terminal.ts";
import { issuanceHelp } from "./help.ts";
import { adminSchema, id } from "./contracts.ts";
import { createIssuanceMcp, IssuanceClient } from "./mcp.ts";

const configSchema = z.object({
  origin: z.string().url(),
  token: z.string().regex(/^[a-f0-9]{64}$/u),
  expiresAt: z.string().datetime(),
  sessionId: z.string(),
});
const configPath = () => join(homedir(), ".config", "poc-vault", "issuance.json");
const okSchema = z.object({ ok: z.literal(true) });

/** A failure worth retrying: the request did not reach Vault, or Vault was busy. */
class TemporaryConnectionError extends Error {
  override readonly name = "TemporaryConnectionError";
}
async function jsonRequest<T extends z.ZodType>(
  origin: string,
  path: string,
  schema: T,
  body: string,
  token?: string,
  method = "POST",
): Promise<z.output<T>> {
  const headers = new Headers({ "Content-Type": "application/json" });
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const init: RequestInit = {
    method,
    redirect: "error",
    signal: AbortSignal.timeout(30000),
    headers,
  };
  if (method !== "GET") init.body = body;
  let response: Response;
  let text: string;
  try {
    response = await fetch(`${origin}${path}`, init);
    text = await response.text();
  } catch {
    throw new TemporaryConnectionError(
      "Could not reach Vault. Check your connection and retry.",
    );
  }
  if (path === "/v1/issuance/setup" && response.status === 404)
    throw new Error(
      "This Vault server needs the guided-setup update deployed. Installing the CLI alone does not update the server.",
    );
  let data: z.infer<ReturnType<typeof z.json>> = null;
  try {
    data = JSON.parse(text);
  } catch {
    // A body that is not JSON stays null and fails the schema below.
  }
  if (response.status === 429 || response.status >= 500)
    throw new TemporaryConnectionError(
      `Vault temporarily unavailable (HTTP ${response.status})`,
    );
  if (!response.ok) {
    const error = z.object({ error: z.string() }).safeParse(data);
    throw new Error(
      error.success ? error.data.error : `Vault returned HTTP ${response.status}`,
    );
  }
  return schema.parse(data);
}
async function saveAdmin(
  origin: string,
  input: z.infer<typeof adminSchema>,
  apiKey: string,
) {
  await jsonRequest(
    origin,
    "/v1/issuance/admin",
    okSchema,
    JSON.stringify(input),
    apiKey,
  );
}
export async function runIssuanceCli(
  args: string[],
  apiUrl: string | undefined,
  io: { log: (...data: unknown[]) => void; error: (...data: unknown[]) => void },
): Promise<number> {
  const command = args[0];
  if (
    command === undefined ||
    command === "help" ||
    command === "--help" ||
    command === "-h"
  ) {
    io.log(issuanceHelp(args[1]));
    return 0;
  }
  if (args.includes("--help") || args.includes("-h")) {
    io.log(issuanceHelp(command));
    return 0;
  }
  if (command === "connect" || command === "setup") {
    if (command === "connect" && (args[1] !== "cloudflare" || args.length !== 2))
      throw new Error("usage: vault issuance connect cloudflare [--api-url URL]");
    if (command === "setup" && args.length !== 1)
      throw new Error("usage: vault issuance setup [--api-url URL]");
    const ui = terminalPrompts();
    ui.intro(command === "setup" ? "Vault setup" : "Connect Cloudflare to Vault");
    const config = resolveClientOptions({ apiUrl });
    const origin = parseVaultApiUrl(config.apiUrl).origin;
    const setup = await jsonRequest(
      origin,
      "/v1/issuance/setup",
      setupSchema,
      "",
      config.apiKey,
      "GET",
    );
    const save = async (input: z.infer<typeof adminSchema>) => {
      await saveAdmin(origin, input, config.apiKey);
    };
    try {
      if (command === "setup") await setupIssuance({ ui, setup, origin, save });
      else await connectCloudflare({ ui, setup, save });
    } catch (error) {
      if (!(error instanceof PromptCancelledError)) throw error;
      ui.cancel(error.message);
      return 130;
    }
    return 0;
  }
  if (command === "admin") {
    const config = resolveClientOptions({ apiUrl });
    const input = adminSchema.parse(
      JSON.parse(
        await readSecretValue(
          undefined,
          process.stdin,
          process.stderr,
          "Issuer administration JSON: ",
        ),
      ),
    );
    await saveAdmin(parseVaultApiUrl(config.apiUrl).origin, input, config.apiKey);
    io.log(`Vault issuance ${input.action} saved.`);
    return 0;
  }
  if (command === "inspect") {
    const config = resolveClientOptions({ apiUrl });
    const requestId = id.parse(args[1]);
    const result = await jsonRequest(
      parseVaultApiUrl(config.apiUrl).origin,
      `/v1/issuance/requests/${requestId}`,
      z.json(),
      "",
      config.apiKey,
      "GET",
    );
    io.log(JSON.stringify(result, null, 2));
    return 0;
  }
  if (command === "login") {
    const origin = parseVaultApiUrl(apiUrl ?? args[1] ?? "").origin;
    const verifier = randomSecretValue();
    const challenge = new Bun.CryptoHasher("sha256").update(verifier).digest("hex");
    const connection = await jsonRequest(
      origin,
      "/issuance/devices",
      z.object({ deviceId: z.string().uuid(), verificationUrl: z.string().url() }),
      JSON.stringify({ challenge, label: "Vault local MCP" }),
    );
    if (
      connection.verificationUrl !== `${origin}/issuance/connect/${connection.deviceId}`
    )
      throw new Error("unexpected Vault connection URL");
    io.log(
      `Open ${connection.verificationUrl}\nVerify connection ID: ${connection.deviceId}`,
    );
    const pollSchema = z.discriminatedUnion("status", [
      z.object({ status: z.literal("pending") }),
      configSchema.omit({ origin: true }).extend({ status: z.literal("connected") }),
    ]);
    const deadline = Date.now() + 600000;
    while (Date.now() < deadline) {
      await Bun.sleep(5000);
      let polled: z.infer<typeof pollSchema>;
      try {
        polled = await jsonRequest(
          origin,
          "/issuance/devices/poll",
          pollSchema,
          JSON.stringify({ deviceId: connection.deviceId, verifier }),
        );
      } catch (error) {
        if (error instanceof TemporaryConnectionError) continue;
        throw error;
      }
      if (polled.status === "pending") continue;
      const config = configSchema.parse({ ...polled, origin });
      const path = configPath();
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      chmodSync(dirname(path), 0o700);
      writeFileSync(path, JSON.stringify(config) + "\n", { mode: 0o600 });
      chmodSync(path, 0o600);
      io.log(
        `Connected until ${config.expiresAt}. Session: ${config.sessionId}\nConfigure your MCP host to run: vault issuance mcp`,
      );
      return 0;
    }
    throw new Error("Vault connection expired; run issuance login again");
  }
  if (command === "mcp") {
    const config = configSchema.parse(JSON.parse(readFileSync(configPath(), "utf8")));
    if (Date.parse(config.expiresAt) <= Date.now())
      throw new Error("Vault issuance session expired; run issuance login");
    if (apiUrl && parseVaultApiUrl(apiUrl).origin !== config.origin)
      throw new Error("sign in to the selected Vault before using MCP");
    delete process.env.VAULT_API_KEY;
    delete process.env.VAULT_BOOTSTRAP_TOKEN;
    const client = new IssuanceClient(config.origin, config.token);
    await new Promise<void>((resolve) => {
      const handle = serveStdio(() => createIssuanceMcp(client), {
        onerror: () => {
          io.error("Vault MCP transport error");
        },
      });
      process.stdin.once("end", () => {
        void handle.close().then(resolve);
      });
    });
    return 0;
  }
  if (command === "logout") {
    const config = configSchema.parse(JSON.parse(readFileSync(configPath(), "utf8")));
    await jsonRequest(
      config.origin,
      "/issuance/session/revoke",
      okSchema,
      "{}",
      config.token,
    );
    unlinkSync(configPath());
    io.log("Vault issuance session revoked.");
    return 0;
  }
  throw new Error(`unknown issuance command: ${command}; run vault issuance --help`);
}
