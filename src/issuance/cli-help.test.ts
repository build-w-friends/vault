import { describe, expect, test } from "bun:test";
import { mkdtempSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(new URL("../cli.ts", import.meta.url).href);

describe("issuance CLI help", () => {
  test.each([
    { args: ["issuance", "setup", "--help"], text: "GitHub" },
    {
      args: ["issuance", "connect", "cloudflare", "--help"],
      text: "without entering JSON",
    },
    { args: ["issuance"], text: "vault issuance <command>" },
    { args: ["issuance", "--help"], text: "browser approval" },
    { args: ["issuance", "login", "--help"], text: "vault issuance login --api-url URL" },
    { args: ["issuance", "mcp", "-h"], text: "use_credential" },
    { args: ["issuance", "admin", "--help"], text: "revoke-issuer" },
    { args: ["issuance", "inspect", "--help"], text: "REQUEST_ID" },
    { args: ["issuance", "logout", "--help"], text: "keeps the local file" },
    { args: ["help", "issuance", "mcp"], text: "mcpServers" },
    { args: ["issuance", "help", "admin"], text: "parentToken" },
  ])("prints help without credentials or side effects: $args", async ({ args, text }) => {
    const directory = mkdtempSync(join(tmpdir(), "vault-help-"));
    try {
      const result = Bun.spawn([process.execPath, cli, ...args], {
        cwd: directory,
        env: { HOME: directory, PATH: process.env.PATH ?? "" },
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
      });
      const [code, stdout, stderr] = await Promise.all([
        result.exited,
        new Response(result.stdout).text(),
        new Response(result.stderr).text(),
      ]);
      expect(code).toBe(0);
      expect(stderr).toBe("");
      expect(stdout).toContain(text);
      expect(existsSync(join(directory, ".config"))).toBe(false);
      expect(existsSync(join(directory, ".dev.vars"))).toBe(false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
