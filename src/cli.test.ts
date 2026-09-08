import { describe, expect, test } from "bun:test";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  assertProviderPushAllowed,
  initializeLocalVaultAt,
  parseArgv,
  runCli,
} from "./cli.ts";

describe("cli argv", () => {
  test("splits flags from the command after --", () => {
    const parsed = parseArgv([
      "run",
      "--project",
      "demo",
      "--env",
      "dev",
      "--",
      "bun",
      "-e",
      "console.log(1)",
    ]);
    expect(parsed.command).toBe("run");
    expect(parsed.flags.project).toBe("demo");
    expect(parsed.flags.env).toBe("dev");
    expect(parsed.flags.rest).toEqual(["bun", "-e", "console.log(1)"]);
  });

  test("set takes the name and keeps --env", () => {
    const parsed = parseArgv(["set", "REALTIME_APP_SECRET", "--env", "prod"]);
    expect(parsed.command).toBe("set");
    expect(parsed.flags.env).toBe("prod");
    expect(parsed.flags.rest).toEqual(["REALTIME_APP_SECRET"]);
  });

  test("keeps --env and --wrangler-env as separate namespaces", () => {
    const parsed = parseArgv([
      "run",
      "--env",
      "prod",
      "--wrangler-env",
      "production",
      "--",
      "bun",
      "x",
    ]);
    expect(parsed.flags.env).toBe("prod");
    expect(parsed.flags.wranglerEnv).toBe("production");
    expect(parsed.flags.rest).toEqual(["bun", "x"]);
  });

  test("reports a run failure as a message, not an unhandled rejection", async () => {
    // `run` and `proxy` return their promise out of runCli's `try`, which the
    // `catch` does not see without an await. The refusal to guess a Wrangler
    // environment reaches the operator through exactly this path.
    const previousUrl = process.env["VAULT_API_URL"];
    const previousKey = process.env["VAULT_API_KEY"];
    process.env["VAULT_API_URL"] = "http://127.0.0.1:1";
    process.env["VAULT_API_KEY"] = "not-used";
    const errors: string[] = [];
    try {
      const code = await runCli(["run"], { log: () => {}, error: (m) => errors.push(m) });
      expect(code).toBe(1);
    } finally {
      if (previousUrl == null) delete process.env["VAULT_API_URL"];
      else process.env["VAULT_API_URL"] = previousUrl;
      if (previousKey == null) delete process.env["VAULT_API_KEY"];
      else process.env["VAULT_API_KEY"] = previousKey;
    }
    expect(errors.join("\n")).toContain("usage: vault run -- CMD");
  });

  test("blocks provider writes while another system is authoritative", () => {
    expect(() => {
      assertProviderPushAllowed("external-system");
    }).toThrow("provider push is disabled while vault.json names another authority");
    expect(() => {
      assertProviderPushAllowed("vault");
    }).not.toThrow();
    expect(() => {
      assertProviderPushAllowed(undefined);
    }).not.toThrow();
  });

  test("initializes credentials with an exclusive private create", () => {
    const root = mkdtempSync(join(tmpdir(), "vault-init-"));
    try {
      const existingConfig = '{"project":"preserved"}\n';
      writeFileSync(join(root, "vault.json"), existingConfig);
      expect(initializeLocalVaultAt(root, { log: () => undefined })).toBe(0);
      expect(statSync(join(root, ".dev.vars")).mode & 0o777).toBe(0o600);
      expect(readFileSync(join(root, ".dev.vars"), "utf8")).toMatch(
        /^MASTER_KEY_PRIMARY=.+\nMASTER_KEY_SECONDARY=.+\nBOOTSTRAP_TOKEN=.+\n$/u,
      );
      expect(readFileSync(join(root, "vault.json"), "utf8")).toBe(existingConfig);
      expect(() => initializeLocalVaultAt(root, { log: () => undefined })).toThrow(
        `${join(root, ".dev.vars")} already exists`,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("refuses an existing credential symlink without changing its target", () => {
    const root = mkdtempSync(join(tmpdir(), "vault-init-symlink-"));
    try {
      const target = join(root, "target");
      writeFileSync(target, "unchanged");
      symlinkSync(target, join(root, ".dev.vars"));
      expect(() => initializeLocalVaultAt(root, { log: () => undefined })).toThrow(
        "already exists",
      );
      expect(readFileSync(target, "utf8")).toBe("unchanged");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
