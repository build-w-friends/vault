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

import { assertProviderPushAllowed, initializeLocalVaultAt, parseArgv } from "./cli.ts";

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

  test("blocks provider writes from an Infisical shadow project", () => {
    expect(() => assertProviderPushAllowed("infisical-shadow")).toThrow(
      "provider push is disabled while Infisical is authoritative",
    );
    expect(() => assertProviderPushAllowed("vault")).not.toThrow();
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
