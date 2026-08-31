import { describe, expect, test } from "bun:test";

import { vault } from "./vite.ts";

describe("vite plugin", () => {
  test("is a pre plugin that no-ops on build", async () => {
    const plugin = vault({ cwd: process.cwd() });
    expect(plugin.name).toBe("poc-vault");
    expect(plugin.enforce).toBe("pre");
    await plugin.config({}, { command: "build", mode: "production" });
  });
});
