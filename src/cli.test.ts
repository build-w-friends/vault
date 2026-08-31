import { describe, expect, test } from "bun:test";

import { parseArgv } from "./cli.ts";

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
});
