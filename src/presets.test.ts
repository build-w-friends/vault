import { expect, test } from "bun:test";

import { routePreset } from "./presets.ts";

test("route presets resolve only registered names", () => {
  expect(routePreset("github")).toEqual({
    host: "api.github.com",
    inject: "header:Authorization:Bearer",
    stripHeaders: ["authorization"],
    dummyEnvName: "GITHUB_TOKEN",
    dummyValue: "ghp_dummy_vault_placeholder",
  });
  expect(routePreset("anthropic")).toEqual({
    host: "api.anthropic.com",
    inject: "header:x-api-key",
    stripHeaders: ["x-api-key"],
    dummyEnvName: "ANTHROPIC_API_KEY",
    dummyValue: "__anthropic_api_key__",
  });
  for (const name of [
    "constructor",
    "__proto__",
    "toString",
    "hasOwnProperty",
    "missing",
    "",
  ])
    expect(routePreset(name)).toBeNull();
});
