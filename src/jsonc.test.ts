import { describe, expect, test } from "bun:test";

import { parseJsonc } from "./jsonc.ts";

describe("jsonc", () => {
  test("does not treat slashes inside strings as comments", () => {
    const parsed = parseJsonc(`{
      // comment
      "url": "https://buildwithfriends.dev",
      "secrets": { "required": ["A", "B",] }
    }`) as { url: string; secrets: { required: string[] } };
    expect(parsed.url).toBe("https://buildwithfriends.dev");
    expect(parsed.secrets.required).toEqual(["A", "B"]);
  });
});
