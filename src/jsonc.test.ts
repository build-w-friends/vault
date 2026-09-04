import { describe, expect, test } from "bun:test";
import * as v from "valibot";

import { stripJsonComments } from "./jsonc.ts";

describe("jsonc", () => {
  test("does not treat slashes inside strings as comments", () => {
    const parsed = v.parse(
      v.object({ url: v.string(), secrets: v.object({ required: v.array(v.string()) }) }),
      JSON.parse(
        stripJsonComments(`{
        // comment
        "url": "https://buildwithfriends.dev",
        "secrets": { "required": ["A", "B",] }
      }`),
      ),
    );
    expect(parsed.url).toBe("https://buildwithfriends.dev");
    expect(parsed.secrets.required).toEqual(["A", "B"]);
  });
});
