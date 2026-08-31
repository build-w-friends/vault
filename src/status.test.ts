import { describe, expect, test } from "bun:test";

import { formatStatus, missingNames, statusFails } from "./status.ts";

describe("status", () => {
  test("reports declared names missing from a listing", () => {
    expect(missingNames(["A", "B", "C"], ["A", "C"])).toEqual(["B"]);
  });

  test("fails when any destination is missing names", () => {
    expect(
      statusFails({
        vaultMissing: [],
        cloudflareMissing: ["X"],
        githubMissing: "skipped",
      }),
    ).toBe(true);
    expect(
      statusFails({
        vaultMissing: [],
        cloudflareMissing: [],
        githubMissing: [],
      }),
    ).toBe(false);
  });

  test("formats skipped destinations without failing them in the text", () => {
    const text = formatStatus({
      vaultMissing: [],
      cloudflareMissing: "skipped",
      githubMissing: [],
    });
    expect(text).toContain("cloudflare: skipped");
    expect(text).toContain("github: ok");
  });
});
