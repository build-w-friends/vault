import { describe, expect, test } from "bun:test";

import {
  parseInfisicalFolderNames,
  parseInfisicalNames,
  shadowEnvironmentName,
} from "../scripts/shadow-migrate.ts";

describe("Infisical shadow migration inventory", () => {
  test("extracts names, collapses folder duplicates, and never retains values", () => {
    const table = `
┌─────────────┬──────────────────┬─────────────┐
│ SECRET NAME │ SECRET VALUE     │ SECRET TYPE │
├─────────────┼──────────────────┼─────────────┤
│ TOKEN       │ first-value      │ shared      │
│ PRIVATE_KEY │ multiline-secret │ shared      │
│ TOKEN       │ second-value     │ shared      │
└─────────────┴──────────────────┴─────────────┘`;
    const inventory = parseInfisicalNames(table);
    expect(inventory).toEqual({
      names: ["PRIVATE_KEY", "TOKEN"],
      duplicateRows: 1,
    });
    expect(JSON.stringify(inventory)).not.toContain("first-value");
    expect(JSON.stringify(inventory)).not.toContain("multiline-secret");
  });

  test("extracts folder names without retaining ids", () => {
    const table = `
┌─────────────┬──────┬──────────────────────────────────────┐
│ FOLDER NAME │ PATH │ FOLDER ID                            │
├─────────────┼──────┼──────────────────────────────────────┤
│ ci          │ /    │ 00000000-0000-4000-8000-0000000000c1 │
│ worker      │ /    │ 00000000-0000-4000-8000-0000000000c2 │
└─────────────┴──────┴──────────────────────────────────────┘`;
    const names = parseInfisicalFolderNames(table);
    expect(names).toEqual(["ci", "worker"]);
    expect(JSON.stringify(names)).not.toContain("763315fe");
  });

  test("preserves source folder identity in shadow environment names", () => {
    expect(shadowEnvironmentName("prod", "/")).toBe("prod-root");
    expect(shadowEnvironmentName("prod", "/worker")).toBe("prod-worker");
    expect(shadowEnvironmentName("prod", "/ci/reviewer")).toBe("prod-ci-reviewer");
  });
});
