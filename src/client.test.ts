import { describe, expect, test } from "bun:test";

import { parseVaultApiUrl } from "./client.ts";

describe("vault API URL", () => {
  test("allows HTTPS and loopback HTTP endpoints", () => {
    expect(parseVaultApiUrl("https://vault.example.test").origin).toBe(
      "https://vault.example.test",
    );
    expect(parseVaultApiUrl("http://127.0.0.1:8787").origin).toBe(
      "http://127.0.0.1:8787",
    );
  });

  test("rejects credential-bearing and non-loopback HTTP endpoints", () => {
    expect(() => parseVaultApiUrl("https://key@example.test")).toThrow();
    expect(() => parseVaultApiUrl("http://vault.example.test")).toThrow();
  });
});
