import { describe, expect, test } from "bun:test";

import { canDecryptValues, valueVisibleOnGet, valueVisibleOnList } from "./policy.ts";
import type { ApiKeyRecord } from "./types.ts";

const user: ApiKeyRecord = {
  id: "1",
  keyPrefix: "vault_user_aaaa",
  type: "user",
  permission: "full",
  mode: null,
  scopes: null,
  revoked: false,
};

const broker: ApiKeyRecord = {
  id: "2",
  keyPrefix: "vault_sys_bbbb",
  type: "system",
  permission: "read",
  mode: "broker",
  scopes: [{ project: "demo", env: "dev" }],
  revoked: false,
};

const inject: ApiKeyRecord = {
  id: "3",
  keyPrefix: "vault_sys_cccc",
  type: "system",
  permission: "read",
  mode: "inject",
  scopes: [{ project: "demo", env: "dev" }],
  revoked: false,
};

describe("policy", () => {
  test("broker keys cannot decrypt", () => {
    expect(canDecryptValues(broker)).toBe(false);
    expect(canDecryptValues(inject)).toBe(true);
    expect(canDecryptValues(user)).toBe(true);
  });

  test("sealed values never appear on get or list --show", () => {
    expect(valueVisibleOnGet(user, "sealed")).toBe(false);
    expect(valueVisibleOnList(user, "sealed", true)).toBe(false);
    expect(valueVisibleOnGet(user, "secret")).toBe(true);
    expect(valueVisibleOnList(broker, "secret", true)).toBe(false);
  });
});
