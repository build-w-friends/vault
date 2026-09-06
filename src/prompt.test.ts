import { rejects } from "node:assert/strict";
import { expect, test } from "bun:test";
import { PassThrough } from "node:stream";
import { readSecretValue } from "./prompt.ts";

test("hidden input accepts a pasted line without echoing the credential", async () => {
  const modes: boolean[] = [];
  const input = Object.assign(new PassThrough(), {
    isTTY: true,
    setRawMode: (mode: boolean) => {
      modes.push(mode);
    },
  });
  const output = new PassThrough();
  let printed = "";
  output.on("data", (chunk) => {
    printed += chunk.toString();
  });
  const value = readSecretValue(undefined, input, output, "Token: ");
  input.write("synthetic-secret\r\n");
  expect(await value).toBe("synthetic-secret");
  expect(printed).toBe("Token: \n");
  expect(modes).toEqual([true, false]);
  input.destroy();
  output.destroy();
});

test("cancelling hidden input restores terminal mode and returns no partial token", async () => {
  const modes: boolean[] = [];
  const input = Object.assign(new PassThrough(), {
    isTTY: true,
    setRawMode: (mode: boolean) => {
      modes.push(mode);
    },
  });
  const output = new PassThrough();
  const value = readSecretValue(undefined, input, output);
  input.write("partial\u0003");
  await rejects(value, new RegExp("cancelled"));
  expect(modes).toEqual([true, false]);
  input.destroy();
  output.destroy();
});
