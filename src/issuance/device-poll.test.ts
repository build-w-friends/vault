import { rejects } from "node:assert/strict";
import { expect, test } from "bun:test";
import { retryDevicePoll, TemporaryConnectionError } from "./device-poll.ts";

test("device polling survives a lost reply and returns the retried session", async () => {
  let calls = 0,
    time = 0;
  const session = { status: "connected", token: "synthetic-member-session" };
  const result = await retryDevicePoll(
    async () => {
      calls++;
      if (calls < 3) throw new TemporaryConnectionError("lost reply");
      return session;
    },
    10000,
    {
      now: () => time,
      wait: async () => {
        time += 1000;
      },
    },
  );
  expect(result).toBe(session);
  expect(calls).toBe(3);
});

test("device polling stops at expiry and does not retry a rejected verifier", async () => {
  let time = 0;
  await rejects(
    retryDevicePoll(
      async () => {
        throw new TemporaryConnectionError();
      },
      2000,
      {
        now: () => time,
        wait: async () => {
          time += 1000;
        },
      },
    ),
    new RegExp("expired"),
  );
  let calls = 0;
  await rejects(
    retryDevicePoll(async () => {
      calls++;
      throw new Error("invalid connection verifier");
    }, Date.now() + 60000),
    new RegExp("invalid connection verifier"),
  );
  expect(calls).toBe(1);
});
