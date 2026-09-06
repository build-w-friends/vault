import { describe, expect, test } from "bun:test";
/* oxlint-disable no-named-as-default-member -- see push-github.ts */
import sodium from "libsodium-wrappers";

import {
  encryptGithubSecret,
  namesFromGithubListing,
  pushGithubSecrets,
} from "./push-github.ts";

describe("github push", () => {
  test("encrypts so the matching keypair can open the seal", async () => {
    await sodium.ready;
    const pair = sodium.crypto_box_keypair();
    const publicKey = sodium.to_base64(pair.publicKey, sodium.base64_variants.ORIGINAL);
    const encrypted = await encryptGithubSecret("super-secret", publicKey);
    const opened = sodium.crypto_box_seal_open(
      sodium.from_base64(encrypted, sodium.base64_variants.ORIGINAL),
      pair.publicKey,
      pair.privateKey,
    );
    expect(sodium.to_string(opened)).toBe("super-secret");
  });

  test("reads names from the actions secrets listing", () => {
    expect(
      namesFromGithubListing({
        total_count: 1,
        secrets: [{ name: "CI_TOKEN", created_at: "x", updated_at: "y" }],
      }),
    ).toEqual(["CI_TOKEN"]);
  });

  test("rejects malformed public keys before putting any secret", async () => {
    for (const body of [null, { key: 1, key_id: "1" }, { key: "key", key_id: 1 }]) {
      let puts = 0;
      const fetchImpl: import("./push-cloudflare.ts").FetchLike = async (input) => {
        if (input.endsWith("/public-key")) return Response.json(body);
        puts += 1;
        return new Response(null, { status: 204 });
      };
      await pushGithubSecrets(
        { repo: "acme/app", token: "gh" },
        { CI_TOKEN: "t" },
        fetchImpl,
      ).then(
        () => {
          throw new Error("Malformed GitHub public key was accepted");
        },
        (cause: unknown) => {
          expect(cause).toBeInstanceOf(Error);
          expect(cause).toHaveProperty("message", "GitHub public key was unreadable");
        },
      );
      expect(puts).toBe(0);
    }
  });

  test("puts each secret after fetching the repo public key", async () => {
    const puts: string[] = [];
    const fetchImpl: import("./push-cloudflare.ts").FetchLike = async (input) => {
      const url = input;
      if (url.endsWith("/public-key")) {
        await sodium.ready;
        const pair = sodium.crypto_box_keypair();
        return Response.json({
          key_id: "1",
          key: sodium.to_base64(pair.publicKey, sodium.base64_variants.ORIGINAL),
        });
      }
      puts.push(url);
      return new Response(null, { status: 204 });
    };
    await pushGithubSecrets(
      { repo: "acme/app", token: "gh" },
      { CI_TOKEN: "t" },
      fetchImpl,
    );
    expect(puts[0]).toContain("/actions/secrets/CI_TOKEN");
  });
});
