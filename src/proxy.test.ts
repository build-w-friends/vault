import { createServer } from "node:http";

import { describe, expect, test } from "bun:test";

import { dummyEnvFor, startProxy } from "./proxy.ts";
import type { RouteRecord, SecretRecord } from "./types.ts";

describe("proxy", () => {
  test("child env holds dummies while the origin sees the real header", async () => {
    const seen: { authorization?: string } = {};
    const origin = await new Promise<{ port: number; close: () => Promise<void> }>(
      (resolve) => {
        const server = createServer((req, res) => {
          seen.authorization = req.headers.authorization;
          res.writeHead(200, { "content-type": "text/plain" });
          res.end("ok");
        });
        server.listen(0, "127.0.0.1", () => {
          const address = server.address();
          if (address == null || typeof address === "string")
            throw new Error("bind failed");
          resolve({
            port: address.port,
            close: () =>
              new Promise((done, reject) => {
                server.close((error) => {
                  if (error) reject(error);
                  else done();
                });
              }),
          });
        });
      },
    );

    const secrets: SecretRecord[] = [
      { name: "GITHUB_TOKEN", value: "real-github-token", kind: "sealed" },
      { name: "APP_PORT", value: "3000", kind: "config" },
    ];
    const routes: RouteRecord[] = [
      {
        host: "api.github.com",
        secretName: "GITHUB_TOKEN",
        inject: "header:Authorization:Bearer",
        stripHeaders: ["authorization"],
        dummyEnvName: "GITHUB_TOKEN",
        dummyValue: "ghp_dummy_vault_placeholder",
      },
    ];

    const dummy = dummyEnvFor(secrets, routes);
    expect(dummy.GITHUB_TOKEN).toBe("ghp_dummy_vault_placeholder");
    expect(dummy.APP_PORT).toBe("3000");

    const handle = await startProxy({
      secrets,
      routes,
      forward: { "api.github.com": `http://127.0.0.1:${origin.port}` },
    });
    try {
      const viaHttps = Bun.spawn({
        cmd: [
          "curl",
          "-sS",
          "--max-time",
          "5",
          "--proxy",
          `http://127.0.0.1:${handle.port}`,
          "--cacert",
          handle.caPath,
          "-H",
          "Authorization: Bearer ghp_dummy_vault_placeholder",
          "https://api.github.com/user",
        ],
        stdout: "pipe",
        stderr: "pipe",
      });
      expect(await viaHttps.exited).toBe(0);
      expect(seen.authorization).toBe("Bearer real-github-token");

      const blocked = Bun.spawn({
        cmd: [
          "curl",
          "-fkSs",
          "--proxy",
          `http://127.0.0.1:${handle.port}`,
          "https://127.0.0.1/",
        ],
        stdout: "pipe",
        stderr: "pipe",
      });
      expect(await blocked.exited).not.toBe(0);
    } finally {
      await handle.stop();
      await origin.close();
    }
  }, 20_000);

  test("rejects local and IP-address proxy route hosts", async () => {
    expect(
      startProxy({
        secrets: [],
        routes: [
          {
            host: "127.0.0.1",
            secretName: "TOKEN",
            inject: "header:Authorization:Bearer",
            stripHeaders: [],
            dummyEnvName: "TOKEN",
            dummyValue: "placeholder",
          },
        ],
      }),
    ).rejects.toThrow("public DNS name");
  });
});
