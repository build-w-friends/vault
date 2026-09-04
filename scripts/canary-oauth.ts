import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { VaultClient } from "../src/client.ts";
import { readConfig } from "../src/config.ts";
import {
  assertGitHubAuthorizationPage,
  assertGitHubAuthorizationUrl,
} from "../src/operational-proofs.ts";
import * as v from "valibot";

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const origin = "http://127.0.0.1:5173";
const project = "bwf-shadow";
const serverId = "00000000-0000-4000-8000-0000000000c4";
const channelId = "00000000-0000-4000-8000-0000000000c3";

type Child = ReturnType<typeof Bun.spawn>;

async function main(): Promise<void> {
  const client = operatorClient();
  const worker = await loadEnvironment(client, "prod-worker");
  const child = Bun.spawn(
    [
      "vault",
      "run",
      "--project",
      project,
      "--env",
      "prod-worker",
      "--",
      "bun",
      "scripts/dev-stack.ts",
      "--no-electron",
      "--port",
      "5173",
    ],
    {
      cwd: projectRoot,
      env: process.env,
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  try {
    await waitForStack(child);
    const identity = await beginIdentityAuthorization();
    assertGitHubAuthorizationUrl(identity, {
      callbackUrl: `${origin}/api/auth/callback/github`,
      clientId: required(worker, "GITHUB_CLIENT_ID"),
      pkce: true,
      scopes: ["read:user", "user:email"],
    });
    await assertGitHubRecognizes(identity);
    console.log(
      "PASS  GitHub identity OAuth redirect, state, PKCE, scopes, and callback",
    );

    const app = await beginGitHubAppAuthorization();
    assertGitHubAuthorizationUrl(app, {
      callbackUrl: `${origin}/api/github-app/callback`,
      clientId: required(worker, "GITHUB_APP_CLIENT_ID"),
      pkce: true,
    });
    if (
      required(worker, "GITHUB_CLIENT_ID") === required(worker, "GITHUB_APP_CLIENT_ID")
    ) {
      throw new Error("identity OAuth and GitHub App unexpectedly share a client id");
    }
    await assertGitHubRecognizes(app);
    console.log("PASS  GitHub App user OAuth redirect, state, PKCE, and callback");
  } finally {
    child.kill("SIGTERM");
    await child.exited;
  }
}

function operatorClient(): VaultClient {
  const config = readConfig();
  if (config.apiUrl == null || config.apiKey == null) {
    throw new Error("vault operator configuration is missing");
  }
  return new VaultClient(config.apiUrl, config.apiKey);
}

async function loadEnvironment(
  client: VaultClient,
  environment: string,
): Promise<ReadonlyMap<string, string>> {
  const exported = await client.exportSecrets(project, environment);
  return new Map(exported.secrets.map((secret) => [secret.name, secret.value]));
}

function required(secrets: ReadonlyMap<string, string>, name: string): string {
  const value = secrets.get(name)?.trim();
  if (value === undefined || value === "") throw new Error(`${name} is absent`);
  return value;
}

async function waitForStack(child: Child): Promise<void> {
  let exited = false;
  void child.exited.then(() => {
    exited = true;
  });
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    if (exited) throw new Error("Vault-injected development stack exited before ready");
    try {
      const response = await fetch(origin, { redirect: "manual" });
      if (response.status >= 200 && response.status < 500) return;
    } catch {
      // The fixed callback origin has not bound yet.
    }
    await Bun.sleep(250);
  }
  throw new Error("Vault-injected development stack did not become ready");
}

async function beginIdentityAuthorization(): Promise<string> {
  const response = await fetch(`${origin}/api/auth/sign-in/social`, {
    method: "POST",
    headers: { "content-type": "application/json", origin },
    body: JSON.stringify({ provider: "github", callbackURL: "/" }),
    redirect: "manual",
  });
  if (!response.ok) throw new Error(`identity OAuth start failed (${response.status})`);
  const location = response.headers.get("location");
  if (location !== null) return location;
  const parsed = v.safeParse(
    v.looseObject({ url: v.optional(v.string()) }),
    await response.json(),
  );
  if (!parsed.success || !v.is(v.string(), parsed.output.url)) {
    throw new Error("identity OAuth returned no URL");
  }
  return parsed.output.url;
}

async function beginGitHubAppAuthorization(): Promise<string> {
  const signIn = await fetch(`${origin}/api/auth/test-session`, {
    method: "POST",
    headers: { "content-type": "application/json", origin },
    body: JSON.stringify({ principal: "alice" }),
    redirect: "manual",
  });
  if (!signIn.ok) throw new Error(`development session failed (${signIn.status})`);
  const cookie = signIn.headers.get("set-cookie")?.split(";", 1)[0];
  if (cookie === undefined) throw new Error("development session returned no cookie");
  const connect = new URL("/api/github-app/connect", origin);
  connect.searchParams.set("server", serverId);
  connect.searchParams.set("channel", channelId);
  const response = await fetch(connect, {
    headers: { cookie, origin },
    redirect: "manual",
  });
  const location = response.headers.get("location");
  if (response.status !== 302 || location === null) {
    throw new Error(`GitHub App OAuth start failed (${response.status})`);
  }
  return location;
}

async function assertGitHubRecognizes(authorizationUrl: string): Promise<void> {
  const response = await fetch(authorizationUrl, {
    headers: { "user-agent": "Build-With-Friends-Vault-Acceptance" },
    redirect: "manual",
  });
  const body = response.status === 200 ? await response.text() : "";
  assertGitHubAuthorizationPage({ body, status: response.status });
}

if (import.meta.main) {
  void main().catch((cause: unknown) => {
    console.error(cause instanceof Error ? cause.message : "OAuth acceptance failed");
    process.exit(1);
  });
}
