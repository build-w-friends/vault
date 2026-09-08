#!/usr/bin/env bun
/**
 * The `vault` operator CLI.
 *
 * Two argument forms are rejected rather than supported, both because they put
 * a credential into shell history: `--api-key <value>`, and `NAME=value` on
 * `secrets set`. Values come from hidden input, stdin, or the environment.
 * Project-secret destructive commands require `--yes`; issuance administration
 * accepts explicit action records, and member requests use browser approval.
 *
 * `run` and `proxy` are the two commands that spawn something. Both strip
 * `VAULT_API_KEY` from the child environment, so a command given secrets cannot
 * turn around and ask the vault for the rest of them.
 *
 * `--env` is the vault environment. `--wrangler-env` is the Wrangler
 * environment whose `secrets.required` list `run`, `status`, and `push` read;
 * the two are separate namespaces and neither is inferred from the other. A
 * repository records the correspondence once in `vault.json`.
 *
 * `push` is guarded by `assertProviderPushAllowed`: while `vault.json` names
 * anything other than the vault as `authority`, provider synchronization fails
 * closed. That refusal is what keeps a replica from overwriting the system
 * that actually owns the values.
 *
 * @see {@link https://vault.buildwithfriends.dev/reference/cli/}
 */
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { runIssuanceCli } from "./issuance/cli.ts";
import { VaultClient } from "./client.ts";
import { resolveClientOptions, writeConfig } from "./config.ts";
import { generateMasterKey } from "./crypto.ts";
import { randomSecretValue } from "./keys.ts";
import { readSecretValue } from "./prompt.ts";
import { proxyChildEnv, startProxy } from "./proxy.ts";
import { loadRequiredSecretValues } from "./inject.ts";
import { loadVaultValues, pushDestinations } from "./push.ts";
import {
  loadRepoContext,
  resolveWranglerEnvironment,
  type WranglerEnvironmentConfig,
} from "./repo-config.ts";
import { collectStatus, formatStatus, statusFails } from "./status.ts";
import type {
  KeyMode,
  KeyType,
  Permission,
  ProcessEnvironment,
  Scope,
  SecretKind,
} from "./types.ts";

type Flags = {
  apiUrl?: string;
  apiKey?: string;
  project?: string;
  env?: string;
  githubRepo?: string;
  wranglerEnv?: string;
  label?: string;
  type?: string;
  permission?: string;
  mode?: string;
  scopes: string[];
  expiresInDays?: number;
  kind?: string;
  preset?: string;
  host?: string;
  header?: string;
  dummyEnvName?: string;
  dummyValue?: string;
  cursor?: string;
  limit?: number;
  yes: boolean;
  random: boolean;
  includeRevoked: boolean;
  rest: string[];
};

type TextFlag = {
  [Key in keyof Flags]-?: Flags[Key] extends string | undefined ? Key : never;
}[keyof Flags];

const stringFlags = new Map<string, TextFlag>([
  ["--api-url", "apiUrl"],
  ["--project", "project"],
  ["--env", "env"],
  ["--github-repo", "githubRepo"],
  ["--wrangler-env", "wranglerEnv"],
  ["--label", "label"],
  ["--type", "type"],
  ["--permission", "permission"],
  ["--mode", "mode"],
  ["--kind", "kind"],
  ["--preset", "preset"],
  ["--host", "host"],
  ["--header", "header"],
  ["--dummy-env", "dummyEnvName"],
  ["--dummy-value", "dummyValue"],
  ["--cursor", "cursor"],
]);

type ParseArgvResult = { command: string; flags: Flags };

export function parseArgv(argv: string[]): ParseArgvResult {
  const flags: Flags = {
    scopes: [],
    yes: false,
    random: false,
    includeRevoked: false,
    rest: [],
  };
  let command = "help";
  let i = 0;
  if (argv[0] != null && !argv[0].startsWith("-")) {
    command = argv[0];
    i = 1;
  }
  while (i < argv.length) {
    const token = argv[i] ?? "";
    if (token === "--") {
      flags.rest = argv.slice(i + 1);
      break;
    }
    if (token === "--yes") {
      flags.yes = true;
      i += 1;
      continue;
    }
    if (token === "--random") {
      flags.random = true;
      i += 1;
      continue;
    }
    if (token === "--include-revoked") {
      flags.includeRevoked = true;
      i += 1;
      continue;
    }
    if (token === "--scope") {
      const value = argv[i + 1];
      if (value == null) throw new Error("--scope requires PROJECT/ENV");
      flags.scopes.push(value);
      i += 2;
      continue;
    }
    if (token === "--expires-in-days" || token === "--limit") {
      const value = argv[i + 1];
      if (value == null || !/^\d+$/u.test(value)) {
        throw new Error(`${token} requires a positive integer`);
      }
      if (token === "--expires-in-days") flags.expiresInDays = Number(value);
      else flags.limit = Number(value);
      i += 2;
      continue;
    }
    const field = stringFlags.get(token);
    if (field != null) {
      const value = argv[i + 1];
      if (value == null) throw new Error(`${token} requires a value`);
      flags[field] = value;
      i += 2;
      continue;
    }
    if (token === "--api-key") {
      throw new Error("--api-key is not accepted; use VAULT_API_KEY or hidden input");
    }
    flags.rest.push(token);
    i += 1;
  }
  return { command, flags };
}

function session(flags: Flags, cwd = process.cwd()) {
  const repo = loadRepoContext(cwd);
  const resolved = resolveClientOptions({
    apiUrl: flags.apiUrl,
    apiKey: flags.apiKey,
    project: flags.project ?? repo.vault.project,
    env: flags.env ?? repo.vault.env,
    githubRepo: flags.githubRepo,
  });
  const project = resolved.project ?? repo.vault.project ?? "bwf";
  const env = resolved.env ?? repo.vault.env ?? "dev";
  return {
    repo,
    cwd,
    client: new VaultClient(resolved.apiUrl, resolved.apiKey),
    project,
    env,
    apiUrl: resolved.apiUrl,
    githubRepo: flags.githubRepo ?? resolved.githubRepo,
    // Deliberately lazy. Only the three commands that read the Wrangler
    // contract may fail on an unselected environment; `vault secrets list`
    // has no business caring which Worker environment exists.
    wranglerEnvironment: (): WranglerEnvironmentConfig | null => {
      const options: Parameters<typeof resolveWranglerEnvironment>[1] = { vaultEnv: env };
      if (flags.wranglerEnv != null) options.wranglerEnv = flags.wranglerEnv;
      return resolveWranglerEnvironment(repo, options);
    },
  };
}

async function ensureProjectAndEnvironment(
  client: VaultClient,
  project: string,
  env: string,
): Promise<void> {
  const projects = await client.listProjects();
  if (!projects.projects.includes(project.toLowerCase()))
    await client.createProject(project);
  const environments = await client.listEnvironments(project);
  if (!environments.environments.includes(env.toLowerCase())) {
    await client.createEnvironment(project, env);
  }
}

function requireYes(flags: Flags, description: string): void {
  if (!flags.yes) throw new Error(`${description} requires --yes`);
}

function enumValue<T extends string>(
  value: string | undefined,
  allowed: readonly T[],
  fallback: T,
  label: string,
): T {
  const selected = value ?? fallback;
  const matched = allowed.find((candidate) => candidate === selected);
  if (matched === undefined) {
    throw new Error(`${label} must be one of: ${allowed.join(", ")}`);
  }
  return matched;
}

function parseScopes(values: string[]): Scope[] {
  return values.map((value) => {
    const match = /^([^/]+)\/([^/]+)$/u.exec(value);
    if (match?.[1] == null || match[2] == null) {
      throw new Error(`invalid scope ${value}; expected PROJECT/ENV`);
    }
    return { project: match[1], env: match[2] };
  });
}

export async function runCli(
  argv: string[],
  io = { log: console.log, error: console.error },
): Promise<number> {
  try {
    const { command, flags } = parseArgv(argv);
    switch (command) {
      case "help":
      case "-h":
      case "--help":
        if (flags.rest[0] === "issuance") {
          return await runIssuanceCli(["help", ...flags.rest.slice(1)], flags.apiUrl, io);
        }
        io.log(helpText());
        return 0;
      case "issuance":
        return await runIssuanceCli(flags.rest, flags.apiUrl, io);
      case "init":
        return initializeLocalVaultAt(process.cwd(), io);
      case "login": {
        const apiUrl = flags.apiUrl ?? flags.rest[0] ?? process.env.VAULT_API_URL;
        if (apiUrl == null) throw new Error("usage: vault login --api-url URL");
        const apiKey = await readSecretValue(
          process.env.VAULT_API_KEY,
          process.stdin,
          process.stdout,
          "API key: ",
        );
        const repo = loadRepoContext(process.cwd());
        writeConfig({
          apiUrl,
          apiKey,
          project: flags.project ?? repo.vault.project,
          env: flags.env ?? repo.vault.env,
          githubRepo: flags.githubRepo,
        });
        io.log("saved credentials to ~/.config/poc-vault/config.json (mode 0600)");
        return 0;
      }
      case "bootstrap": {
        const apiUrl =
          flags.apiUrl ?? process.env.VAULT_API_URL ?? "http://127.0.0.1:8787";
        const bootstrapToken = await readSecretValue(
          process.env.VAULT_BOOTSTRAP_TOKEN,
          process.stdin,
          process.stdout,
          "Bootstrap token: ",
        );
        const temporary = await new VaultClient(apiUrl, "").bootstrap(
          bootstrapToken,
          "temporary bootstrap key",
        );
        const temporaryClient = new VaultClient(apiUrl, temporary.key);
        const durable = await temporaryClient.createKey({
          type: "user",
          label: flags.label ?? "primary operator",
          expiresInDays: flags.expiresInDays ?? 90,
        });
        await temporaryClient.revokeKey(temporary.prefix);
        const repo = loadRepoContext(process.cwd());
        writeConfig({
          apiUrl,
          apiKey: durable.key,
          project: flags.project ?? repo.vault.project,
          env: flags.env ?? repo.vault.env,
          githubRepo: flags.githubRepo,
        });
        io.log(`bootstrapped; saved operator key ${durable.prefix} (mode 0600)`);
        return 0;
      }
      case "status": {
        const { client, repo, project, env, wranglerEnvironment } = session(flags);
        const report = await collectStatus({
          client,
          repo,
          wrangler: wranglerEnvironment(),
          project,
          env,
        });
        io.log(formatStatus(report).trimEnd());
        return statusFails(report) ? 1 : 0;
      }
      case "projects":
        return runProjects(flags, io);
      case "environments":
      case "envs":
        return runEnvironments(flags, io);
      case "ls":
      case "list":
        flags.rest.unshift("list");
        return runSecrets(flags, io);
      case "get":
        flags.rest.unshift("get");
        return runSecrets(flags, io);
      case "set":
        flags.rest.unshift("set");
        return runSecrets(flags, io);
      case "secrets":
        return runSecrets(flags, io);
      case "keys":
        return runKeys(flags, io);
      case "routes":
        return runRoutes(flags, io);
      case "audit": {
        const page = await session(flags).client.listAudit(
          flags.limit ?? 50,
          flags.cursor,
        );
        for (const event of page.events) io.log(JSON.stringify(event));
        if (page.nextCursor != null) io.log(`next cursor: ${page.nextCursor}`);
        return 0;
      }
      case "master-keys":
        return runMasterKeys(flags, io);
      case "push": {
        const { client, repo, project, env, githubRepo, wranglerEnvironment } =
          session(flags);
        assertProviderPushAllowed(repo.vault.authority);
        const values = await loadVaultValues(client, project, env);
        const githubEnv = repo.vault.github?.env;
        const githubValues =
          githubEnv != null && githubEnv !== env
            ? await loadVaultValues(client, project, githubEnv)
            : values;
        const report = await pushDestinations({
          repo,
          wrangler: wranglerEnvironment(),
          values,
          githubValues,
          githubRepo,
        });
        for (const name of report.cloudflare) io.log(`cloudflare: ${name}`);
        for (const name of report.retired) io.log(`cloudflare: ${name} (retired)`);
        for (const name of report.github) io.log(`github: ${name}`);
        for (const skip of report.skipped) io.log(`skipped ${skip}`);
        if (
          report.cloudflare.length +
            report.retired.length +
            report.github.length +
            report.skipped.length ===
          0
        ) {
          io.log("nothing to push");
        }
        return 0;
      }
      // `return await`, not `return`: a promise returned out of a `try` is not
      // caught by its `catch`, and these two are the commands that now refuse
      // an unresolved Wrangler environment. Without the await that refusal
      // reached the operator as an unhandled rejection and a stack trace.
      case "run":
        return await runInjected(flags);
      case "proxy":
        return await runProxied(flags);
      default:
        throw new Error(`unknown command: ${command}`);
    }
  } catch (error) {
    io.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
}

export function assertProviderPushAllowed(authority: string | undefined): void {
  if (authority != null && authority !== "vault") {
    throw new Error(
      `provider push is disabled while vault.json names another authority (${authority})`,
    );
  }
}

export function initializeLocalVaultAt(
  cwd: string,
  io: { log: (value: string) => void },
): number {
  const varsPath = resolve(cwd, ".dev.vars");
  createPrivateFile(
    varsPath,
    [
      `MASTER_KEY_PRIMARY=${generateMasterKey()}`,
      `MASTER_KEY_SECONDARY=${generateMasterKey()}`,
      `BOOTSTRAP_TOKEN=${randomSecretValue()}`,
      "",
    ].join("\n"),
  );
  const vaultJson = resolve(cwd, "vault.json");
  try {
    writeFileSync(
      vaultJson,
      `${JSON.stringify({ project: "bwf", env: "dev" }, null, 2)}\n`,
      { flag: "wx" },
    );
  } catch (error) {
    if (!isAlreadyExistsError(error)) throw error;
  }
  io.log(`wrote local root credentials to ${varsPath} (mode 0600)`);
  io.log(`vault configuration: ${vaultJson}`);
  return 0;
}

function createPrivateFile(path: string, contents: string): void {
  try {
    writeFileSync(path, contents, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if (isAlreadyExistsError(error)) {
      throw new Error(`${path} already exists`, { cause: error });
    }
    throw error;
  }
}

function isAlreadyExistsError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error && error.code === "EEXIST";
}

async function runProjects(flags: Flags, io: { log: (value: string) => void }) {
  const sub = flags.rest[0] ?? "list";
  const client = session(flags).client;
  if (sub === "list") {
    for (const name of (await client.listProjects()).projects) io.log(name);
    return 0;
  }
  const name = flags.rest[1];
  if (name == null) throw new Error(`usage: vault projects ${sub} NAME`);
  if (sub === "create") {
    io.log((await client.createProject(name)).name);
    return 0;
  }
  if (sub === "delete") {
    requireYes(flags, `deleting project ${name}`);
    await client.deleteProject(name);
    io.log(`deleted project ${name}`);
    return 0;
  }
  throw new Error(`unknown projects command: ${sub}`);
}

async function runEnvironments(flags: Flags, io: { log: (value: string) => void }) {
  const sub = flags.rest[0] ?? "list";
  const { client, project } = session(flags);
  if (sub === "list") {
    for (const name of (await client.listEnvironments(project)).environments)
      io.log(name);
    return 0;
  }
  const name = flags.rest[1];
  if (name == null) throw new Error(`usage: vault environments ${sub} NAME`);
  if (sub === "create") {
    io.log((await client.createEnvironment(project, name)).name);
    return 0;
  }
  if (sub === "delete") {
    requireYes(flags, `deleting environment ${project}/${name}`);
    await client.deleteEnvironment(project, name);
    io.log(`deleted environment ${project}/${name}`);
    return 0;
  }
  throw new Error(`unknown environments command: ${sub}`);
}

async function runSecrets(flags: Flags, io: { log: (value: string) => void }) {
  const sub = flags.rest[0] ?? "list";
  const { client, project, env } = session(flags);
  if (sub === "list") {
    for (const secret of (await client.listSecretMeta(project, env)).secrets) {
      io.log(`${secret.name}\t${secret.kind}`);
    }
    return 0;
  }
  const name = flags.rest[1];
  if (name == null) throw new Error(`usage: vault secrets ${sub} NAME`);
  if (name.includes("=")) {
    throw new Error("inline secret values are not accepted; use hidden input or stdin");
  }
  if (sub === "get") {
    io.log((await client.getSecret(project, env, name)).value);
    return 0;
  }
  if (sub === "set") {
    const kind = enumValue<SecretKind>(
      flags.kind,
      ["config", "secret", "sealed"],
      "secret",
      "--kind",
    );
    await ensureProjectAndEnvironment(client, project, env);
    if (flags.random) {
      await client.patchSecrets(project, env, { set: [{ name, kind, random: true }] });
    } else {
      const value = await readSecretValue(undefined);
      await client.patchSecrets(project, env, { set: [{ name, value, kind }] });
    }
    io.log(name);
    return 0;
  }
  if (sub === "delete") {
    requireYes(flags, `deleting secret ${project}/${env}/${name}`);
    await client.patchSecrets(project, env, { delete: [name] });
    io.log(`deleted ${name}`);
    return 0;
  }
  throw new Error(`unknown secrets command: ${sub}`);
}

async function runKeys(flags: Flags, io: { log: (value: string) => void }) {
  const sub = flags.rest[0] ?? "list";
  const client = session(flags).client;
  if (sub === "list") {
    for (const key of (await client.listKeys(flags.includeRevoked)).keys)
      io.log(JSON.stringify(key));
    return 0;
  }
  if (sub === "create") {
    const type = enumValue<KeyType>(flags.type, ["user", "system"], "system", "--type");
    const permission = enumValue<Permission>(
      flags.permission,
      ["read", "readwrite", "full"],
      type === "user" ? "full" : "read",
      "--permission",
    );
    const mode = enumValue<KeyMode>(flags.mode, ["inject", "broker"], "inject", "--mode");
    const keyOptions: Parameters<VaultClient["createKey"]>[0] = {
      type,
      label: flags.label,
      permission,
      expiresInDays: flags.expiresInDays,
    };
    if (type === "system") {
      keyOptions.mode = mode;
      keyOptions.scopes = parseScopes(flags.scopes);
    }
    const created = await client.createKey(keyOptions);
    io.log(`key ${created.prefix} (shown once): ${created.key}`);
    return 0;
  }
  const prefix = flags.rest[1];
  if (prefix == null) throw new Error(`usage: vault keys ${sub} PREFIX`);
  if (sub === "rotate") {
    const created = await client.rotateKey(prefix, flags.expiresInDays);
    io.log(`key ${created.prefix} (shown once): ${created.key}`);
    return 0;
  }
  if (sub === "revoke") {
    requireYes(flags, `revoking key ${prefix}`);
    await client.revokeKey(prefix);
    io.log(`revoked ${prefix}`);
    return 0;
  }
  throw new Error(`unknown keys command: ${sub}`);
}

async function runRoutes(flags: Flags, io: { log: (value: string) => void }) {
  const sub = flags.rest[0] ?? "list";
  const { client, project, env } = session(flags);
  if (sub === "list") {
    for (const route of (await client.listRoutes(project, env)).routes)
      io.log(JSON.stringify(route));
    return 0;
  }
  if (sub === "put") {
    const secret = flags.rest[1];
    if (secret == null) throw new Error("usage: vault routes put SECRET [options]");
    const routeOptions: Parameters<VaultClient["putRoute"]>[2] = { secret };
    if (flags.preset != null) routeOptions.preset = flags.preset;
    if (flags.host != null) routeOptions.host = flags.host;
    if (flags.header != null) routeOptions.header = flags.header;
    if (flags.dummyEnvName != null) routeOptions.dummyEnvName = flags.dummyEnvName;
    if (flags.dummyValue != null) routeOptions.dummyValue = flags.dummyValue;
    const route = await client.putRoute(project, env, routeOptions);
    io.log(route.host);
    return 0;
  }
  throw new Error(`unknown routes command: ${sub}`);
}

async function runMasterKeys(flags: Flags, io: { log: (value: string) => void }) {
  const sub = flags.rest[0] ?? "status";
  const client = session(flags).client;
  if (sub === "status") {
    const status = await client.listMasterKeys();
    io.log(`active ${status.activeFingerprint}`);
    for (const wrap of status.wraps) io.log(`${wrap.fingerprint}\t${wrap.createdAt}`);
    return 0;
  }
  if (sub === "prepare") {
    io.log(`prepared ${(await client.prepareMasterKey()).fingerprint}`);
    return 0;
  }
  if (sub === "retire") {
    const fingerprint = flags.rest[1];
    if (fingerprint == null)
      throw new Error("usage: vault master-keys retire FINGERPRINT --yes");
    requireYes(flags, `retiring master-key wrap ${fingerprint}`);
    await client.retireMasterKey(fingerprint);
    io.log(`retired ${fingerprint}`);
    return 0;
  }
  throw new Error(`unknown master-keys command: ${sub}`);
}

async function runInjected(flags: Flags): Promise<number> {
  const { client, cwd, project, env } = session(flags);
  if (flags.rest.length === 0) throw new Error("usage: vault run -- CMD");
  // One resolver for `vault run` and the Vite plugin. Two of them drifted once
  // already: only this one rejected an empty value.
  const injectOptions: Parameters<typeof loadRequiredSecretValues>[0] = {
    cwd,
    client,
    project,
    env,
  };
  if (flags.wranglerEnv != null) injectOptions.wranglerEnv = flags.wranglerEnv;
  const injected = await loadRequiredSecretValues(injectOptions);
  return spawnCommand(flags.rest, {
    ...process.env,
    ...injected,
    VAULT_API_KEY: undefined,
  });
}

async function runProxied(flags: Flags): Promise<number> {
  const { client, project, env } = session(flags);
  if (flags.rest.length === 0) throw new Error("usage: vault proxy -- CMD");
  const listed = await client.exportSecrets(project, env);
  const secrets = listed.secrets.map((secret) => ({
    name: secret.name,
    kind: secret.kind,
    value: secret.value ?? "",
  }));
  const routes = (await client.listRoutes(project, env)).routes;
  const handle = await startProxy({ secrets, routes });
  try {
    return await spawnCommand(flags.rest, proxyChildEnv(handle, process.env));
  } finally {
    await handle.stop();
  }
}

function spawnCommand(argv: string[], env: ProcessEnvironment): Promise<number> {
  const [command, ...args] = argv;
  if (command == null) return Promise.resolve(1);
  return new Promise((finish) => {
    const child = spawn(command, args, {
      // SAFETY: spawn accepts string environment entries; generated Worker declarations
      // add required vault bindings to ProcessEnv that a child process does not need.
      env: env as NodeJS.ProcessEnv,
      stdio: "inherit",
    });
    child.on("exit", (code) => {
      finish(code ?? 1);
    });
    child.on("error", () => {
      finish(1);
    });
  });
}

function helpText(): string {
  return `vault

  vault bootstrap --api-url URL [--label LABEL] [--expires-in-days 90]
  vault login --api-url URL                 # hidden API-key prompt
  vault status
  vault projects list|create NAME|delete NAME --yes
  vault environments list|create NAME|delete NAME --yes
  vault secrets list|get NAME|set NAME [--kind config|secret|sealed] [--random]
  vault secrets delete NAME --yes
  vault keys list [--include-revoked]
  vault keys create --type system --scope PROJECT/ENV [--mode inject|broker]
  vault keys rotate PREFIX | revoke PREFIX --yes
  vault routes list | put SECRET --preset NAME
  vault audit [--limit N] [--cursor CURSOR]
  vault master-keys status|prepare|retire FINGERPRINT --yes
  vault run [--wrangler-env NAME] -- CMD    # injects only secrets.required
  vault proxy -- CMD
  vault push                               # explicit provider synchronization
  vault issuance setup                     # guided identity and member setup
  vault issuance connect cloudflare         # discover and register a Cloudflare token
  vault issuance login --api-url URL       # GitHub member login and tenant selection
  vault issuance mcp                       # AI provisioning and scoped-token tools
  vault issuance admin | inspect REQUEST_ID | logout
  vault issuance [COMMAND] --help          # setup, approval flow, and tool reference
  vault init                               # local development only

Secret values and login/bootstrap credentials are read from hidden input or stdin.
VAULT_API_URL, VAULT_API_KEY, and VAULT_BOOTSTRAP_TOKEN are supported environment inputs.

Shared issuers can provision Cloudflare services or create tokens after browser
approval. AI uses Vault references; provider values stay in Vault. Project-secret
commands use operator/system keys; issuance uses a separate tenant member session.

Documentation: https://vault.buildwithfriends.dev/reference/cli/`;
}

if (import.meta.main) {
  void runCli(process.argv.slice(2)).then((code) => process.exit(code));
}
