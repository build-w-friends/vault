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
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";

import { serveAgentMcp } from "./agent/cli.ts";
import { runIssuanceCli } from "./issuance/cli.ts";
import { VaultClient } from "./client.ts";
import { resolveClientOptions, writeConfig } from "./config.ts";
import { generateMasterKey } from "./crypto.ts";
import { randomSecretValue } from "./keys.ts";
import { readSecretValue } from "./prompt.ts";
import * as v from "valibot";
import { collectionTargetSchema } from "./collection-contract.ts";
import { startSecretCollection, openCollectionBrowser } from "./collection.ts";
import { proxyChildEnv, startProxy } from "./proxy.ts";
import { loadRequiredSecretValues } from "./inject.ts";
import { loadVaultValues, pushDestinations } from "./push.ts";
import { loadRepoContext, resolveWranglerEnvironment } from "./repo-config.ts";
import { collectStatus, formatStatus, statusFails } from "./status.ts";
import type {
  KeyMode,
  KeyType,
  Permission,
  ProcessEnvironment,
  Scope,
  SecretKind,
} from "./types.ts";

const options = {
  "api-url": { type: "string" },
  project: { type: "string" },
  env: { type: "string" },
  "github-repo": { type: "string" },
  "wrangler-env": { type: "string" },
  label: { type: "string" },
  type: { type: "string" },
  permission: { type: "string" },
  mode: { type: "string" },
  kind: { type: "string" },
  preset: { type: "string" },
  host: { type: "string" },
  header: { type: "string" },
  "dummy-env": { type: "string" },
  "dummy-value": { type: "string" },
  cursor: { type: "string" },
  scope: { type: "string", multiple: true },
  "expires-in-days": { type: "string" },
  limit: { type: "string" },
  yes: { type: "boolean" },
  random: { type: "boolean" },
  "include-revoked": { type: "boolean" },
} as const;
const optionTypes = new Map<string, string>(
  Object.entries(options).map(([name, option]) => [name, option.type]),
);

type Flags = ReturnType<typeof parseArgv>["flags"];

/**
 * The first argument is the command unless it starts with `-`. Known options
 * may appear anywhere before `--`; everything else (positionals and unknown
 * options, verbatim) lands in `rest` for the subcommand, and `--` replaces
 * `rest` with the arguments after it.
 */
export function parseArgv(argv: string[]) {
  const first = argv[0];
  const command = first != null && !first.startsWith("-") ? first : null;
  const args = command == null ? argv : argv.slice(1);
  const { tokens } = parseArgs({
    args,
    options,
    strict: false,
    allowPositionals: true,
    tokens: true,
  });
  let rest: string[] = [];
  let lastIndex = -1;
  const seen = new Map<string, string[]>();
  for (const token of tokens) {
    if (token.kind === "option-terminator") {
      rest = args.slice(token.index + 1);
      break;
    }
    if (token.kind === "option" && token.name === "api-key") {
      throw new Error("--api-key is not accepted; use VAULT_API_KEY or hidden input");
    }
    const type = token.kind === "option" ? optionTypes.get(token.name) : undefined;
    if (token.kind === "option" && type != null) {
      const value = token.value;
      if (token.name === "expires-in-days" || token.name === "limit") {
        if (value == null || !/^\d+$/u.test(value)) {
          throw new Error(`${token.rawName} requires a positive integer`);
        }
      } else if (token.name === "scope" && value == null) {
        throw new Error("--scope requires PROJECT/ENV");
      } else if (type === "string" && value == null) {
        throw new Error(`${token.rawName} requires a value`);
      }
      if (type === "boolean" && value != null) continue;
      seen.set(token.name, [...(seen.get(token.name) ?? []), value ?? ""]);
      continue;
    }
    // A short-option group such as `-abc` yields one token per letter.
    if (token.index !== lastIndex) rest.push(args[token.index]!);
    lastIndex = token.index;
  }
  const text = (name: keyof typeof options) => seen.get(name)?.at(-1);
  const integer = (name: "expires-in-days" | "limit") => {
    const value = text(name);
    return value == null ? undefined : Number(value);
  };
  return {
    command: command ?? "help",
    flags: {
      apiUrl: text("api-url"),
      project: text("project"),
      env: text("env"),
      githubRepo: text("github-repo"),
      wranglerEnv: text("wrangler-env"),
      label: text("label"),
      type: text("type"),
      permission: text("permission"),
      mode: text("mode"),
      kind: text("kind"),
      preset: text("preset"),
      host: text("host"),
      header: text("header"),
      dummyEnvName: text("dummy-env"),
      dummyValue: text("dummy-value"),
      cursor: text("cursor"),
      scopes: seen.get("scope") ?? [],
      expiresInDays: integer("expires-in-days"),
      limit: integer("limit"),
      yes: seen.has("yes"),
      random: seen.has("random"),
      includeRevoked: seen.has("include-revoked"),
      rest,
    },
  };
}

function session(flags: Flags, cwd = process.cwd()) {
  const repo = loadRepoContext(cwd);
  // Precedence: flag, vault.json, VAULT_PROJECT/VAULT_ENV, stored config, default.
  const resolved = resolveClientOptions({
    apiUrl: flags.apiUrl,
    project: flags.project ?? repo.vault.project,
    env: flags.env ?? repo.vault.env,
  });
  const project = resolved.project ?? "bwf";
  const env = resolved.env ?? "dev";
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
    wranglerEnvironment: () =>
      resolveWranglerEnvironment(repo, { vaultEnv: env, wranglerEnv: flags.wranglerEnv }),
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

const DEFAULT_CLI_IO = { log: console.log, error: console.error };

export async function runCli(argv: string[], io = DEFAULT_CLI_IO): Promise<number> {
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
      case "mcp": {
        if (flags.rest.includes("--help") || flags.rest.includes("-h")) {
          io.log(
            "vault mcp [--project PROJECT --env ENV]\n\nLocal MCP: describe_context, collect_secret, connect_cloudflare, request_github_access, get_task, cancel_task, read_provider. Uses the operator login; no secret values in tool inputs or receipts. Supports URL elicitation and the MCP Tasks extension. Reuse request IDs to resume. Cloudflare needs VAULT_CLOUDFLARE_OAUTH configuration; GitHub needs VAULT_GITHUB_APP. See https://vault.buildwithfriends.dev/reference/mcp/.",
          );
          return 0;
        }
        const { client, project, env } = session(flags);
        await serveAgentMcp(client, project, env);
        return 0;
      }
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
        return await runProjects(flags, io);
      case "environments":
      case "envs":
        return await runEnvironments(flags, io);
      case "ls":
      case "list":
        flags.rest.unshift("list");
        return await runSecrets(flags, io);
      case "get":
        flags.rest.unshift("get");
        return await runSecrets(flags, io);
      case "set":
        flags.rest.unshift("set");
        return await runSecrets(flags, io);
      case "secrets":
        return await runSecrets(flags, io);
      case "keys":
        return await runKeys(flags, io);
      case "routes":
        return await runRoutes(flags, io);
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
        return await runMasterKeys(flags, io);
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
    const projects = await client.listProjects();
    for (const name of projects.projects) io.log(name);
    return 0;
  }
  const name = flags.rest[1];
  if (name == null) throw new Error(`usage: vault projects ${sub} NAME`);
  if (sub === "create") {
    const created = await client.createProject(name);
    io.log(created.name);
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
    const environments = await client.listEnvironments(project);
    for (const name of environments.environments) io.log(name);
    return 0;
  }
  const name = flags.rest[1];
  if (name == null) throw new Error(`usage: vault environments ${sub} NAME`);
  if (sub === "create") {
    const createdEnvironment = await client.createEnvironment(project, name);
    io.log(createdEnvironment.name);
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
  if (sub === "collect" && (flags.rest.includes("--help") || flags.rest.includes("-h"))) {
    io.log(
      "vault secrets collect NAME [--project PROJECT --env ENV] [--kind secret|sealed]\n\nAgents: run this command yourself when a required user-supplied secret is missing. Tell the user the form is ready and wait for the receipt; do not give them a command or ask for the value in chat. Opens a local browser form using your operator login. Enter the value in the browser, never in chat or command arguments. Creates one missing secret in an existing environment; never replaces a value. Waits up to ten minutes. Returns a JSON receipt without the secret. An unknown result must be inspected, not retried automatically. Requires the create-only Vault API.",
    );
    return 0;
  }
  const { client, project, env } = session(flags);
  if (sub === "list") {
    const meta = await client.listSecretMeta(project, env);
    for (const secret of meta.secrets) {
      io.log(`${secret.name}\t${secret.kind}`);
    }
    return 0;
  }
  const name = flags.rest[1];
  if (name == null) throw new Error(`usage: vault secrets ${sub} NAME`);
  if (name.includes("=")) {
    throw new Error("inline secret values are not accepted; use hidden input or stdin");
  }
  if (sub === "collect") {
    if (flags.rest.length !== 2 || flags.random || flags.yes)
      throw new Error(
        "usage: vault secrets collect NAME [--kind secret|sealed] [--project PROJECT --env ENV]",
      );
    const parsed = v.safeParse(collectionTargetSchema, {
      project,
      env,
      name,
      kind: flags.kind ?? "secret",
    });
    if (!parsed.success)
      throw new Error(
        "invalid collection destination or kind; use a secret name and kind secret or sealed",
      );
    const target = parsed.output;
    const meta = await client.listSecretMeta(project, env);
    if (meta.secrets.some((secret) => secret.name === name))
      throw new Error("secret already exists; collection never replaces a value");
    const collection = startSecretCollection({
      target,
      vaultOrigin: client.apiUrl,
      save: (value) => client.createCollectedSecret(target, value),
    });
    const interrupt = () => {
      void collection.stop();
    };
    process.once("SIGINT", interrupt);
    process.once("SIGTERM", interrupt);
    try {
      io.log(`Open this local Vault page to enter the secret: ${collection.url}`);
      if (!(await openCollectionBrowser(collection.url)))
        io.log("The browser could not be opened. Open the URL above on this machine.");
      const receipt = await collection.completed;
      io.log(JSON.stringify(receipt));
      // Keep the HTTP response alive long enough for the browser to render its receipt.
      await new Promise((done) => setTimeout(done, 1000));
      return receipt.state === "stored" ? 0 : 1;
    } finally {
      process.off("SIGINT", interrupt);
      process.off("SIGTERM", interrupt);
      await collection.stop();
    }
  }
  if (sub === "get") {
    const secret = await client.getSecret(project, env, name);
    io.log(secret.value);
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
    const keyList = await client.listKeys(flags.includeRevoked);
    for (const key of keyList.keys) io.log(JSON.stringify(key));
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
    const keyOptions: Parameters<typeof client.createKey>[0] = {
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
    const routeList = await client.listRoutes(project, env);
    for (const route of routeList.routes) io.log(JSON.stringify(route));
    return 0;
  }
  if (sub === "put") {
    const secret = flags.rest[1];
    if (secret == null) throw new Error("usage: vault routes put SECRET [options]");
    const route = await client.putRoute(project, env, {
      secret,
      preset: flags.preset,
      host: flags.host,
      header: flags.header,
      dummyEnvName: flags.dummyEnvName,
      dummyValue: flags.dummyValue,
    });
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
    const prepared = await client.prepareMasterKey();
    io.log(`prepared ${prepared.fingerprint}`);
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
  const injected = await loadRequiredSecretValues({
    cwd,
    client,
    project,
    env,
    wranglerEnv: flags.wranglerEnv,
  });
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
  const routeList = await client.listRoutes(project, env);
  const routes = routeList.routes;
  const handle = await startProxy({ secrets, routes });
  try {
    return await spawnCommand(flags.rest, proxyChildEnv(handle, process.env));
  } finally {
    await handle.stop();
  }
}

/** The child's exit code; 1 when it cannot start or is killed by a signal. */
async function spawnCommand(argv: string[], env: ProcessEnvironment): Promise<number> {
  try {
    const child = Bun.spawn(argv, { env, stdio: ["inherit", "inherit", "inherit"] });
    await child.exited;
    return child.exitCode ?? 1;
  } catch {
    return 1;
  }
}

function helpText(): string {
  return `vault

  vault bootstrap --api-url URL [--label LABEL] [--expires-in-days 90]
  vault login --api-url URL                 # hidden API-key prompt
  vault status
  vault mcp                                # local secret prompts and provider access
  vault projects list|create NAME|delete NAME --yes
  vault environments list|create NAME|delete NAME --yes
  vault secrets list|get NAME|set NAME [--kind config|secret|sealed] [--random]
  vault secrets delete NAME --yes
  vault secrets collect NAME [--kind secret|sealed] # browser entry; create only
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

Agents: when a user-supplied secret is missing, run secrets collect yourself on
the operator's machine, tell the user the form is ready, and wait for its receipt.
Do not ask for the value in chat or hand the user a command. Inspect names first;
continue only after stored. Cancelled/expired stops; unknown requires inspection.
See vault secrets collect --help. Existing interactive secrets set stays available.

Secret values and login/bootstrap credentials are read from hidden input or stdin.
VAULT_API_URL, VAULT_API_KEY, and VAULT_BOOTSTRAP_TOKEN are supported environment inputs.

Shared issuers can provision Cloudflare services or create tokens after browser
approval. AI uses Vault references; provider values stay in Vault. Project-secret
commands use operator/system keys; issuance uses a separate tenant member session.

Documentation: https://vault.buildwithfriends.dev/reference/cli/`;
}

if (import.meta.main) process.exit(await runCli(process.argv.slice(2)));
