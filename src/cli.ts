#!/usr/bin/env bun
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { VaultClient } from "./client.ts";
import { resolveClientOptions, writeConfig } from "./config.ts";
import { generateMasterKey } from "./crypto.ts";
import { readSecretValue } from "./prompt.ts";
import { proxyChildEnv, startProxy } from "./proxy.ts";
import { loadVaultValues, pushDestinations } from "./push.ts";
import { collectStatus, formatStatus, statusFails } from "./status.ts";
import { loadRepoContext } from "./repo-config.ts";
import type { SecretKind } from "./types.ts";

type Flags = {
  apiUrl?: string;
  apiKey?: string;
  project?: string;
  env?: string;
  githubRepo?: string;
  rest: string[];
};

export function parseArgv(argv: string[]): { command: string; flags: Flags } {
  const rest: string[] = [];
  const flags: Flags = { rest };
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
    const next = argv[i + 1];
    if (token === "--api-url" && next != null) {
      flags.apiUrl = next;
      i += 2;
      continue;
    }
    if (token === "--api-key" && next != null) {
      flags.apiKey = next;
      i += 2;
      continue;
    }
    if (token === "--project" && next != null) {
      flags.project = next;
      i += 2;
      continue;
    }
    if (token === "--env" && next != null) {
      flags.env = next;
      i += 2;
      continue;
    }
    if (token === "--github-repo" && next != null) {
      flags.githubRepo = next;
      i += 2;
      continue;
    }
    rest.push(token);
    i += 1;
  }
  return { command, flags };
}

function session(flags: Flags, cwd = process.cwd()) {
  const repo = loadRepoContext(cwd);
  const resolved = resolveClientOptions({
    ...flags,
    project: flags.project ?? repo.vault.project,
    env: flags.env ?? repo.vault.env,
  });
  const project = resolved.project ?? repo.vault.project ?? "bwf";
  const env = resolved.env ?? repo.vault.env ?? "dev";
  return {
    repo,
    client: new VaultClient(resolved.apiUrl, resolved.apiKey),
    project,
    env,
    apiUrl: resolved.apiUrl,
    githubRepo: resolved.githubRepo,
  };
}

async function ensureProject(client: VaultClient, name: string): Promise<void> {
  const listed = await client.listProjects();
  if (!listed.projects.includes(name.toLowerCase())) {
    await client.createProject(name);
  }
}

export async function runCli(
  argv: string[],
  io = { log: console.log, error: console.error },
): Promise<number> {
  const { command, flags } = parseArgv(argv);
  try {
    switch (command) {
      case "help":
      case "-h":
      case "--help":
        io.log(helpText());
        return 0;
      case "init": {
        const key = generateMasterKey();
        const path = resolve(process.cwd(), ".dev.vars");
        writeFileSync(path, `MASTER_KEY=${key}\n`);
        const vaultJson = resolve(process.cwd(), "vault.json");
        writeFileSync(
          vaultJson,
          `${JSON.stringify({ project: "bwf", env: "dev" }, null, 2)}\n`,
        );
        io.log(`wrote MASTER_KEY to ${path}`);
        io.log(`wrote ${vaultJson}`);
        io.log(
          "run: bunx wrangler d1 migrations apply poc-vault --local && bunx wrangler dev",
        );
        io.log("then: vault bootstrap && vault login --api-url URL --api-key KEY");
        return 0;
      }
      case "login": {
        const apiUrl = flags.apiUrl ?? flags.rest[0];
        const apiKey = flags.apiKey ?? flags.rest[1];
        if (apiUrl == null || apiKey == null)
          throw new Error("usage: vault login --api-url URL --api-key KEY");
        const repo = loadRepoContext(process.cwd());
        writeConfig({
          apiUrl,
          apiKey,
          project: flags.project ?? repo.vault.project,
          env: flags.env ?? repo.vault.env,
          githubRepo: flags.githubRepo,
        });
        io.log("saved credentials to ~/.config/poc-vault/config.json");
        return 0;
      }
      case "bootstrap": {
        const apiUrl =
          flags.apiUrl ?? process.env.VAULT_API_URL ?? "http://127.0.0.1:8787";
        const created = await new VaultClient(apiUrl, "").bootstrap("bootstrap");
        writeConfig({
          apiUrl,
          apiKey: created.key,
          ...(flags.project != null ? { project: flags.project } : {}),
          ...(flags.env != null ? { env: flags.env } : {}),
        });
        io.log(`bootstrap key (shown once): ${created.key}`);
        return 0;
      }
      case "status": {
        const { client, repo, project, env } = session(flags);
        const report = await collectStatus({ client, repo, project, env });
        io.log(formatStatus(report).trimEnd());
        return statusFails(report) ? 1 : 0;
      }
      case "ls":
      case "list": {
        const { client, project, env } = session(flags);
        const listed = await client.listSecretMeta(project, env);
        for (const secret of listed.secrets) io.log(`${secret.name}\t${secret.kind}`);
        return 0;
      }
      case "get": {
        const name = flags.rest[0];
        if (name == null) throw new Error("usage: vault get NAME");
        const { client, project, env } = session(flags);
        const secret = await client.getSecret(project, env, name);
        io.log(secret.value);
        return 0;
      }
      case "set": {
        const pair = flags.rest[0];
        if (pair == null)
          throw new Error("usage: vault set NAME  or  vault set NAME=value");
        const config = flags.rest.includes("--config");
        const eq = pair.indexOf("=");
        const name = eq === -1 ? pair : pair.slice(0, eq);
        const inline = eq === -1 ? undefined : pair.slice(eq + 1);
        const value = await readSecretValue(inline);
        const kind: SecretKind = config ? "config" : "sealed";
        const { client, repo, project, env, githubRepo } = session(flags);
        await ensureProject(client, project);
        await client.patchSecrets(project, env, { set: [{ name, value, kind }] });
        io.log(name);
        if (env === "prod") {
          const values = await loadVaultValues(client, project, env);
          const report = await pushDestinations({
            repo,
            values,
            names: [name],
            githubRepo,
          });
          if (report.cloudflare.length > 0)
            io.log(`cloudflare: ${report.cloudflare.join(", ")}`);
          if (report.github.length > 0) io.log(`github: ${report.github.join(", ")}`);
          for (const skip of report.skipped) io.log(`skipped ${skip}`);
        }
        return 0;
      }
      case "push": {
        const { client, repo, project, env, githubRepo } = session(flags);
        const values = await loadVaultValues(client, project, env);
        const report = await pushDestinations({ repo, values, githubRepo });
        if (report.cloudflare.length > 0)
          io.log(`cloudflare: ${report.cloudflare.join(", ")}`);
        if (report.github.length > 0) io.log(`github: ${report.github.join(", ")}`);
        for (const skip of report.skipped) io.log(`skipped ${skip}`);
        if (
          report.cloudflare.length === 0 &&
          report.github.length === 0 &&
          report.skipped.length === 0
        ) {
          io.log("nothing to push");
        }
        return 0;
      }
      case "projects": {
        const sub = flags.rest[0] ?? "list";
        const api = session(flags).client;
        if (sub === "list") {
          io.log((await api.listProjects()).projects.join("\n"));
          return 0;
        }
        if (sub === "create") {
          const name = flags.rest[1];
          if (name == null) throw new Error("usage: vault projects create NAME");
          io.log((await api.createProject(name)).name);
          return 0;
        }
        throw new Error(`unknown projects command: ${sub}`);
      }
      case "secrets": {
        const sub = flags.rest[0] ?? "list";
        if (sub === "list") return runCli(["ls", ...argv.slice(2)], io);
        if (sub === "get") return runCli(["get", ...flags.rest.slice(1)], io);
        if (sub === "set") {
          const pair = flags.rest[1];
          const extra = flags.rest.includes("--type")
            ? flags.rest.includes("config")
              ? ["--config"]
              : []
            : [];
          return runCli(["set", pair ?? "", ...extra], io);
        }
        throw new Error(`unknown secrets command: ${sub}`);
      }
      case "run": {
        const { client, project, env } = session(flags);
        if (flags.rest.length === 0) throw new Error("usage: vault run -- CMD");
        const listed = await client.exportSecrets(project, env);
        const injected: Record<string, string> = {};
        for (const secret of listed.secrets) {
          if (secret.value != null) injected[secret.name] = secret.value;
        }
        return await spawnCommand(flags.rest, {
          ...process.env,
          ...injected,
          VAULT_API_KEY: undefined,
        });
      }
      case "proxy": {
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
      default:
        io.error(`unknown command: ${command}`);
        return 1;
    }
  } catch (error) {
    io.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
}

function spawnCommand(argv: string[], env: NodeJS.ProcessEnv): Promise<number> {
  const [command, ...args] = argv;
  if (command == null) return Promise.resolve(1);
  return new Promise((finish) => {
    const child = spawn(command, args, { env, stdio: "inherit" });
    child.on("exit", (code) => finish(code ?? 1));
    child.on("error", () => finish(1));
  });
}

function helpText(): string {
  return `vault

  vault login --api-url URL --api-key KEY [--github-repo OWNER/REPO]
  vault status
  vault ls
  vault set NAME                 # sealed; prompts for value
  vault set NAME --config
  vault get NAME
  vault push                     # Cloudflare Worker + GitHub Actions
  vault init
`;
}

if (import.meta.main) {
  void runCli(process.argv.slice(2)).then((code) => process.exit(code));
}
