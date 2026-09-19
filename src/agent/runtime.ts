import * as v from "valibot";
import { z } from "zod";
import { VaultClient } from "../client.ts";
import { startSecretCollection } from "../collection.ts";
import { AgentTasks } from "./tasks.ts";
import { cloudflareHandoff, githubHandoff } from "./handoff.ts";
import {
  cloudflareConfigSchema,
  cloudflareAccessSchema,
  githubAccess,
  githubAccessSchema,
  providerJson,
} from "./provider.ts";

export class AgentRuntime {
  private closing = false;
  private readonly active = new Map<
    string,
    { stop: () => Promise<void>; timer: ReturnType<typeof setTimeout> }
  >();
  constructor(
    readonly client: VaultClient,
    readonly project: string,
    readonly env: string,
    readonly tasks: AgentTasks,
    private readonly send: typeof fetch = fetch,
  ) {}
  private target(name: string) {
    return { project: this.project, env: this.env, name, kind: "secret" as const };
  }
  private hold(taskId: string, handle: { url: string; stop: () => Promise<void> }) {
    this.tasks.transition(taskId, "waiting", "waiting", handle.url);
    const timer = setTimeout(() => {
      void handle.stop();
      this.active.delete(taskId);
      this.tasks.get(taskId);
    }, 600000);
    this.active.set(taskId, { stop: handle.stop, timer });
  }
  async context() {
    const meta = await this.client.listSecretMeta(this.project, this.env);
    const names = new Set(meta.secrets.map((secret) => secret.name));
    return {
      project: this.project,
      env: this.env,
      secrets: meta.secrets.map(({ name, kind }) => ({ name, kind })),
      cloudflareConfigured: names.has("VAULT_CLOUDFLARE_OAUTH"),
      githubConfigured: names.has("VAULT_GITHUB_APP"),
      message:
        "Collect missing values through collect_secret. Provider configuration stays in Vault. Provider access is referenced by task ID, never returned as a token.",
    };
  }
  async collect(taskId: string, name: string) {
    const { created, task } = this.tasks.create(taskId, "collection", name);
    if (!created && !this.tasks.reclaim(task.taskId)) return task;
    taskId = task.taskId;
    try {
      const meta = await this.client.listSecretMeta(this.project, this.env);
      if (meta.secrets.some((secret) => secret.name === name))
        return this.tasks.transition(taskId, "waiting", "conflict");
      const helper = startSecretCollection({
        target: this.target(name),
        vaultOrigin: this.client.apiUrl,
        save: async (value) => {
          if (!this.tasks.claim(taskId)) throw new Error("Task is no longer waiting");
          await this.client.createCollectedSecret(this.target(name), value);
        },
      });
      this.hold(taskId, helper);
      void helper.completed.then((receipt) => {
        if (this.closing) return;
        const current = this.tasks.get(taskId);
        if (current.state === "waiting" || current.state === "saving")
          this.tasks.transition(taskId, current.state, receipt.state);
      });
      return this.tasks.get(taskId);
    } catch {
      return this.tasks.transition(taskId, "waiting", "unknown");
    }
  }
  async connectCloudflare(taskId: string) {
    const name = `CF_CONNECTION_${taskId.replaceAll("-", "_")}`;
    const { created, task } = this.tasks.create(taskId, "cloudflare", name);
    if (!created && !this.tasks.reclaim(task.taskId)) return task;
    taskId = task.taskId;
    try {
      const config = v.parse(
        cloudflareConfigSchema,
        JSON.parse(
          (await this.client.getSecret(this.project, this.env, "VAULT_CLOUDFLARE_OAUTH"))
            .value,
        ),
      );
      const handle = cloudflareHandoff({
        tasks: this.tasks,
        taskId,
        config,
        send: this.send,
        save: (value) => this.client.createCollectedSecret(this.target(name), value),
      });
      this.hold(taskId, handle);
      return this.tasks.get(taskId);
    } catch {
      return this.tasks.transition(taskId, "waiting", "unknown");
    }
  }
  async requestGithub(taskId: string, repository: string) {
    const { created, task } = this.tasks.create(taskId, "github", repository);
    if (!created && !this.tasks.reclaim(task.taskId)) return task;
    taskId = task.taskId;
    try {
      // Check only metadata before asking for consent; the key stays in the trusted host.
      const meta = await this.client.listSecretMeta(this.project, this.env);
      if (!meta.secrets.some((secret) => secret.name === "VAULT_GITHUB_APP"))
        throw new Error("GitHub App is not configured");
      const handle = githubHandoff({
        tasks: this.tasks,
        taskId,
        repository,
        save: async () => {
          const config = (
            await this.client.getSecret(this.project, this.env, "VAULT_GITHUB_APP")
          ).value;
          const access = await githubAccess(config, repository, this.send);
          await this.client.createCollectedSecret(
            this.target(`GH_ACCESS_${taskId.replaceAll("-", "_")}`),
            JSON.stringify(access),
          );
        },
      });
      this.hold(taskId, handle);
      return this.tasks.get(taskId);
    } catch {
      return this.tasks.transition(taskId, "waiting", "unknown");
    }
  }
  async readProvider(taskId: string, path: string) {
    const task = this.tasks.get(taskId);
    taskId = task.taskId;
    if (task.state !== "stored") throw new Error("Provider access is not ready");
    let token: string;
    let origin: string;
    if (task.kind === "github") {
      if (path !== `/repos/${task.target}` && !path.startsWith(`/repos/${task.target}/`))
        throw new Error("Path is outside the approved repository");
      const access = v.parse(
        githubAccessSchema,
        JSON.parse(
          (
            await this.client.getSecret(
              this.project,
              this.env,
              `GH_ACCESS_${taskId.replaceAll("-", "_")}`,
            )
          ).value,
        ),
      );
      if (access.repository !== task.target || access.expiresAt <= Date.now())
        throw new Error("GitHub access expired; request new access");
      token = access.token;
      origin = "https://api.github.com";
    } else if (task.kind === "cloudflare") {
      if (!/^\/client\/v4\/(accounts|zones)(?:\/|$)/u.test(path))
        throw new Error("Use a Cloudflare accounts or zones API path");
      const access = v.parse(
        cloudflareAccessSchema,
        JSON.parse(
          (await this.client.getSecret(this.project, this.env, task.target)).value,
        ),
      );
      if (access.expiresAt <= Date.now())
        throw new Error("Cloudflare connection expired; reconnect");
      token = access.accessToken;
      origin = "https://api.cloudflare.com";
    } else throw new Error("This task is not provider access");
    if (
      path.includes("%") ||
      path.includes("\\") ||
      path.split(/[/?]/u).some((part) => part === "." || part === "..") ||
      path.includes("#")
    )
      throw new Error("Invalid provider path");
    const response = await this.send(origin + path, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
        "User-Agent": "Vault",
        "X-GitHub-Api-Version": "2026-03-10",
      },
      redirect: "error",
      signal: AbortSignal.timeout(30000),
    });
    const body = await providerJson(response);
    // The trusted proxy never reflects its injected bearer, including upstream echoes.
    return z
      .json()
      .parse(JSON.parse(JSON.stringify(body).replaceAll(token, "[redacted]")));
  }
  async cancel(taskId: string) {
    const current = this.tasks.get(taskId);
    taskId = current.taskId;
    if (current.state === "waiting")
      this.tasks.transition(taskId, "waiting", "cancelled");
    const active = this.active.get(taskId);
    if (active && current.state === "waiting") {
      clearTimeout(active.timer);
      await active.stop();
      this.active.delete(taskId);
    }
    return this.tasks.get(taskId);
  }
  async resume(taskId: string) {
    const task = this.tasks.get(taskId);
    if (task.state !== "waiting" || task.url) return task;
    if (task.kind === "collection") return this.collect(task.requestId, task.target);
    if (task.kind === "github") return this.requestGithub(task.requestId, task.target);
    return this.connectCloudflare(task.requestId);
  }
  async close() {
    this.closing = true;
    for (const [taskId, active] of this.active) {
      clearTimeout(active.timer);
      this.tasks.release(taskId);
      await active.stop();
    }
    this.active.clear();
  }
}
