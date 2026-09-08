/**
 * `vault status` — comparing required names against three sources.
 *
 * Vault is compared against the selected Wrangler environment's
 * `secrets.required` list in the session vault environment, and against the
 * GitHub destination's names in that destination's own environment
 * (`github.env`), because the runtime and CI names live in different
 * environments. Cloudflare and GitHub are compared against what each provider
 * actually holds. The caller resolves the Wrangler environment, so an
 * environment-scoped Worker is never checked against the top-level list —
 * that under-reports, and a genuinely missing production secret then reads as
 * healthy.
 *
 * A provider with no token in the environment reports `skipped`, which is
 * deliberately not `ok`. The distinction is the whole point of the command: a
 * check that did not run has proven nothing, and collapsing the two states is
 * how a green status starts covering a missing secret.
 *
 * @see {@link https://vault.buildwithfriends.dev/start/daily-use/}
 */
import type { VaultClient } from "./client.ts";
import { cloudflareTokenFromEnv, listCloudflareSecretNames } from "./push-cloudflare.ts";
import { githubTokenFromEnv, listGithubSecretNames } from "./push-github.ts";
import type { RepoContext, WranglerEnvironmentConfig } from "./repo-config.ts";
import type { ProcessEnvironment } from "./types.ts";

export type StatusReport = {
  vaultMissing: string[];
  cloudflareMissing: string[] | "skipped";
  githubMissing: string[] | "skipped";
};

export function missingNames(required: string[], present: string[]): string[] {
  const held = new Set(present);
  return required.filter((name) => !held.has(name));
}

export async function collectStatus(input: {
  client: VaultClient;
  repo: RepoContext;
  wrangler: WranglerEnvironmentConfig | null;
  project: string;
  env: string;
  processEnv?: ProcessEnvironment;
  fetchImpl?: import("./push-cloudflare.ts").FetchLike;
}): Promise<StatusReport> {
  const processEnv = input.processEnv ?? process.env;
  const fetchImpl = input.fetchImpl ?? fetch;
  const wrangler = input.wrangler;
  const required = wrangler?.required ?? [];
  const vaultMeta = await input.client.listSecretMeta(input.project, input.env);
  const vaultNames = new Set(vaultMeta.secrets.map((secret) => secret.name));
  const github = input.repo.vault.github;
  const githubSourceEnv = github?.env ?? input.env;
  let githubSourceNames = vaultNames;
  if (github != null && githubSourceEnv !== input.env) {
    const githubMeta = await input.client.listSecretMeta(input.project, githubSourceEnv);
    githubSourceNames = new Set(githubMeta.secrets.map((secret) => secret.name));
  }
  const vaultMissing = [
    ...new Set([
      ...missingNames(required, [...vaultNames]),
      ...missingNames(github?.secrets ?? [], [...githubSourceNames]),
    ]),
  ];

  let cloudflareMissing: string[] | "skipped" = "skipped";
  const cfToken = cloudflareTokenFromEnv(processEnv);
  if (cfToken != null && wrangler?.accountId != null && wrangler.name != null) {
    const present = await listCloudflareSecretNames(
      {
        accountId: wrangler.accountId,
        scriptName: wrangler.name,
        token: cfToken,
      },
      fetchImpl,
    );
    cloudflareMissing = missingNames(required, present);
  }

  let githubMissing: string[] | "skipped" = "skipped";
  const ghToken = githubTokenFromEnv(processEnv);
  if (ghToken != null && github != null) {
    const present = await listGithubSecretNames(
      { repo: github.repo, token: ghToken },
      fetchImpl,
    );
    githubMissing = missingNames(github.secrets, present);
  }

  return { vaultMissing, cloudflareMissing, githubMissing };
}

export function formatStatus(report: StatusReport): string {
  const lines = [
    formatLine("vault", report.vaultMissing),
    formatLine("cloudflare", report.cloudflareMissing),
    formatLine("github", report.githubMissing),
  ];
  return `${lines.join("\n")}\n`;
}

function formatLine(label: string, missing: string[] | "skipped"): string {
  if (missing === "skipped") return `${label}: skipped`;
  if (missing.length === 0) return `${label}: ok`;
  return `${label}: missing ${missing.join(", ")}`;
}

export function statusFails(report: StatusReport): boolean {
  if (report.vaultMissing.length > 0) return true;
  if (Array.isArray(report.cloudflareMissing) && report.cloudflareMissing.length > 0) {
    return true;
  }
  if (Array.isArray(report.githubMissing) && report.githubMissing.length > 0) {
    return true;
  }
  return false;
}
