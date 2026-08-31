import type { VaultClient } from "./client.ts";
import { cloudflareTokenFromEnv, listCloudflareSecretNames } from "./push-cloudflare.ts";
import { githubTokenFromEnv, listGithubSecretNames } from "./push-github.ts";
import type { RepoContext } from "./repo-config.ts";
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

export function requiredVaultNames(repo: RepoContext): string[] {
  const runtimeRequired = repo.wrangler?.required ?? [];
  const destinationRequired =
    repo.vault.authority === "infisical-shadow" ? [] : (repo.vault.github?.secrets ?? []);
  return [...new Set([...runtimeRequired, ...destinationRequired])];
}

export async function collectStatus(input: {
  client: VaultClient;
  repo: RepoContext;
  project: string;
  env: string;
  processEnv?: ProcessEnvironment;
  fetchImpl?: import("./push-cloudflare.ts").FetchLike;
}): Promise<StatusReport> {
  const processEnv = input.processEnv ?? process.env;
  const fetchImpl = input.fetchImpl ?? fetch;
  const required = input.repo.wrangler?.required ?? [];
  const vaultNames = new Set(
    (await input.client.listSecretMeta(input.project, input.env)).secrets.map(
      (secret) => secret.name,
    ),
  );
  const vaultMissing = missingNames(requiredVaultNames(input.repo), [...vaultNames]);

  let cloudflareMissing: string[] | "skipped" = "skipped";
  const cfToken = cloudflareTokenFromEnv(processEnv);
  const wrangler = input.repo.wrangler;
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
  const github = input.repo.vault.github;
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
