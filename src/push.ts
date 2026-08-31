import type { VaultClient } from "./client.ts";
import {
  cloudflareTokenFromEnv,
  pushCloudflareSecrets,
  type CloudflarePushTarget,
} from "./push-cloudflare.ts";
import {
  githubTokenFromEnv,
  pushGithubSecrets,
  type GithubPushTarget,
} from "./push-github.ts";
import { githubOwnerRepo, type RepoContext } from "./repo-config.ts";

export type PushReport = {
  cloudflare: string[];
  github: string[];
  skipped: string[];
};

function pick(all: Record<string, string>, names: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of names) {
    const value = all[name];
    if (value != null) out[name] = value;
  }
  return out;
}

export async function loadVaultValues(
  client: VaultClient,
  project: string,
  env: string,
): Promise<Record<string, string>> {
  const listed = await client.exportSecrets(project, env);
  const values: Record<string, string> = {};
  for (const secret of listed.secrets) {
    if (secret.value != null && secret.value.length > 0) {
      values[secret.name] = secret.value;
    }
  }
  return values;
}

export async function pushDestinations(input: {
  repo: RepoContext;
  values: Record<string, string>;
  names?: string[];
  githubRepo?: string;
  env?: NodeJS.ProcessEnv;
  fetchImpl?: import("./push-cloudflare.ts").FetchLike;
}): Promise<PushReport> {
  const processEnv = input.env ?? process.env;
  const fetchImpl = input.fetchImpl ?? fetch;
  const report: PushReport = { cloudflare: [], github: [], skipped: [] };
  const filter = input.names != null ? new Set(input.names) : null;
  const required = input.repo.wrangler?.required ?? [];
  const cloudflareNames = required.filter((name) => filter == null || filter.has(name));
  const githubNames = (input.repo.vault.github?.secrets ?? []).filter(
    (name) => filter == null || filter.has(name),
  );

  const cfToken = cloudflareTokenFromEnv(processEnv);
  const wrangler = input.repo.wrangler;
  if (cloudflareNames.length > 0) {
    if (cfToken == null) report.skipped.push("cloudflare (no CLOUDFLARE_API_TOKEN)");
    else if (wrangler == null || wrangler.accountId == null || wrangler.name == null) {
      report.skipped.push("cloudflare (wrangler.jsonc missing name/account_id)");
    } else {
      const target: CloudflarePushTarget = {
        accountId: wrangler.accountId,
        scriptName: wrangler.name,
        token: cfToken,
      };
      const values = pick(input.values, cloudflareNames);
      const missing = cloudflareNames.filter((name) => values[name] == null);
      if (missing.length > 0) {
        throw new Error(`vault missing names for Cloudflare: ${missing.join(", ")}`);
      }
      await pushCloudflareSecrets(target, values, fetchImpl);
      report.cloudflare = Object.keys(values);
    }
  }

  const ghToken = githubTokenFromEnv(processEnv);
  const github = input.repo.vault.github;
  if (githubNames.length > 0) {
    if (ghToken == null) report.skipped.push("github (no GH_TOKEN)");
    else if (github == null) report.skipped.push("github (vault.json missing github)");
    else {
      const repository = input.githubRepo;
      if (repository == null || githubOwnerRepo(repository) == null) {
        throw new Error(
          "missing trusted GitHub repository; set it with vault login --github-repo OWNER/REPO",
        );
      }
      if (repository !== github.repo) {
        throw new Error("trusted GitHub repository must match vault.json github.repo");
      }
      const target: GithubPushTarget = { repo: repository, token: ghToken };
      const values = pick(input.values, githubNames);
      const missing = githubNames.filter((name) => values[name] == null);
      if (missing.length > 0) {
        throw new Error(`vault missing names for GitHub: ${missing.join(", ")}`);
      }
      await pushGithubSecrets(target, values, fetchImpl);
      report.github = Object.keys(values);
    }
  }

  return report;
}
