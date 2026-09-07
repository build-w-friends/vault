/**
 * Explicit synchronization of vault values out to Cloudflare and GitHub.
 *
 * This is the one path that writes a credential to another system, so it is
 * never implicit. `vault push` is an operator command, and `cli.ts` refuses it
 * outright while `vault.json` names anything other than the vault as
 * `authority` — the mechanism that keeps a replica from overwriting the system
 * that owns the values.
 *
 * A missing provider token skips that destination and says so. A destination
 * whose names the vault cannot supply throws before anything is written, so a
 * push is all-or-nothing per destination rather than partially applied. The
 * GitHub destination reads from its own environment (`github.env`) because the
 * runtime and CI names live in different environments.
 *
 * The Cloudflare half is per Wrangler environment: the caller resolves which
 * one, and both the script name and the required names come from it. A named
 * environment deploys as its own Worker, so pushing the top-level list there
 * would write the wrong set to the wrong script.
 *
 * @see {@link https://vault.buildwithfriends.dev/reference/cli/}
 */
import type { VaultClient } from "./client.ts";
import {
  cloudflareSecretsToRetire,
  cloudflareTokenFromEnv,
  listCloudflareSecretNames,
  pushCloudflareSecrets,
  type CloudflarePushTarget,
} from "./push-cloudflare.ts";
import {
  githubTokenFromEnv,
  pushGithubSecrets,
  type GithubPushTarget,
} from "./push-github.ts";
import {
  githubOwnerRepo,
  type RepoContext,
  type WranglerEnvironmentConfig,
} from "./repo-config.ts";
import type { ProcessEnvironment } from "./types.ts";

export type PushReport = {
  cloudflare: string[];
  /** Names deleted from the Worker because `secrets.required` no longer declares them. */
  retired: string[];
  github: string[];
  skipped: string[];
};

function pick(all: Record<string, string>, names: string[]) {
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
  wrangler: WranglerEnvironmentConfig | null;
  values: Record<string, string>;
  /** Values for the GitHub destination when `github.env` differs from the
   * session environment. Defaults to `values`. */
  githubValues?: Record<string, string>;
  names?: string[];
  githubRepo?: string;
  env?: ProcessEnvironment;
  fetchImpl?: import("./push-cloudflare.ts").FetchLike;
}): Promise<PushReport> {
  const processEnv = input.env ?? process.env;
  const fetchImpl = input.fetchImpl ?? fetch;
  const report: PushReport = { cloudflare: [], retired: [], github: [], skipped: [] };
  const filter = input.names != null ? new Set(input.names) : null;
  const required = input.wrangler?.required ?? [];
  const cloudflareNames = required.filter((name) => filter == null || filter.has(name));
  const githubNames = (input.repo.vault.github?.secrets ?? []).filter(
    (name) => filter == null || filter.has(name),
  );

  const cfToken = cloudflareTokenFromEnv(processEnv);
  const wrangler = input.wrangler;
  // A full push reconciles even with nothing to write. Entering only when
  // there are values would mean the Worker that just retired its *last*
  // required name never gets that name deleted, and `vault status` cannot
  // report the leftover — the one case where the drift is total. A narrowed
  // push still needs a name of its own, because it writes rather than
  // reconciles.
  if (filter == null || cloudflareNames.length > 0) {
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
      // A push reconciles the Worker against `secrets.required`, so a name
      // retired from that list is deleted rather than left live. Only a full
      // push may do that: `--name` narrows what is written, and treating the
      // rest as retired would delete every other secret the Worker needs.
      const retire =
        filter == null
          ? cloudflareSecretsToRetire(
              await listCloudflareSecretNames(target, fetchImpl),
              required,
            )
          : [];
      await pushCloudflareSecrets(target, values, fetchImpl, retire);
      report.cloudflare = Object.keys(values);
      report.retired = retire;
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
      const values = pick(input.githubValues ?? input.values, githubNames);
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
