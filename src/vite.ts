import { VaultClient } from "./client.ts";
import { resolveClientOptions } from "./config.ts";
import { injectRequiredIntoProcess } from "./inject.ts";
import { loadRepoContext } from "./repo-config.ts";

export type ViteCommandEnv = {
  command: string;
  mode: string;
};

/** Minimal Vite plugin shape so this package does not depend on Vite. */
export type VaultVitePlugin = {
  name: string;
  enforce: "pre";
  config: (config: unknown, env: ViteCommandEnv) => Promise<void>;
};

/**
 * Cloudflare Vite / `vite dev` only. Injects `secrets.required` into
 * `process.env` on serve. Does not inject on build (would serialize into
 * dist/worker/.dev.vars). Does not write files.
 */
export function vault(options?: { cwd?: string }): VaultVitePlugin {
  return {
    name: "poc-vault",
    enforce: "pre",
    async config(_config, env) {
      if (env.command !== "serve") return;
      const cwd = options?.cwd ?? process.cwd();
      const repo = loadRepoContext(cwd);
      const resolved = resolveClientOptions({
        project: repo.vault.project,
        env: repo.vault.env,
      });
      const client = new VaultClient(resolved.apiUrl, resolved.apiKey);
      const project = resolved.project ?? repo.vault.project ?? "bwf";
      const vaultEnv = resolved.env ?? repo.vault.env ?? "dev";
      await injectRequiredIntoProcess({ cwd, client, project, env: vaultEnv });
    },
  };
}
