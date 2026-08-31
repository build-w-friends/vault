# poc/vault

Credential plane for this repo’s Cloudflare Vite Worker. The vault is the only place a value is authored. Local `vite` / `wrangler dev` inject `secrets.required`. `prod` pushes those names to the Worker and listed names to GitHub Actions.

## Daily

```sh
vault login --api-url URL --api-key KEY
vault status
vault ls
vault set REALTIME_APP_SECRET
bun run dev
```

`vault set NAME` on `--env prod` also pushes Cloudflare (`secrets.required`) and GitHub (`vault.json` `github.secrets`).

```sh
vault set REALTIME_APP_SECRET --env prod
vault push --env prod
```

## Vite

```ts
import { vault } from "poc-vault/vite";

export default defineConfig({
  plugins: [vault()],
});
```

On `command === "serve"` the plugin loads `wrangler.jsonc` `secrets.required` into `process.env`. Missing or empty throws. It injects nothing on `build`. It does not write `.env` / `.dev.vars`. Extra vault names are not copied.

## Config

`vault.json` (committed, no values):

```json
{
  "project": "bwf",
  "env": "dev",
  "wrangler": "apps/worker/wrangler.jsonc",
  "github": {
    "repo": "owner/repo",
    "secrets": ["SOME_ACTIONS_TOKEN"]
  }
}
```

Push uses `CLOUDFLARE_API_TOKEN` and `GH_TOKEN` / `GITHUB_TOKEN` from the operator environment (`wrangler` / `gh` sessions). The vault Worker does not store those.

## First Worker

```sh
vault init
wrangler d1 migrations apply poc-vault --local
wrangler dev
vault bootstrap
vault login --api-url http://127.0.0.1:8787 --api-key vault_user_…
```

## Check

```sh
bun test
bun run check
```
