# BWF vault

`poc/vault` is Build With Friends' credential plane: an isolated Cloudflare
Worker + D1 that has been the authoring authority for every secret in this
project since the 2026-09-01 cutover from Infisical. It lives under `poc/`
pending extraction, but it is production infrastructure, not an experiment.
The repo-root `vault.json` still names the project `bwf-shadow` — import-era
storage identity that renaming would strand, not a statement of authority.

**The full documentation is at <https://vault.buildwithfriends.dev>** — concepts,
the complete CLI and HTTP references, the database schema, and the operational
runbooks. It is built from [`apps/vault-docs`](../../apps/vault-docs). This file
stays the operator's entry point with the checkout open; the site is what you
read without one. Neither is a copy of the other, and a change to this package's
routes, commands, schema, or procedures updates both.

The only production values outside the encrypted D1 database are the two
envelope-encryption roots and one-time bootstrap token. They live in Cloudflare
Secrets Store and are bound only to the `bwf-vault` Worker. Secret names,
values, API-key labels/scopes, and audit host/secret fields are encrypted in D1;
lookup hashes are keyed. API keys expire, can be rotated or revoked, and a
database trigger prevents revoking the last active human key.

## Install the CLI

Build a platform-specific standalone executable and install it from the
repository root:

```sh
bun run install:vault-cli
vault --help
```

The installer embeds the Bun runtime, so the installed command does not need
Bun or this checkout to run. It defaults to `~/.local/bin/vault`, which is
already on the standard BWF developer PATH. Override the destination for an
isolated or system-specific installation:

```sh
BWF_VAULT_INSTALL_DIR=/chosen/bin bun run install:vault-cli
```

The installer records the binary digest beside the command. Upgrades and
uninstallations refuse to replace an unrelated or locally modified `vault`
executable. It never edits a shell profile or copies credentials. If
`~/.local/bin` is not on PATH, add this to the relevant shell profile:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Remove a managed installation with `bun run uninstall:vault-cli`. Rebuild on
the target operating system and architecture; the generated executable is not
portable between platforms.

## Operator CLI

Once installed, run from this repository or any directory below one that has a
`vault.json`:

```sh
vault --help
vault status
vault projects list
vault environments list --project bwf
vault secrets list --project bwf --env dev
vault audit --limit 50
vault keys list --include-revoked
```

Credentials are read from hidden input/stdin or `VAULT_API_KEY`; `--api-key`
and `NAME=value` are rejected so they do not enter shell history. Destructive
commands require `--yes`. A newly created or rotated API key is shown once.

```sh
vault secrets set NAME --kind secret
vault secrets set GENERATED_NAME --kind sealed --random
vault secrets delete NAME --yes
vault keys create --type system --scope bwf/dev --mode inject
vault keys rotate vault_sys_PREFIX
vault keys revoke vault_sys_PREFIX --yes
```

`vault run` exports only names declared in the target Wrangler
`secrets.required` list and fails closed when any is missing. When that config
declares environments, the list belongs to one of them: `--wrangler-env NAME`
or `vault.json`'s `wranglerEnvironments` selects it, and an unselected
environment is an error rather than a fall back to the top-level list.
`vault proxy`
gives brokered tools dummy environment values and injects the real value only
into an allowlisted HTTPS request. Neither command writes secret values to the
repository.

```sh
vault run -- bun scripts/dev-stack.ts --no-electron
vault proxy -- agent-command
```

The repo-level `dev` and `dev:stack` scripts run under `vault run` by default,
injecting the `dev-worker` environment before the stack starts. `vault status`
verifies the selected runtime environment against `secrets.required` and the
GitHub destination names against `vault.json`'s `github.env`; `vault push`
delivers the runtime names to the Worker and the destination names to GitHub
Actions when the matching provider tokens are present. Push fails closed
whenever `vault.json` names anything other than the vault as `authority`.

## Provider verification

Run the redacted, read-only provider probes after authoring or rotating a
credential:

```sh
bun run vault:verify
bun run vault:canary:oauth
bun run vault:canary:sentry
bun run vault:recovery:rehearse
```

This checks the GitHub App, both analytics platform tokens, both
Cloudflare tokens, both R2 credential pairs, and the Sentry API credential.
OAuth and event ingestion use the separate Vault-backed consumer canaries
above. The OAuth canary boots the exact registered loopback origin, verifies
identity and GitHub App redirects, PKCE, state, scopes, and callback URLs, then
confirms GitHub accepts both client registrations without completing consent.
The Sentry canary packages the application with explicit export and source-map
upload, emits one opaque diagnostic, and queries that exact diagnostic back.
The recovery rehearsal captures a restricted production export, proves it in
disposable Cloudflare infrastructure, and removes that infrastructure. Realtime
media remains the existing explicit desktop acceptance command.

## Local development

From `poc/vault`:

```sh
bun run cli init
bun run migrations:local
bun run dev
```

`init` creates a private `.dev.vars` containing only local root credentials;
the repository ignores this file. In a second terminal, provide the bootstrap
token through hidden input or the environment:

```sh
bun run cli bootstrap --api-url http://127.0.0.1:8787
```

Bootstrap atomically claims an empty database, creates a 15-minute temporary
key, uses it to create a 90-day operator key, revokes the temporary key, and
saves only the durable key in `~/.config/poc-vault/config.json` with mode 0600.
The key is not printed.

## Production deployment

Production resources are deliberately isolated:

- Worker: `bwf-vault`
- D1: `bwf-vault`
- Secrets Store roots: `BWF_VAULT_MASTER_KEY_PRIMARY`,
  `BWF_VAULT_MASTER_KEY_SECONDARY`, `BWF_VAULT_BOOTSTRAP_TOKEN`

Apply migrations before deploying code that requires them:

```sh
bun run migrations:production
bun run deploy
```

Deployment is not a BWF credential cutover. Bootstrap the production URL once,
then verify root health, project CRUD, encrypted secret CRUD with a synthetic
value, API-key rotation, audit pagination, and the recovery checks in
[RECOVERY.md](RECOVERY.md).

## Master-key rotation

The checked-in `ACTIVE_MASTER_KEY` selects one of two Secrets Store bindings.
Rotation never decrypts and rewrites every row:

1. Authenticate Wrangler as the human operator authorized to update the
   production Secrets Store. Vault-held runtime credentials are never used for
   this root-of-trust ceremony.
2. Run `bun run vault:master-keys:prepare-rotation`. The helper generates a new
   random 32-byte root, writes it to the inactive binding through the logged-in
   Wrangler client, computes its expected fingerprint, and retries preparation
   until that exact fingerprint is wrapped. A merely new fingerprint is not
   sufficient because Secrets Store updates can reach existing Worker isolates
   asynchronously.
3. Change `ACTIVE_MASTER_KEY` to that slot and deploy.
4. Confirm `vault master-keys status` reports the expected active fingerprint
   and read a synthetic secret.
5. Keep the prior active wrap and root through an observation window. Retire
   only stale, unbound preparation wraps during activation.
6. Run `vault master-keys retire OLD_FINGERPRINT --yes` after the rollback
   window closes.
7. Replace the now-inactive old root so it cannot be reused.

The API refuses to retire the active wrap and refuses to start when the selected
root has not been prepared.

## Verification

```sh
bun run check
bun run test
bun run acceptance
bun run types:check
```

`acceptance` starts real local workerd + D1 state, bootstraps it, writes and
decrypts a synthetic secret, verifies audit evidence, and removes the temporary
state. Root `check:poc` and `test:poc` include this package's static and unit
gates; acceptance remains an explicit runtime proof.
