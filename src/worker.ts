/**
 * The `bwf-vault` Worker entry point.
 *
 * Every request resolves both root-key slots and the bootstrap token from
 * Secrets Store, selects the active root by `ACTIVE_MASTER_KEY`, opens the
 * keyring, and builds the Hono application around the resulting crypto.
 *
 * A `MasterKeyError` anywhere in that chain answers 500 and logs one structured
 * line. The Worker does not serve with key material it could not verify: a
 * missing root, an unparseable one, or one with no prepared wrap are all
 * configuration errors, not conditions to degrade through.
 *
 * `scheduled` runs every five minutes, reconciles issuer credentials, and prunes
 * audit rows past `AUDIT_RETENTION_DAYS`. It
 * opens the keyring exactly as a request does, so a misconfigured root fails
 * the cron rather than pruning against the wrong database.
 *
 * @see {@link https://vault.buildwithfriends.dev/concepts/architecture/}
 */
import { createApp } from "./app.ts";
import { MasterKeyError } from "./crypto.ts";
import { IssuanceStore } from "./issuance/store.ts";
import { IssuanceService } from "./issuance/service.ts";
import { VaultStore } from "./db.ts";
import { VaultKeyring } from "./keyring.ts";
import {
  auditRetentionDays,
  readRuntimeSecret,
  resolveMasterKeys,
} from "./runtime-secrets.ts";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      const [masterKeys, bootstrapToken] = await Promise.all([
        resolveMasterKeys(env),
        readRuntimeSecret(env.BOOTSTRAP_TOKEN, "BOOTSTRAP_TOKEN"),
      ]);
      const keyring = await VaultKeyring.open(env.DB, masterKeys.active);
      return await createApp(keyring, {
        bootstrapToken,
        inactiveMasterKey: masterKeys.inactive,
      }).fetch(request, env, ctx);
    } catch (error) {
      if (error instanceof MasterKeyError) {
        console.error(
          JSON.stringify({ message: "vault root key rejected", error: error.message }),
        );
        return Response.json({ error: error.message }, { status: 500 });
      }
      throw error;
    }
  },

  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    const masterKeys = await resolveMasterKeys(env);
    const keyring = await VaultKeyring.open(env.DB, masterKeys.active);
    await new IssuanceService(new IssuanceStore(env.DB, keyring.crypto)).reconcile();
    const store = new VaultStore(env.DB, keyring.crypto);
    const cutoff = new Date(
      Date.now() - auditRetentionDays(env) * 24 * 60 * 60 * 1000,
    ).toISOString();
    const deleted = await store.pruneAudit(cutoff);
    console.log(
      JSON.stringify({ message: "vault audit retention complete", deleted, cutoff }),
    );
  },
} satisfies ExportedHandler<Env>;
