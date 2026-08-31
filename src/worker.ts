import { createApp } from "./app.ts";
import { MasterKeyError } from "./crypto.ts";
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
      return await createApp(keyring.crypto, {
        bootstrapToken,
        activeMasterKeyFingerprint: keyring.activeFingerprint,
        keyring,
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
