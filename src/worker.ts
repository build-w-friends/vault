import { createApp } from "./app.ts";
import { MasterKeyError, VaultCrypto } from "./crypto.ts";
import type { VaultEnv } from "./types.ts";

export default {
  async fetch(request: Request, env: VaultEnv, ctx: ExecutionContext): Promise<Response> {
    try {
      const vaultCrypto = await VaultCrypto.fromMasterKey(env.MASTER_KEY);
      return await createApp(vaultCrypto).fetch(request, env, ctx);
    } catch (error) {
      if (error instanceof MasterKeyError) {
        return Response.json({ error: error.message }, { status: 500 });
      }
      throw error;
    }
  },
};
