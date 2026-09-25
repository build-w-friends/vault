import * as v from "valibot";
/**
 * Reading the Worker's required runtime configuration.
 *
 * The three Secrets Store roots and both vars are *required*: every accessor
 * here throws on absence rather than returning a default. Vault has no mode in
 * which a missing root selects a fallback — presence of a credential must never
 * decide whether a capability is on, and an empty default would be a second,
 * untested configuration of the product.
 *
 * `resolveMasterKeys` returns both slots because rotation needs the inactive
 * one: `POST /v1/master-keys/prepare` wraps the data key for the slot that is
 * not currently live.
 *
 * @see {@link https://vault.buildwithfriends.dev/reference/configuration/}
 */
import { MasterKeyError } from "./crypto.ts";

export async function readRuntimeSecret(
  binding: SecretsStoreSecret | string | undefined,
  name: string,
): Promise<string> {
  // A plain string is the value itself; a binding has to be read.
  let value: string | undefined;
  if (v.is(v.string(), binding)) value = binding;
  else if (binding != null) value = await binding.get();
  if (value == null || value.length === 0) {
    throw new MasterKeyError(`${name} is required`);
  }
  return value;
}

export async function resolveMasterKeys(env: Env): Promise<{
  active: string;
  inactive: string;
  activeSlot: "primary" | "secondary";
}> {
  const [primary, secondary] = await Promise.all([
    readRuntimeSecret(env.MASTER_KEY_PRIMARY, "MASTER_KEY_PRIMARY"),
    readRuntimeSecret(env.MASTER_KEY_SECONDARY, "MASTER_KEY_SECONDARY"),
  ]);
  const activeSlot: string = env.ACTIVE_MASTER_KEY;
  if (activeSlot !== "primary" && activeSlot !== "secondary") {
    throw new MasterKeyError("ACTIVE_MASTER_KEY must be primary or secondary");
  }
  return activeSlot === "primary"
    ? { active: primary, inactive: secondary, activeSlot }
    : { active: secondary, inactive: primary, activeSlot };
}

export function auditRetentionDays(env: Env): number {
  const days = Number(env.AUDIT_RETENTION_DAYS);
  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    throw new Error("AUDIT_RETENTION_DAYS must be an integer from 1 to 3650");
  }
  return days;
}
