import { MasterKeyError } from "./crypto.ts";

export async function readRuntimeSecret(
  binding: SecretsStoreSecret | string | undefined,
  name: string,
): Promise<string> {
  const value =
    typeof binding === "string"
      ? binding
      : binding == null
        ? undefined
        : await binding.get();
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
