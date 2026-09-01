/**
 * The single place a key's authority is decided.
 *
 * Two key types: `user` keys are operators (manage keys, projects, and audit;
 * unscoped) and `system` keys are machines (scoped, and never able to manage
 * anything). A system key's `mode` splits it further — `inject` may decrypt
 * values within its scopes, `broker` may not decrypt anything at all.
 *
 * `broker` is what makes `vault proxy` meaningful: it can list names, list
 * routes, and create sealed random secrets, so a process can mint and use a
 * credential it is never permitted to read.
 *
 * The `sealed` kind is checked here rather than at a call site: no key type,
 * permission, or query parameter returns a sealed value, which is what makes
 * "write-only" a property of the system instead of a convention.
 *
 * Keep these decisions in this module. A policy check inlined into a route is
 * a rule that the next route silently does not get.
 *
 * @see {@link https://vault.buildwithfriends.dev/concepts/keys-and-policy/}
 */
import type { ApiKeyRecord, SecretKind } from "./types.ts";

export class PolicyError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "PolicyError";
    this.status = status;
  }
}

export function canManageKeys(key: ApiKeyRecord): boolean {
  return key.type === "user";
}

export function canManageProjects(key: ApiKeyRecord): boolean {
  return key.type === "user";
}

function canWriteSecrets(key: ApiKeyRecord): boolean {
  return key.permission === "full" || key.permission === "readwrite";
}

export function canDecryptValues(key: ApiKeyRecord): boolean {
  if (key.type === "user") return true;
  return key.mode === "inject";
}

export function assertActiveKey(key: ApiKeyRecord, now: Date = new Date()): void {
  if (key.revoked) throw new PolicyError(401, "API key revoked");
  if (Date.parse(key.expiresAt) <= now.getTime()) {
    throw new PolicyError(401, "API key expired");
  }
}

export function assertScope(key: ApiKeyRecord, project: string, env: string): void {
  if (key.type === "user") return;
  const scopes = key.scopes ?? [];
  const allowed = scopes.some(
    (scope) => scope.project === project && (scope.env === "*" || scope.env === env),
  );
  if (!allowed)
    throw new PolicyError(403, "API key is not scoped to this project/environment");
}

export function assertCanDecrypt(key: ApiKeyRecord): void {
  if (!canDecryptValues(key)) {
    throw new PolicyError(403, "broker keys cannot read secret values");
  }
}

export function assertCanWrite(key: ApiKeyRecord): void {
  if (!canWriteSecrets(key)) throw new PolicyError(403, "API key cannot write secrets");
}

export function valueVisibleOnList(
  key: ApiKeyRecord,
  kind: SecretKind,
  show: boolean,
): boolean {
  if (!show) return false;
  if (!canDecryptValues(key)) return false;
  if (kind === "sealed") return false;
  if (kind === "config") return true;
  return key.type === "user";
}

export function valueVisibleOnGet(key: ApiKeyRecord, kind: SecretKind): boolean {
  if (kind === "sealed") return false;
  return canDecryptValues(key);
}

export function dummyForProxy(kind: SecretKind): boolean {
  return kind !== "config";
}
