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

export function canWriteSecrets(key: ApiKeyRecord): boolean {
  return key.permission === "full" || key.permission === "readwrite";
}

export function canDecryptValues(key: ApiKeyRecord): boolean {
  if (key.type === "user") return true;
  return key.mode === "inject";
}

export function assertNotRevoked(key: ApiKeyRecord): void {
  if (key.revoked) throw new PolicyError(401, "API key revoked");
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
