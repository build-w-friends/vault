export type KeyType = "user" | "system";
export type Permission = "read" | "readwrite" | "full";
export type KeyMode = "inject" | "broker";
export type SecretKind = "config" | "secret" | "sealed";
export type AuditAction = "inject" | "broker" | "get" | "set" | "list";

export type Scope = {
  project: string;
  env: string;
};

export type ApiKeyRecord = {
  id: string;
  keyPrefix: string;
  type: KeyType;
  permission: Permission;
  mode: KeyMode | null;
  scopes: Scope[] | null;
  revoked: boolean;
};

export type SecretRecord = {
  name: string;
  value: string;
  kind: SecretKind;
};

export type SecretMeta = {
  name: string;
  kind: SecretKind;
};

export type RouteRecord = {
  host: string;
  secretName: string;
  inject: string;
  stripHeaders: string[];
  dummyEnvName: string;
  dummyValue: string;
};

export type VaultEnv = {
  DB: D1Database;
  MASTER_KEY: string;
};
