export type KeyType = "user" | "system";
export type Permission = "read" | "readwrite" | "full";
export type KeyMode = "inject" | "broker";
export type SecretKind = "config" | "secret" | "sealed";
export type AuditAction =
  | "audit_list"
  | "bootstrap"
  | "broker"
  | "environment_create"
  | "environment_delete"
  | "get"
  | "inject"
  | "key_create"
  | "key_revoke"
  | "key_rotate"
  | "list"
  | "master_key_prepare"
  | "master_key_retire"
  | "project_create"
  | "project_delete"
  | "route_list"
  | "route_put"
  | "secret_delete"
  | "set";

export type Scope = {
  project: string;
  env: string;
};

export type ApiKeyRecord = {
  id: string;
  keyPrefix: string;
  type: KeyType;
  label: string | null;
  permission: Permission;
  mode: KeyMode | null;
  scopes: Scope[] | null;
  createdAt: string;
  lastUsedAt: string | null;
  expiresAt: string;
  revoked: boolean;
  revokedAt: string | null;
};

export type ApiKeyMeta = Omit<ApiKeyRecord, "id">;

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

export type AuditRecord = {
  id: string;
  keyPrefix: string;
  action: AuditAction;
  host: string | null;
  secretName: string | null;
  status: string;
  createdAt: string;
};

export type MasterKeyWrapMeta = {
  fingerprint: string;
  createdAt: string;
};

export type ProcessEnvironment = Record<string, string | undefined>;
