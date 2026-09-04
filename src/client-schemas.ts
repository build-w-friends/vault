import * as v from "valibot";

import type {
  ApiKeyMeta,
  AuditRecord,
  MasterKeyWrapMeta,
  RouteRecord,
  SecretMeta,
  SecretRecord,
} from "./types.ts";

const secretKindSchema = v.picklist(["config", "secret", "sealed"]);

export const secretMetaSchema = v.looseObject({
  name: v.string(),
  kind: secretKindSchema,
}) satisfies v.GenericSchema<SecretMeta>;

export const secretRecordSchema = v.looseObject({
  name: v.string(),
  value: v.string(),
  kind: secretKindSchema,
}) satisfies v.GenericSchema<SecretRecord>;

export const routeRecordSchema = v.looseObject({
  host: v.string(),
  secretName: v.string(),
  inject: v.string(),
  stripHeaders: v.array(v.string()),
  dummyEnvName: v.string(),
  dummyValue: v.string(),
}) satisfies v.GenericSchema<RouteRecord>;

const scopeSchema = v.looseObject({
  project: v.string(),
  env: v.string(),
});

export const apiKeyMetaSchema = v.looseObject({
  keyPrefix: v.string(),
  type: v.picklist(["user", "system"]),
  label: v.nullable(v.string()),
  permission: v.picklist(["read", "readwrite", "full"]),
  mode: v.nullable(v.picklist(["inject", "broker"])),
  scopes: v.nullable(v.array(scopeSchema)),
  createdAt: v.string(),
  lastUsedAt: v.nullable(v.string()),
  expiresAt: v.string(),
  revoked: v.boolean(),
  revokedAt: v.nullable(v.string()),
}) satisfies v.GenericSchema<ApiKeyMeta>;

export const auditRecordSchema = v.looseObject({
  id: v.string(),
  keyPrefix: v.string(),
  action: v.picklist([
    "audit_list",
    "bootstrap",
    "broker",
    "environment_create",
    "environment_delete",
    "get",
    "inject",
    "key_create",
    "key_revoke",
    "key_rotate",
    "list",
    "master_key_prepare",
    "master_key_retire",
    "project_create",
    "project_delete",
    "route_list",
    "route_put",
    "secret_delete",
    "set",
  ]),
  host: v.nullable(v.string()),
  secretName: v.nullable(v.string()),
  status: v.string(),
  createdAt: v.string(),
}) satisfies v.GenericSchema<AuditRecord>;

export const masterKeyWrapMetaSchema = v.looseObject({
  fingerprint: v.string(),
  createdAt: v.string(),
}) satisfies v.GenericSchema<MasterKeyWrapMeta>;

export const routeInputSchema = v.object({
  host: v.exactOptional(v.pipe(v.string(), v.minLength(1))),
  secret: v.pipe(v.string(), v.minLength(1)),
  preset: v.exactOptional(v.string()),
  header: v.exactOptional(v.string()),
  dummyEnvName: v.exactOptional(v.string()),
  dummyValue: v.exactOptional(v.string()),
});
