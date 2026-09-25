/**
 * The vault's shared vocabulary.
 *
 * `SecretKind` is the one type here that carries a policy decision rather than
 * a shape: `config` is passed through to a brokered child, `secret` is dummied,
 * and `sealed` is never returned by any route. `policy.ts` is where each of
 * those is enforced.
 *
 * Each shape is declared once, as a valibot schema, and its TypeScript type is
 * inferred from it. The server validates requests and the client validates
 * responses against these same definitions.
 *
 * `AuditAction` is deliberately a closed union. Adding an audited operation
 * means adding a member, which makes the audit surface reviewable as a list
 * instead of discoverable by grep.
 *
 * @see {@link https://vault.buildwithfriends.dev/concepts/secret-kinds/}
 */
import * as v from "valibot";

export const keyTypeSchema = v.picklist(["user", "system"]);
export const permissionSchema = v.picklist(["read", "readwrite", "full"]);
export const keyModeSchema = v.picklist(["inject", "broker"]);
export const secretKindSchema = v.picklist(["config", "secret", "sealed"]);
export const auditActionSchema = v.picklist([
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
]);

export const scopeSchema = v.object({ project: v.string(), env: v.string() });

export const apiKeyMetaSchema = v.object({
  keyPrefix: v.string(),
  type: keyTypeSchema,
  label: v.nullable(v.string()),
  permission: permissionSchema,
  mode: v.nullable(keyModeSchema),
  scopes: v.nullable(v.array(scopeSchema)),
  createdAt: v.string(),
  lastUsedAt: v.nullable(v.string()),
  expiresAt: v.string(),
  revoked: v.boolean(),
  revokedAt: v.nullable(v.string()),
});

export const secretMetaSchema = v.object({ name: v.string(), kind: secretKindSchema });

export const secretRecordSchema = v.object({
  name: v.string(),
  value: v.string(),
  kind: secretKindSchema,
});

export const routeRecordSchema = v.object({
  host: v.string(),
  secretName: v.string(),
  inject: v.string(),
  stripHeaders: v.array(v.string()),
  dummyEnvName: v.string(),
  dummyValue: v.string(),
});

export const auditRecordSchema = v.object({
  id: v.string(),
  keyPrefix: v.string(),
  action: auditActionSchema,
  host: v.nullable(v.string()),
  secretName: v.nullable(v.string()),
  status: v.string(),
  createdAt: v.string(),
});

export const masterKeyWrapMetaSchema = v.object({
  fingerprint: v.string(),
  createdAt: v.string(),
});

/** `PUT .../routes` body. The server rejects unknown fields; see `app.ts`. */
export const routeInputSchema = v.object({
  host: v.exactOptional(v.pipe(v.string(), v.minLength(1))),
  secret: v.pipe(v.string(), v.minLength(1)),
  preset: v.exactOptional(v.string()),
  header: v.exactOptional(v.string()),
  dummyEnvName: v.exactOptional(v.string()),
  dummyValue: v.exactOptional(v.string()),
});

export type KeyType = v.InferOutput<typeof keyTypeSchema>;
export type Permission = v.InferOutput<typeof permissionSchema>;
export type KeyMode = v.InferOutput<typeof keyModeSchema>;
export type SecretKind = v.InferOutput<typeof secretKindSchema>;
export type AuditAction = v.InferOutput<typeof auditActionSchema>;
export type Scope = v.InferOutput<typeof scopeSchema>;
export type ApiKeyMeta = v.InferOutput<typeof apiKeyMetaSchema>;
export type ApiKeyRecord = ApiKeyMeta & { id: string };
export type SecretMeta = v.InferOutput<typeof secretMetaSchema>;
export type SecretRecord = v.InferOutput<typeof secretRecordSchema>;
export type RouteRecord = v.InferOutput<typeof routeRecordSchema>;
export type AuditRecord = v.InferOutput<typeof auditRecordSchema>;
export type MasterKeyWrapMeta = v.InferOutput<typeof masterKeyWrapMetaSchema>;

export type ProcessEnvironment = Record<string, string | undefined>;
