/**
 * Response schemas for `VaultClient`.
 *
 * These reuse the wire in `types.ts` but accept unknown extra fields, so a
 * client keeps working against a server that adds a field to a response.
 */
import * as v from "valibot";

import * as wire from "./types.ts";

export const secretMetaSchema = v.looseObject(wire.secretMetaSchema.entries);
export const secretRecordSchema = v.looseObject(wire.secretRecordSchema.entries);
export const routeRecordSchema = v.looseObject(wire.routeRecordSchema.entries);
export const apiKeyMetaSchema = v.looseObject({
  ...wire.apiKeyMetaSchema.entries,
  scopes: v.nullable(v.array(v.looseObject(wire.scopeSchema.entries))),
});
export const auditRecordSchema = v.looseObject(wire.auditRecordSchema.entries);
export const masterKeyWrapMetaSchema = v.looseObject(
  wire.masterKeyWrapMetaSchema.entries,
);
