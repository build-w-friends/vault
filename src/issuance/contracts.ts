import { z } from "zod";

export const id = z.string().uuid();
export const subject = z.string().regex(/^[1-9][0-9]{0,19}$/u);
export const cfId = z.string().regex(/^[a-f0-9]{32}$/u);
export const secretReferenceSchema = z
  .object({
    $vaultSecret: z.object({ outputId: id, pointer: z.string().max(2000) }).strict(),
  })
  .strict();
export const apiRequestSchema = z
  .object({
    host: z
      .enum(["api.cloudflare.com", "gateway.ai.cloudflare.com"])
      .default("api.cloudflare.com"),
    method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
    path: z
      .string()
      .regex(/^\/(?:accounts|zones|v1)\/[a-f0-9]{32}(?:\/[a-zA-Z0-9_@.:-]+)*$/u)
      .max(2000)
      .refine(
        (value) => !value.split("/").some((part) => part === "." || part === ".."),
        "path traversal is not allowed",
      ),
    query: z.record(z.string().min(1).max(200), z.string().max(4000)).default({}),
    body: z
      .discriminatedUnion("kind", [
        z.object({ kind: z.literal("none") }).strict(),
        z.object({ kind: z.literal("json"), value: z.json() }).strict(),
        z
          .object({
            kind: z.literal("multipart"),
            parts: z
              .array(
                z
                  .object({
                    name: z.string().min(1).max(200),
                    content: z.string().max(800000),
                    filename: z.string().min(1).max(200),
                    contentType: z.string().regex(/^[a-zA-Z0-9.+-]+\/[a-zA-Z0-9.+-]+$/u),
                  })
                  .strict(),
              )
              .min(1)
              .max(30),
          })
          .strict(),
      ])
      .default({ kind: "none" }),
  })
  .strict()
  .refine(
    (value) => value.method !== "GET" || value.body.kind === "none",
    "GET cannot have a body",
  );
export type ApiRequest = z.infer<typeof apiRequestSchema>;
export const tokenPolicySchema = z
  .object({
    effect: z.enum(["allow", "deny"]),
    permission_groups: z
      .array(z.object({ id: cfId }).strict())
      .min(1)
      .max(100),
    resources: z.record(
      z.string().min(1),
      z.union([z.literal("*"), z.record(z.string(), z.literal("*"))]),
    ),
  })
  .strict();
const operationSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("api-request"), request: apiRequestSchema }).strict(),
  z
    .object({
      kind: z.literal("create-token"),
      policies: z.array(tokenPolicySchema).min(1).max(100),
    })
    .strict(),
]);
export const policySchema = z
  .object({
    accountId: cfId,
    zoneIds: z.array(cfId).max(1000),
    maxTtlSeconds: z.number().int().min(60).max(86400),
  })
  .strict();
export const prepareSchema = z
  .object({
    requestId: id,
    issuerId: id,
    operation: operationSchema,
    ttlSeconds: z.number().int().min(60).max(86400),
    purpose: z.string().trim().min(1).max(500),
    consumer: z.string().trim().min(1).max(120),
  })
  .strict();
export type Prepare = z.infer<typeof prepareSchema>;
export const planSchema = prepareSchema.extend({
  accountId: cfId,
  expiresAt: z.string().datetime(),
});
export type Plan = z.infer<typeof planSchema>;
export const identitySchema = z
  .object({
    origin: z
      .string()
      .url()
      .refine((value) => {
        const url = new URL(value);
        return (
          url.protocol === "https:" &&
          url.origin === value &&
          !url.username &&
          !url.password
        );
      }, "a canonical HTTPS origin is required"),
    clientId: z.string().min(1).max(200),
    clientSecret: z.string().min(1).max(500),
  })
  .strict();
export const adminSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("identity"), config: identitySchema }).strict(),
  z
    .object({ action: z.literal("tenant"), id, label: z.string().trim().min(1).max(120) })
    .strict(),
  z
    .object({
      action: z.literal("member"),
      tenantId: id,
      subject,
      operation: z.enum(["add", "remove"]),
    })
    .strict(),
  z
    .object({
      action: z.literal("issuer"),
      id,
      tenantId: id,
      label: z.string().trim().min(1).max(120),
      policy: policySchema,
      parentToken: z.string().min(1).max(4096),
      audience: z.union([z.literal("tenant"), z.array(subject).min(1).max(100)]),
    })
    .strict(),
  z.object({ action: z.literal("revoke-issuer"), issuerId: id }).strict(),
  z
    .object({
      action: z.literal("revoke-session"),
      sessionId: z.string().regex(/^[a-f0-9]{64}$/u),
    })
    .strict(),
]);
export type Auth = {
  hash: string;
  kind: "browser" | "agent";
  subject: string;
  tenant_id: string | null;
  label: string;
  csrf: string;
  expires_at: number;
  revoked_at: number | null;
};
export type Issuer = {
  id: string;
  tenant_id: string;
  label: string;
  policy_encrypted: string;
  parent_encrypted: string;
  revoked_at: number | null;
};
const requestStatusSchema = z.enum([
  "prepared",
  "approved",
  "declined",
  "executing",
  "completed",
  "issued",
  "unknown",
  "failed",
  "revoking",
  "revoked",
  "expired",
]);
export type IssuanceRequest = {
  id: string;
  issuer_id: string;
  subject: string;
  auth_hash: string;
  plan_encrypted: string;
  input_hash: string;
  created_at: number;
  approve_before: number;
  expires_at: number;
  status: z.infer<typeof requestStatusSchema>;
  kind: "api-request" | "create-token";
  output_id: string | null;
  token_id: string | null;
  token_encrypted: string | null;
  updated_at: number;
};
const useResultSchema = z.object({
  status: z.number().int(),
  outputId: id,
  body: z.json(),
});
const requestViewSchema = z.object({
  requestId: id,
  issuer: z.string(),
  tenantId: id,
  status: requestStatusSchema,
  plan: planSchema,
  effect: z.string(),
  approvalUrl: z.string().url(),
  approvalExpiresAt: z.string().datetime(),
  credentialRef: id.nullable(),
  result: useResultSchema.nullable(),
});
const catalogueSchema = z.object({
  issuers: z.array(
    z.object({
      id,
      tenantId: id,
      label: z.string(),
      policy: policySchema,
      approvalRequired: z.literal(true),
    }),
  ),
});
export const issuanceResponseSchema = z.union([
  requestViewSchema,
  catalogueSchema,
  useResultSchema,
]);
export type IssuanceResponse = z.infer<typeof issuanceResponseSchema>;
export const loginStateSchema = z.object({
  returnTo: z.string().regex(/^\/issuance\/(?:connect|approve)\/[a-f0-9-]{36}$/u),
  verifier: z.string(),
  configHash: z.string(),
});
