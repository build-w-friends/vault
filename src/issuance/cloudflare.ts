import * as v from "valibot";
import type { Plan } from "./contracts.ts";

const cloudflareIdSchema = v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u));
const policySchema = v.looseObject({
  effect: v.picklist(["allow", "deny"]),
  permission_groups: v.array(v.looseObject({ id: cloudflareIdSchema })),
  resources: v.record(
    v.string(),
    v.union([v.literal("*"), v.record(v.string(), v.literal("*"))]),
  ),
});
const tokenSchema = v.looseObject({
  id: cloudflareIdSchema,
  name: v.string(),
  expires_on: v.string(),
  policies: v.array(policySchema),
  status: v.literal("active"),
});
const createdTokenSchema = v.object({
  ...tokenSchema.entries,
  value: v.pipe(v.string(), v.minLength(1)),
});

type TokenPlan = Pick<Plan, "accountId" | "requestId" | "operation" | "expiresAt">;

export class ProviderError extends Error {
  constructor(
    readonly outcome: "rejected" | "unknown",
    message: string,
    readonly tokenId?: string,
    readonly status: number | null = null,
  ) {
    super(message);
    this.name = "ProviderError";
  }
}

export class CloudflareIssuer {
  constructor(private readonly send: typeof fetch = fetch) {}

  async create(parent: string, plan: TokenPlan): Promise<{ id: string; value: string }> {
    if (plan.operation.kind !== "create-token")
      throw new ProviderError("rejected", "not a token request");
    const policies = plan.operation.policies;
    const token = await this.call(
      parent,
      plan.accountId,
      "",
      "POST",
      createdTokenSchema,
      JSON.stringify({
        name: this.tokenName(plan.requestId),
        policies,
        expires_on: plan.expiresAt,
      }),
    );
    if (
      token.name !== this.tokenName(plan.requestId) ||
      Date.parse(token.expires_on) !== Date.parse(plan.expiresAt) ||
      canonical(
        token.policies.map((policy) => ({
          effect: policy.effect,
          permission_groups: policy.permission_groups.map(({ id }) => ({ id })),
          resources: policy.resources,
        })),
      ) !== canonical(policies)
    ) {
      try {
        await this.revoke(parent, plan.accountId, token.id);
      } catch {
        throw new ProviderError(
          "unknown",
          "scope mismatch requires reconciliation",
          token.id,
        );
      }
      throw new ProviderError(
        "rejected",
        "Cloudflare returned a different token scope; the token was revoked",
      );
    }
    return { id: token.id, value: token.value };
  }

  async revoke(parent: string, accountId: string, tokenId: string): Promise<void> {
    v.parse(cloudflareIdSchema, tokenId);
    await this.call(
      parent,
      accountId,
      `/${tokenId}`,
      "DELETE",
      v.nullable(v.looseObject({ id: cloudflareIdSchema })),
    );
  }

  async revokeUncertain(parent: string, plan: TokenPlan): Promise<void> {
    const ids: string[] = [];
    for (let page = 1; page <= 100; page++) {
      const rows = await this.call(
        parent,
        plan.accountId,
        `?page=${page}&per_page=50`,
        "GET",
        v.array(v.looseObject({ id: cloudflareIdSchema, name: v.string() })),
      );
      for (const token of rows) {
        if (token.name === this.tokenName(plan.requestId)) ids.push(token.id);
      }
      if (rows.length < 50) {
        for (const id of ids) await this.revoke(parent, plan.accountId, id);
        return;
      }
    }
    throw new ProviderError(
      "rejected",
      "Cloudflare token reconciliation exceeded its page limit",
    );
  }

  tokenName(requestId: string): string {
    return `vault-issuance-${requestId}`;
  }

  private async call<TSchema extends v.GenericSchema>(
    parent: string,
    accountId: string,
    suffix: string,
    method: "GET" | "POST" | "DELETE",
    resultSchema: TSchema,
    body?: string,
  ): Promise<v.InferOutput<TSchema>> {
    v.parse(cloudflareIdSchema, accountId);
    let response: Response;
    try {
      const send = this.send;
      response = await send(
        `https://api.cloudflare.com/client/v4/accounts/${accountId}/tokens${suffix}`,
        {
          method,
          headers: {
            Authorization: `Bearer ${parent}`,
            "Content-Type": "application/json",
          },
          body,
          redirect: "manual",
          signal: AbortSignal.timeout(20_000),
        },
      );
    } catch {
      throw new ProviderError(
        method === "POST" ? "unknown" : "rejected",
        "Cloudflare request did not complete",
      );
    }
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new ProviderError(
        method === "POST" ? "unknown" : "rejected",
        "Cloudflare redirects are not allowed",
      );
    }
    if (method === "DELETE" && response.status === 404)
      return v.parse(resultSchema, null);
    if (response.status >= 400 && response.status < 500) {
      await response.body?.cancel();
      throw new ProviderError(
        "rejected",
        `Cloudflare rejected the operation (HTTP ${response.status})`,
        undefined,
        response.status,
      );
    }
    const schema = v.looseObject({ success: v.boolean(), result: v.unknown() });
    let data: unknown;
    try {
      data = await response.json();
    } catch {
      throw new ProviderError(
        method === "POST" ? "unknown" : "rejected",
        "Cloudflare returned an invalid response",
      );
    }
    const parsed = v.safeParse(schema, data);
    if (!response.ok || !parsed.success || !parsed.output.success) {
      throw new ProviderError(
        method === "POST" && (response.status >= 500 || response.ok)
          ? "unknown"
          : "rejected",
        `Cloudflare rejected the operation (HTTP ${response.status})`,
        undefined,
        response.status,
      );
    }
    const result = v.safeParse(resultSchema, parsed.output.result);
    if (!result.success) {
      const identified = v.safeParse(
        v.looseObject({ id: cloudflareIdSchema }),
        parsed.output.result,
      );
      throw new ProviderError(
        method === "POST" ? "unknown" : "rejected",
        "Cloudflare returned an invalid result",
        method === "POST" && identified.success ? identified.output.id : undefined,
      );
    }
    return result.output;
  }
}

function canonical(policies: v.InferOutput<typeof policySchema>[]): string {
  return JSON.stringify(
    policies
      .map((policy) =>
        JSON.stringify({
          effect: policy.effect,
          permission_groups: policy.permission_groups.map((group) => group.id).sort(),
          resources: Object.entries(policy.resources)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([resource, scope]) => [
              resource,
              scope === "*"
                ? "*"
                : Object.entries(scope).sort(([a], [b]) => a.localeCompare(b)),
            ]),
        }),
      )
      .sort(),
  );
}
