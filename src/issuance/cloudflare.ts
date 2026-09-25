import { z } from "zod";
import { cfId, type Plan } from "./contracts.ts";
import { readProviderResponse, type Send } from "./provider-request.ts";

// Cloudflare echoes policies with extra fields (policy ids, group names), so this
// reads them loosely; contracts.ts tokenPolicySchema is the strict request shape.
const policySchema = z.looseObject({
  effect: z.enum(["allow", "deny"]),
  permission_groups: z.array(z.looseObject({ id: cfId })),
  resources: z.record(
    z.string(),
    z.union([z.literal("*"), z.record(z.string(), z.literal("*"))]),
  ),
});
const createdTokenSchema = z.object({
  id: cfId,
  name: z.string(),
  expires_on: z.string(),
  policies: z.array(policySchema),
  status: z.literal("active"),
  value: z.string().min(1),
});

type TokenPlan = Pick<Plan, "accountId" | "requestId" | "operation" | "expiresAt">;
type ProviderBody = Awaited<ReturnType<typeof readProviderResponse>>["body"];

const errorsSchema = z.looseObject({
  errors: z.array(z.looseObject({ code: z.number(), message: z.string() })),
});

function rejectionMessage(status: number, body: ProviderBody | undefined): string {
  const message = `Cloudflare rejected the operation (HTTP ${status})`;
  const parsed = errorsSchema.safeParse(body);
  if (!parsed.success || parsed.data.errors.length === 0) return message;
  const details = parsed.data.errors
    .slice(0, 5)
    .map((error) => `${error.code}: ${error.message.slice(0, 500)}`)
    .join("; ");
  return `${message}: ${details}`;
}

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
  constructor(private readonly send: Send = fetch) {}

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
        // Plans already end on a whole second; Cloudflare rejects even .000Z.
        expires_on: plan.expiresAt.replace(/\.000Z$/u, "Z"),
      }),
    );
    if (
      token.name !== this.tokenName(plan.requestId) ||
      Date.parse(token.expires_on) !== Date.parse(plan.expiresAt) ||
      canonical(token.policies) !== canonical(policies)
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
    cfId.parse(tokenId);
    await this.call(
      parent,
      accountId,
      `/${tokenId}`,
      "DELETE",
      z.looseObject({ id: cfId }).nullable(),
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
        z.array(z.looseObject({ id: cfId, name: z.string() })),
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

  private async call<TSchema extends z.ZodType>(
    parent: string,
    accountId: string,
    suffix: string,
    method: "GET" | "POST" | "DELETE",
    resultSchema: TSchema,
    body?: string,
  ): Promise<z.output<TSchema>> {
    cfId.parse(accountId);
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
    if (method === "DELETE" && response.status === 404) return resultSchema.parse(null);
    if (response.status >= 400 && response.status < 500) {
      // A missing or malformed error body cannot make a definite rejection uncertain.
      const details = await readProviderResponse(response, parent).catch(() => null);
      throw new ProviderError(
        "rejected",
        rejectionMessage(response.status, details?.body),
        undefined,
        response.status,
      );
    }
    const schema = z.looseObject({ success: z.boolean(), result: z.unknown() });
    let data: ProviderBody;
    try {
      data = (await readProviderResponse(response, parent)).body;
    } catch {
      throw new ProviderError(
        method === "POST" ? "unknown" : "rejected",
        "Cloudflare returned an invalid response",
      );
    }
    const parsed = schema.safeParse(data);
    if (!response.ok || !parsed.success || !parsed.data.success) {
      throw new ProviderError(
        method === "POST" && (response.status >= 500 || response.ok)
          ? "unknown"
          : "rejected",
        rejectionMessage(response.status, data),
        undefined,
        response.status,
      );
    }
    const result = resultSchema.safeParse(parsed.data.result);
    if (!result.success) {
      const identified = z.looseObject({ id: cfId }).safeParse(parsed.data.result);
      throw new ProviderError(
        method === "POST" ? "unknown" : "rejected",
        "Cloudflare returned an invalid result",
        method === "POST" && identified.success ? identified.data.id : undefined,
      );
    }
    return result.data;
  }
}

function canonical(policies: z.output<typeof policySchema>[]): string {
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
