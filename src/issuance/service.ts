import { PolicyError } from "../policy.ts";
import { CloudflareIssuer, ProviderError } from "./cloudflare.ts";
import {
  policySchema,
  type Auth,
  type Prepare,
  type IssuanceRequest,
  apiRequestSchema,
} from "./contracts.ts";
import { IssuanceStore } from "./store.ts";
import type { z } from "zod";
import {
  assertApiScope,
  assertTokenScope,
  isTokenManagement,
  providerRequest,
} from "./provider-request.ts";
import { saveOutput, showOutput, resolveSecrets } from "./outputs.ts";

export class IssuanceService {
  constructor(
    readonly store: IssuanceStore,
    readonly provider = new CloudflareIssuer(),
    readonly send: typeof fetch = fetch,
  ) {}
  async prepare(auth: Auth, input: Prepare) {
    const existing = await this.store.db
      .prepare("SELECT id FROM issuance_requests WHERE id = ?")
      .bind(input.requestId)
      .first();
    const inputHash = await this.store.crypto.sha256(JSON.stringify(input));
    if (existing) {
      const row = await this.store.request(input.requestId, auth);
      if (row.input_hash !== inputHash)
        throw new PolicyError(409, "request ID is already bound to another plan");
      return this.view(row);
    }
    const issuer = await this.store.requireIssuer(auth, input.issuerId);
    const policy = policySchema.parse(
      JSON.parse(await this.store.crypto.decrypt(issuer.policy_encrypted)),
    );
    if (input.ttlSeconds > policy.maxTtlSeconds)
      throw new PolicyError(403, "requested lifetime exceeds issuer policy");
    if (input.operation.kind === "create-token")
      assertTokenScope(input.operation.policies, policy);
    else {
      assertApiScope(input.operation.request, policy);
      if (
        input.operation.request.method === "POST" &&
        input.operation.request.path === `/accounts/${policy.accountId}/tokens`
      ) {
        throw new PolicyError(
          400,
          "use create-token so Vault stores and tracks the issued credential",
        );
      }
    }
    const count = await this.store.db
      .prepare(
        "SELECT count(*) AS n FROM issuance_requests WHERE auth_hash = ? AND created_at > ?",
      )
      .bind(auth.hash, this.store.now() - 3600000)
      .first<{ n: number }>();
    if ((count?.n ?? 0) >= 100)
      throw new PolicyError(429, "too many issuance requests; retry later");
    const now = this.store.now();
    const expiresAt = new Date(
      Math.floor(now / 1000) * 1000 + input.ttlSeconds * 1000,
    ).toISOString();
    const plan = { ...input, accountId: policy.accountId, expiresAt };
    await this.store.db.batch([
      this.store.db
        .prepare(`INSERT OR IGNORE INTO issuance_requests
        (id,issuer_id,subject,auth_hash,plan_encrypted,input_hash,created_at,approve_before,expires_at,status,updated_at,kind)
        VALUES (?,?,?,?,?,?,?,?,?,'prepared',?,?)`)
        .bind(
          input.requestId,
          issuer.id,
          auth.subject,
          auth.hash,
          await this.store.crypto.encrypt(JSON.stringify(plan)),
          inputHash,
          now,
          Math.min(now + 600000, Date.parse(expiresAt)),
          Date.parse(expiresAt),
          now,
          input.operation.kind,
        ),
      this.store.db
        .prepare(
          "INSERT INTO issuance_events SELECT ?, ?, ?, 'prepared', ? WHERE changes() = 1",
        )
        .bind(crypto.randomUUID(), input.requestId, auth.subject, now),
    ]);
    const row = await this.store.request(input.requestId, auth);
    if (row.input_hash !== inputHash)
      throw new PolicyError(409, "request ID is already bound to another plan");
    return this.view(row);
  }
  async view(row: IssuanceRequest) {
    const plan = await this.store.plan(row);
    const issuer = await this.store.issuer(row.issuer_id);
    const config = await this.store.identity();
    let result = null;
    if (row.output_id) {
      try {
        result = await showOutput(this.store, row.output_id);
      } catch (error) {
        if (!(error instanceof PolicyError) || error.status !== 404) throw error;
      }
    }
    return {
      requestId: row.id,
      issuer: issuer.label,
      tenantId: issuer.tenant_id,
      status: row.status,
      plan,
      effect:
        plan.operation.kind === "create-token"
          ? "Create an account token with the displayed Cloudflare policies"
          : `${plan.operation.request.method} ${plan.operation.request.path}`,
      result,
      approvalUrl: `${config.origin}/issuance/approve/${row.id}`,
      approvalExpiresAt: new Date(row.approve_before).toISOString(),
      credentialRef: row.status === "issued" ? row.id : null,
    };
  }
  async approve(auth: Auth, requestId: string, allow: boolean) {
    if (auth.kind !== "browser")
      throw new PolicyError(403, "approval requires browser sign-in");
    const row = await this.store.request(requestId, auth);
    if (
      !(await this.store.transition(
        row,
        "prepared",
        allow ? "approved" : "declined",
        allow ? "approval" : "none",
      ))
    ) {
      throw new PolicyError(
        409,
        "request is no longer pending or eligible; prepare a new request",
      );
    }
  }
  async execute(auth: Auth, requestId: string) {
    const row = await this.store.request(requestId, auth);
    if (row.status === "issued" || row.status === "completed") return this.view(row);
    if (!(await this.store.transition(row, "approved", "executing", "approval"))) {
      throw new PolicyError(
        409,
        "issuance requires an unexpired human approval; check request status",
      );
    }
    const issuer = await this.store.issuer(row.issuer_id);
    const plan = await this.store.plan(row);
    if (plan.operation.kind === "api-request") {
      const secrets = new Set<string>();
      let request = plan.operation.request;
      let parent: string;
      try {
        if (request.body.kind === "json")
          request = {
            ...request,
            body: {
              kind: "json",
              value: await resolveSecrets(this.store, auth, request.body.value, secrets),
            },
          };
        parent = await this.store.crypto.decrypt(issuer.parent_encrypted);
      } catch (error) {
        await this.store.transition(row, "executing", "failed");
        const outputId = await saveOutput(this.store, row.id, {
          status: error instanceof PolicyError ? error.status : 400,
          body: {
            outcome: "rejected",
            reason:
              error instanceof PolicyError
                ? error.message
                : "invalid local request inputs",
          },
        });
        await this.store.db
          .prepare("UPDATE issuance_requests SET output_id = ? WHERE id = ?")
          .bind(outputId, row.id)
          .run();
        throw new PolicyError(
          400,
          "request rejected before contacting the provider; check request status for details",
        );
      }
      try {
        const result = await providerRequest(this.send, parent, request);
        const outputId = await saveOutput(this.store, row.id, result, [...secrets]);
        await this.store.db
          .prepare("UPDATE issuance_requests SET output_id = ? WHERE id = ?")
          .bind(outputId, row.id)
          .run();
        // A provider response is evidence even if membership was revoked during the call.
        await this.store.transition(
          row,
          "executing",
          result.status >= 500 ? "unknown" : "completed",
        );
      } catch {
        await this.store.transition(row, "executing", "unknown");
        throw new PolicyError(
          502,
          "provider outcome is unknown; inspect the resource before preparing another mutation",
        );
      }
      return this.view(await this.store.request(row.id, auth));
    }
    try {
      const token = await this.provider.create(
        await this.store.crypto.decrypt(issuer.parent_encrypted),
        plan,
      );
      await this.store.db
        .prepare(
          "UPDATE issuance_requests SET token_id = ?, token_encrypted = ?, updated_at = ? WHERE id = ?",
        )
        .bind(
          token.id,
          await this.store.crypto.encrypt(token.value),
          this.store.now(),
          row.id,
        )
        .run();
      if (!(await this.store.transition(row, "executing", "issued", "active"))) {
        await this.store.db
          .prepare(
            "UPDATE issuance_requests SET status = 'revoking', updated_at = ? WHERE id = ?",
          )
          .bind(this.store.now(), row.id)
          .run();
        await this.cleanup(await this.store.request(row.id));
      }
    } catch (error) {
      if (error instanceof ProviderError && error.tokenId) {
        await this.store.db
          .prepare("UPDATE issuance_requests SET token_id = ? WHERE id = ?")
          .bind(error.tokenId, row.id)
          .run();
      }
      const outcome = error instanceof ProviderError ? error.outcome : "unknown";
      const outputId = await saveOutput(this.store, row.id, {
        status: error instanceof ProviderError ? (error.status ?? 502) : 502,
        body: {
          outcome,
          reason:
            error instanceof ProviderError
              ? error.message
              : "Vault could not finish recording token creation; reconciliation is required",
        },
      });
      await this.store.db
        .prepare("UPDATE issuance_requests SET output_id = ? WHERE id = ?")
        .bind(outputId, row.id)
        .run();
      await this.store.transition(
        row,
        "executing",
        outcome === "rejected" ? "failed" : "unknown",
      );
      throw new PolicyError(
        502,
        outcome === "rejected"
          ? "token creation was rejected; check request status for details"
          : "token creation outcome is unknown; check request status before preparing another request",
      );
    }
    return this.view(await this.store.request(row.id, auth));
  }
  async revoke(auth: Auth, requestId: string) {
    const row = await this.store.request(requestId, auth);
    await this.store.db.batch([
      this.store.db
        .prepare(`UPDATE issuance_requests SET status = CASE
        WHEN status IN ('prepared','approved') THEN 'declined' ELSE 'revoking' END, updated_at = ?
        WHERE id = ? AND (status IN ('prepared','approved') OR (kind = 'create-token' AND status IN ('issued','executing','unknown')))`)
        .bind(this.store.now(), row.id),
      this.store.db
        .prepare(
          "INSERT INTO issuance_events SELECT ?, ?, ?, 'cancel-requested', ? WHERE changes() = 1",
        )
        .bind(crypto.randomUUID(), row.id, auth.subject, this.store.now()),
    ]);
    await this.cleanup(await this.store.request(requestId, auth));
    return this.view(await this.store.request(requestId, auth));
  }
  async reconcile() {
    const now = this.store.now();
    const stalledRows = await this.store.db
      .prepare(
        "SELECT * FROM issuance_requests WHERE status = 'executing' AND updated_at < ? LIMIT 200",
      )
      .bind(now - 60000)
      .all<IssuanceRequest>();
    const stalled = stalledRows.results;
    for (const row of stalled) await this.store.transition(row, "executing", "unknown");
    const pendingRows = await this.store.db
      .prepare(
        "SELECT * FROM issuance_requests WHERE (status IN ('prepared','approved','issued','revoking') OR (kind = 'create-token' AND status = 'unknown')) ORDER BY updated_at LIMIT 200",
      )
      .all<IssuanceRequest>();
    const rows = pendingRows.results;
    for (const row of rows) {
      try {
        await this.cleanup(row);
      } catch {
        await this.store.db
          .prepare("UPDATE issuance_requests SET updated_at = ? WHERE id = ?")
          .bind(now, row.id)
          .run();
      }
    }
    await this.store.pruneOutputs();
    await this.store.db.batch([
      this.store.db
        .prepare("DELETE FROM issuance_limits WHERE window < ?")
        .bind(Math.floor(now / 60000) - 2),
      this.store.db
        .prepare("DELETE FROM issuance_ephemeral WHERE expires_at < ?")
        .bind(now),
      this.store.db
        .prepare("DELETE FROM issuance_devices WHERE expires_at < ?")
        .bind(now),
    ]);
  }
  private async cleanup(row: IssuanceRequest) {
    const now = this.store.now();
    if (["revoked", "expired", "failed", "declined", "completed"].includes(row.status))
      return;
    if (row.kind === "api-request" && !["prepared", "approved"].includes(row.status))
      return;
    if (
      row.expires_at <= now &&
      !(
        row.token_id &&
        row.token_encrypted === null &&
        (row.status === "unknown" || row.status === "revoking")
      )
    ) {
      await this.store.transition(row, row.status, "expired");
      await this.store.db
        .prepare(
          "UPDATE issuance_requests SET token_encrypted = NULL WHERE id = ? AND status = 'expired'",
        )
        .bind(row.id)
        .run();
      return;
    }
    if (row.status === "prepared" || row.status === "approved") {
      if (row.approve_before <= now || !(await this.store.eligibleRequest(row)))
        await this.store.transition(row, row.status, "declined");
      else
        await this.store.db
          .prepare(
            "UPDATE issuance_requests SET updated_at = ? WHERE id = ? AND status = ?",
          )
          .bind(now, row.id, row.status)
          .run();
      return;
    }
    if (row.status === "issued") {
      if (await this.store.eligibleRequest(row)) {
        await this.store.db
          .prepare(
            "UPDATE issuance_requests SET updated_at = ? WHERE id = ? AND status = 'issued'",
          )
          .bind(now, row.id)
          .run();
        return;
      }
      await this.store.transition(row, "issued", "revoking");
      row = await this.store.request(row.id);
    }
    if (row.status !== "revoking" && row.status !== "unknown") return;
    const issuer = await this.store.issuer(row.issuer_id);
    const parent = await this.store.crypto.decrypt(issuer.parent_encrypted);
    const plan = await this.store.plan(row);
    if (row.token_id) {
      await this.provider.revoke(parent, plan.accountId, row.token_id);
      await this.store.transition(row, row.status, "revoked");
      await this.store.db
        .prepare(
          "UPDATE issuance_requests SET token_encrypted = NULL WHERE id = ? AND status = 'revoked'",
        )
        .bind(row.id)
        .run();
    } else {
      // A timed-out creation can become visible after this scan: keep scanning until expiry.
      await this.provider.revokeUncertain(parent, plan);
      await this.store.db
        .prepare("UPDATE issuance_requests SET updated_at = ? WHERE id = ?")
        .bind(now, row.id)
        .run();
    }
  }
  async use(auth: Auth, requestId: string, input: z.infer<typeof apiRequestSchema>) {
    const row = await this.store.request(requestId, auth);
    if (
      row.status !== "issued" ||
      row.expires_at <= this.store.now() ||
      !row.token_encrypted ||
      !(await this.store.eligibleRequest(row))
    ) {
      throw new PolicyError(403, "credential is unavailable, expired, or revoked");
    }
    const issuer = await this.store.issuer(row.issuer_id);
    const policy = policySchema.parse(
      JSON.parse(await this.store.crypto.decrypt(issuer.policy_encrypted)),
    );
    assertApiScope(input, policy);
    if (isTokenManagement(input))
      throw new PolicyError(403, "token management requires a new parent-token approval");
    const admitted = await this.store.db
      .prepare(
        "INSERT INTO issuance_limits VALUES (?, ?, 1) ON CONFLICT(key, window) DO UPDATE SET count = count + 1 WHERE count < 60 RETURNING count",
      )
      .bind(`credential-use:${issuer.tenant_id}`, Math.floor(this.store.now() / 60000))
      .first();
    if (!admitted)
      throw new PolicyError(
        429,
        "too many credential uses for this tenant; retry after one minute",
      );
    const secrets = new Set<string>();
    let request = input;
    if (request.body.kind === "json")
      request = {
        ...request,
        body: {
          kind: "json",
          value: await resolveSecrets(this.store, auth, request.body.value, secrets),
        },
      };
    await this.store
      .event(row.id, auth.subject, `use:${request.method}:${request.path}`)
      .run();
    let result;
    try {
      result = await providerRequest(
        this.send,
        await this.store.crypto.decrypt(row.token_encrypted),
        request,
      );
    } catch {
      throw new PolicyError(
        502,
        "provider operation did not complete; do not automatically repeat a mutation",
      );
    }
    return showOutput(
      this.store,
      await saveOutput(this.store, row.id, result, [...secrets]),
    );
  }
}
