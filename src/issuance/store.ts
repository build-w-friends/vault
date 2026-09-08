import { z } from "zod";
import type { VaultCrypto } from "../crypto.ts";
import { PolicyError } from "../policy.ts";
import {
  adminSchema,
  identitySchema,
  loginStateSchema,
  planSchema,
  policySchema,
  type Auth,
  type Issuer,
  type IssuanceRequest,
} from "./contracts.ts";

const eligibleSql = `i.revoked_at IS NULL
  AND EXISTS (SELECT 1 FROM issuance_members m WHERE m.tenant_id = i.tenant_id AND m.subject = ?)
  AND EXISTS (SELECT 1 FROM issuance_grantees g WHERE g.issuer_id = i.id AND g.subject IN ('*', ?))`;
const requestEligibleSql = `EXISTS (SELECT 1 FROM issuance_issuers i WHERE i.id = issuance_requests.issuer_id
  AND ${eligibleSql}) AND EXISTS (SELECT 1 FROM issuance_auth a WHERE a.hash = issuance_requests.auth_hash
  AND a.revoked_at IS NULL AND a.expires_at > ?)`;

export class IssuanceStore {
  constructor(
    readonly db: D1Database,
    readonly crypto: VaultCrypto,
    readonly now = () => Date.now(),
  ) {}
  async setup() {
    const tenants = (
      await this.db
        .prepare("SELECT id, label FROM issuance_tenants ORDER BY label, id")
        .all<{ id: string; label: string }>()
    ).results;
    const members = (
      await this.db
        .prepare("SELECT tenant_id, subject FROM issuance_members ORDER BY subject")
        .all<{ tenant_id: string; subject: string }>()
    ).results;
    const identity = await this.db
      .prepare("SELECT id FROM issuance_identity WHERE id = 1")
      .first();
    return {
      identityConfigured: identity !== null,
      tenants: tenants.map((tenant) => ({
        ...tenant,
        members: members
          .filter((member) => member.tenant_id === tenant.id)
          .map((member) => member.subject),
      })),
    };
  }
  async identity() {
    const row = await this.db
      .prepare("SELECT encrypted FROM issuance_identity WHERE id = 1")
      .first<{ encrypted: string }>();
    if (!row)
      throw new PolicyError(503, "Vault issuance requires GitHub identity configuration");
    return identitySchema.parse(JSON.parse(await this.crypto.decrypt(row.encrypted)));
  }
  async admin(input: z.infer<typeof adminSchema>, actor: string) {
    const statements: D1PreparedStatement[] = [];
    const now = this.now();
    switch (input.action) {
      case "identity":
        statements.push(
          this.db
            .prepare(
              "INSERT INTO issuance_identity VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET encrypted = excluded.encrypted",
            )
            .bind(await this.crypto.encrypt(JSON.stringify(input.config))),
        );
        break;
      case "tenant":
        statements.push(
          this.db
            .prepare(
              "INSERT INTO issuance_tenants VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET label = excluded.label",
            )
            .bind(input.id, input.label),
        );
        break;
      case "member":
        statements.push(
          input.operation === "add"
            ? this.db
                .prepare("INSERT OR IGNORE INTO issuance_members VALUES (?, ?)")
                .bind(input.tenantId, input.subject)
            : this.db
                .prepare(
                  "DELETE FROM issuance_members WHERE tenant_id = ? AND subject = ?",
                )
                .bind(input.tenantId, input.subject),
        );
        if (input.operation === "remove")
          statements.push(
            this.db
              .prepare(`UPDATE issuance_requests SET status = CASE WHEN status IN ('prepared','approved') THEN 'declined' ELSE 'revoking' END, updated_at = ?
          WHERE subject = ? AND issuer_id IN (SELECT id FROM issuance_issuers WHERE tenant_id = ?) AND (status IN ('prepared','approved') OR (kind = 'create-token' AND status IN ('executing','issued','unknown')))`)
              .bind(now, input.subject, input.tenantId),
          );
        break;
      case "issuer": {
        if (
          await this.db
            .prepare("SELECT id FROM issuance_issuers WHERE id = ?")
            .bind(input.id)
            .first()
        )
          throw new PolicyError(
            409,
            "issuer already exists; revoke it and register a new issuer to change policy",
          );
        statements.push(
          this.db
            .prepare("INSERT INTO issuance_issuers VALUES (?, ?, ?, ?, ?, NULL)")
            .bind(
              input.id,
              input.tenantId,
              input.label,
              await this.crypto.encrypt(JSON.stringify(input.policy)),
              await this.crypto.encrypt(input.parentToken),
            ),
        );
        for (const member of input.audience === "tenant"
          ? ["*"]
          : [...new Set(input.audience)]) {
          statements.push(
            this.db
              .prepare("INSERT INTO issuance_grantees VALUES (?, ?)")
              .bind(input.id, member),
          );
        }
        break;
      }
      case "revoke-issuer":
        statements.push(
          this.db
            .prepare(
              "UPDATE issuance_issuers SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            )
            .bind(now, input.issuerId),
          this.db
            .prepare(`UPDATE issuance_requests SET status = CASE WHEN status IN ('prepared','approved') THEN 'declined' ELSE 'revoking' END, updated_at = ?
          WHERE issuer_id = ? AND (status IN ('prepared','approved') OR (kind = 'create-token' AND status IN ('executing','issued','unknown')))`)
            .bind(now, input.issuerId),
        );
        break;
      case "revoke-session":
        statements.push(
          this.db
            .prepare("UPDATE issuance_auth SET revoked_at = ? WHERE hash = ?")
            .bind(now, input.sessionId),
          this.db
            .prepare(`UPDATE issuance_requests SET status = CASE WHEN status IN ('prepared','approved') THEN 'declined' ELSE 'revoking' END, updated_at = ?
          WHERE auth_hash = ? AND (status IN ('prepared','approved') OR (kind = 'create-token' AND status IN ('executing','issued','unknown')))`)
            .bind(now, input.sessionId),
        );
        break;
    }
    const action =
      input.action === "member"
        ? `${input.action}:${input.operation}:${input.tenantId}:${input.subject}`
        : input.action === "issuer" || input.action === "tenant"
          ? `${input.action}:${input.id}`
          : input.action === "revoke-issuer"
            ? `${input.action}:${input.issuerId}`
            : input.action === "revoke-session"
              ? `${input.action}:${input.sessionId}`
              : input.action;
    statements.push(this.event(null, actor, action));
    await this.db.batch(statements);
  }
  async auth(token: string | undefined, kind: Auth["kind"]): Promise<Auth> {
    if (!token) throw new PolicyError(401, "sign in to Vault");
    const row = await this.db
      .prepare(
        "SELECT * FROM issuance_auth WHERE hash = ? AND kind = ? AND revoked_at IS NULL AND expires_at > ?",
      )
      .bind(await this.crypto.sha256(token), kind, this.now())
      .first<Auth>();
    if (!row) throw new PolicyError(401, "Vault session is invalid or expired");
    if (
      kind === "agent" &&
      !(await this.db
        .prepare("SELECT 1 FROM issuance_members WHERE tenant_id = ? AND subject = ?")
        .bind(row.tenant_id, row.subject)
        .first())
    ) {
      throw new PolicyError(403, "tenant membership is required");
    }
    return row;
  }
  async membersTenants(subject: string) {
    return (
      await this.db
        .prepare(
          "SELECT t.id, t.label FROM issuance_tenants t JOIN issuance_members m ON m.tenant_id = t.id WHERE m.subject = ? ORDER BY t.label",
        )
        .bind(subject)
        .all<{ id: string; label: string }>()
    ).results;
  }
  async issuers(auth: Auth) {
    const rows = (
      await this.db
        .prepare(
          `SELECT i.* FROM issuance_issuers i WHERE i.tenant_id = ? AND ${eligibleSql} ORDER BY i.id`,
        )
        .bind(auth.tenant_id, auth.subject, auth.subject)
        .all<Issuer>()
    ).results;
    return Promise.all(
      rows.map(async (row) => ({
        id: row.id,
        tenantId: row.tenant_id,
        label: row.label,
        policy: policySchema.parse(
          JSON.parse(await this.crypto.decrypt(row.policy_encrypted)),
        ),
        approvalRequired: true,
      })),
    );
  }
  async issuer(id: string): Promise<Issuer> {
    const row = await this.db
      .prepare("SELECT * FROM issuance_issuers WHERE id = ?")
      .bind(id)
      .first<Issuer>();
    if (!row) throw new PolicyError(404, "issuer not found");
    return row;
  }
  async requireIssuer(auth: Auth, id: string) {
    const row = await this.db
      .prepare(
        `SELECT i.* FROM issuance_issuers i WHERE i.id = ? AND i.tenant_id = ? AND ${eligibleSql}`,
      )
      .bind(id, auth.tenant_id, auth.subject, auth.subject)
      .first<Issuer>();
    if (!row) throw new PolicyError(403, "issuer is not available to this user");
    return row;
  }
  async request(id: string, auth?: Auth): Promise<IssuanceRequest> {
    const row = await this.db
      .prepare("SELECT * FROM issuance_requests WHERE id = ?")
      .bind(id)
      .first<IssuanceRequest>();
    if (
      !row ||
      (auth &&
        (row.subject !== auth.subject ||
          (auth.kind === "agent" && row.auth_hash !== auth.hash)))
    )
      throw new PolicyError(404, "request not found");
    return row;
  }
  async plan(row: IssuanceRequest) {
    return planSchema.parse(JSON.parse(await this.crypto.decrypt(row.plan_encrypted)));
  }
  async eligibleRequest(row: IssuanceRequest) {
    return Boolean(
      await this.db
        .prepare(`SELECT 1 FROM issuance_requests WHERE id = ? AND ${requestEligibleSql}`)
        .bind(row.id, row.subject, row.subject, this.now())
        .first(),
    );
  }
  async transition(
    row: IssuanceRequest,
    from: IssuanceRequest["status"],
    to: IssuanceRequest["status"],
    eligibility: "none" | "approval" | "active" = "none",
  ) {
    const now = this.now();
    const clauses = ["id = ?", "status = ?"];
    const args: (string | number)[] = [to, now, row.id, from];
    if (eligibility === "approval") {
      clauses.push("approve_before > ?");
      args.push(now);
    }
    if (eligibility !== "none") {
      clauses.push("expires_at > ?", requestEligibleSql);
      args.push(now, row.subject, row.subject, now);
    }
    const sql = `UPDATE issuance_requests SET status = ?, updated_at = ? WHERE ${clauses.join(" AND ")}`;
    const results = await this.db.batch([
      this.db.prepare(sql).bind(...args),
      this.db
        .prepare("INSERT INTO issuance_events SELECT ?, ?, ?, ?, ? WHERE changes() = 1")
        .bind(crypto.randomUUID(), row.id, row.subject, to, now),
    ]);
    return results[0]?.meta.changes === 1;
  }
  event(requestId: string | null, actor: string, action: string) {
    return this.db
      .prepare("INSERT INTO issuance_events VALUES (?, ?, ?, ?, ?)")
      .bind(crypto.randomUUID(), requestId, actor, action, this.now());
  }
  async pruneOutputs() {
    const expired = `SELECT o.id FROM issuance_outputs o
      JOIN issuance_requests r ON r.id = o.request_id
      JOIN issuance_issuers i ON i.id = r.issuer_id
      JOIN issuance_auth a ON a.hash = r.auth_hash
      WHERE o.created_at <= ? OR a.expires_at <= ? OR a.revoked_at IS NOT NULL
        OR i.revoked_at IS NOT NULL
        OR NOT EXISTS (SELECT 1 FROM issuance_members m WHERE m.tenant_id = i.tenant_id AND m.subject = r.subject)
        OR NOT EXISTS (SELECT 1 FROM issuance_grantees g WHERE g.issuer_id = i.id AND g.subject IN ('*', r.subject))`;
    const now = this.now();
    await this.db.batch([
      this.db
        .prepare(
          `UPDATE issuance_requests SET output_id = NULL WHERE output_id IN (${expired})`,
        )
        .bind(now - 86400000, now),
      this.db
        .prepare(`DELETE FROM issuance_outputs WHERE id IN (${expired})`)
        .bind(now - 86400000, now),
    ]);
  }
  async putEphemeral(id: string, value: z.infer<typeof loginStateSchema>, ttlMs: number) {
    await this.db
      .prepare("INSERT INTO issuance_ephemeral VALUES (?, ?, ?)")
      .bind(id, await this.crypto.encrypt(JSON.stringify(value)), this.now() + ttlMs)
      .run();
  }
  async takeEphemeral(id: string) {
    const row = await this.db
      .prepare(
        "DELETE FROM issuance_ephemeral WHERE id = ? AND expires_at > ? RETURNING encrypted",
      )
      .bind(id, this.now())
      .first<{ encrypted: string }>();
    if (!row) throw new PolicyError(401, "sign-in attempt expired or was already used");
    return loginStateSchema.parse(JSON.parse(await this.crypto.decrypt(row.encrypted)));
  }
}
