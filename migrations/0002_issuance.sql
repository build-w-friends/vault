CREATE TABLE issuance_identity (id INTEGER PRIMARY KEY CHECK (id = 1), encrypted TEXT NOT NULL);
CREATE TABLE issuance_tenants (id TEXT PRIMARY KEY, label TEXT NOT NULL);
CREATE TABLE issuance_members (
  tenant_id TEXT NOT NULL REFERENCES issuance_tenants(id), subject TEXT NOT NULL,
  PRIMARY KEY (tenant_id, subject)
);
CREATE TABLE issuance_issuers (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES issuance_tenants(id),
  label TEXT NOT NULL, policy_encrypted TEXT NOT NULL, parent_encrypted TEXT NOT NULL,
  revoked_at INTEGER
);
CREATE TABLE issuance_grantees (
  issuer_id TEXT NOT NULL REFERENCES issuance_issuers(id), subject TEXT NOT NULL,
  PRIMARY KEY (issuer_id, subject)
);
CREATE TABLE issuance_auth (
  hash TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('browser', 'agent')),
  subject TEXT NOT NULL, tenant_id TEXT REFERENCES issuance_tenants(id),
  label TEXT NOT NULL, csrf TEXT NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER
);
CREATE TABLE issuance_ephemeral (
  id TEXT PRIMARY KEY, encrypted TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE issuance_devices (
  id TEXT PRIMARY KEY, challenge TEXT NOT NULL, label TEXT NOT NULL, ip_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL, subject TEXT, tenant_id TEXT REFERENCES issuance_tenants(id),
  created_at INTEGER NOT NULL
);
CREATE INDEX issuance_devices_rate ON issuance_devices(ip_hash, created_at);
CREATE TABLE issuance_requests (
  id TEXT PRIMARY KEY, issuer_id TEXT NOT NULL REFERENCES issuance_issuers(id),
  subject TEXT NOT NULL, auth_hash TEXT NOT NULL REFERENCES issuance_auth(hash),
  plan_encrypted TEXT NOT NULL, input_hash TEXT NOT NULL, created_at INTEGER NOT NULL,
  approve_before INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('prepared','approved','declined','executing','issued','completed','unknown','failed','revoking','revoked','expired')),
  kind TEXT NOT NULL CHECK (kind IN ('api-request','create-token')),
  output_id TEXT, token_id TEXT, token_encrypted TEXT, updated_at INTEGER NOT NULL
);
CREATE INDEX issuance_requests_cleanup ON issuance_requests(status, updated_at);
CREATE TABLE issuance_events (
  id TEXT PRIMARY KEY, request_id TEXT REFERENCES issuance_requests(id),
  actor TEXT NOT NULL, action TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE issuance_limits (
  key TEXT NOT NULL, window INTEGER NOT NULL, count INTEGER NOT NULL,
  PRIMARY KEY (key, window)
);

CREATE TABLE issuance_outputs (
  id TEXT PRIMARY KEY, request_id TEXT NOT NULL REFERENCES issuance_requests(id),
  encrypted TEXT NOT NULL, created_at INTEGER NOT NULL
);
