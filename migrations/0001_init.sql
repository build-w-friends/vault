CREATE TABLE master_key_wraps (
  fingerprint TEXT PRIMARY KEY,
  wrapped_data_key TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE api_keys (
  id TEXT PRIMARY KEY,
  key_prefix TEXT NOT NULL UNIQUE,
  key_hash TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,
  label_encrypted TEXT,
  scopes_encrypted TEXT,
  permission TEXT NOT NULL,
  mode TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  revoked_at TEXT
);

CREATE INDEX api_keys_active_idx
ON api_keys (type, revoked, expires_at);

CREATE TRIGGER prevent_last_active_user_key
BEFORE UPDATE OF revoked ON api_keys
WHEN OLD.type = 'user'
  AND OLD.revoked = 0
  AND NEW.revoked = 1
  AND OLD.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  AND (
    SELECT COUNT(*)
    FROM api_keys
    WHERE type = 'user'
      AND revoked = 0
      AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  ) <= 1
BEGIN
  SELECT RAISE(ABORT, 'cannot revoke the last active user key');
END;

CREATE TABLE bootstrap_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  claimed_at TEXT NOT NULL,
  key_prefix TEXT NOT NULL
);

CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE environments (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (project_id, name)
);

CREATE TABLE secrets (
  id TEXT PRIMARY KEY,
  environment_id TEXT NOT NULL REFERENCES environments (id) ON DELETE CASCADE,
  key_encrypted TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  value_encrypted TEXT NOT NULL,
  kind TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (environment_id, key_hash)
);

CREATE TABLE routes (
  id TEXT PRIMARY KEY,
  environment_id TEXT NOT NULL REFERENCES environments (id) ON DELETE CASCADE,
  host TEXT NOT NULL,
  secret_key_hash TEXT NOT NULL,
  inject TEXT NOT NULL,
  strip_headers TEXT NOT NULL,
  dummy_env_name TEXT NOT NULL,
  dummy_value TEXT NOT NULL,
  UNIQUE (environment_id, host)
);

CREATE TABLE audit_events (
  id TEXT PRIMARY KEY,
  key_prefix TEXT NOT NULL,
  action TEXT NOT NULL,
  host_encrypted TEXT,
  secret_name_encrypted TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX audit_events_created_idx
ON audit_events (created_at DESC, id DESC);
