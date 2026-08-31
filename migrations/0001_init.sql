CREATE TABLE api_keys (
  id TEXT PRIMARY KEY,
  key_prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,
  label_encrypted TEXT,
  scopes_encrypted TEXT,
  permission TEXT NOT NULL,
  mode TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked INTEGER NOT NULL DEFAULT 0
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
  host TEXT,
  secret_name TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);
