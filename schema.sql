CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS credentials_user ON credentials(user_id);

CREATE TABLE IF NOT EXISTS invites (
  token TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  used_at INTEGER
);

CREATE TABLE IF NOT EXISTS shares (
  code TEXT PRIMARY KEY,
  blob TEXT NOT NULL,
  user_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  size INTEGER NOT NULL,
  encrypted INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  ip TEXT,
  reported INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS shares_user ON shares(user_id);
CREATE INDEX IF NOT EXISTS shares_expires ON shares(expires_at);
CREATE INDEX IF NOT EXISTS shares_ip ON shares(ip, created_at);

CREATE TABLE IF NOT EXISTS anon_usage (
  hour INTEGER PRIMARY KEY,
  count INTEGER NOT NULL,
  bytes INTEGER NOT NULL
);
