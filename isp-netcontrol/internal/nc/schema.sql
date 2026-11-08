-- ISP NetControl schema (version 1). Admin users, sessions and the audit log
-- come from shared/authkit; license_state from internal/license.

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_blocklist (
  domain     TEXT PRIMARY KEY,
  category   TEXT NOT NULL DEFAULT 'custom',
  note       TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dns_allowlist (
  domain     TEXT PRIMARY KEY,
  category   TEXT NOT NULL DEFAULT 'allow',
  note       TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS firewall_rules (
  id         BIGSERIAL PRIMARY KEY,
  cidr       CIDR NOT NULL,
  direction  TEXT NOT NULL CHECK (direction IN ('src', 'dst', 'both')),
  note       TEXT NOT NULL DEFAULT '',
  enabled    BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (cidr, direction)
);

CREATE TABLE IF NOT EXISTS dns_query_log (
  id     BIGSERIAL PRIMARY KEY,
  at     TIMESTAMPTZ NOT NULL,
  client INET,
  qname  TEXT NOT NULL,
  qtype  TEXT NOT NULL,
  action TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS dns_query_log_at ON dns_query_log(at DESC);
