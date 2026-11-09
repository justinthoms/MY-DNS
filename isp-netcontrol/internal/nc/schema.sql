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

-- ---- v1.1.0 ---------------------------------------------------------------

-- Local DNS records, answered before filtering and forwarding.
CREATE TABLE IF NOT EXISTS dns_records (
  id         BIGSERIAL PRIMARY KEY,
  name       TEXT NOT NULL,
  type       TEXT NOT NULL CHECK (type IN ('A', 'AAAA', 'CNAME', 'TXT', 'MX', 'PTR')),
  value      TEXT NOT NULL,
  ttl        INT NOT NULL DEFAULT 300 CHECK (ttl BETWEEN 0 AND 86400),
  priority   INT NOT NULL DEFAULT 10 CHECK (priority BETWEEN 0 AND 65535),
  note       TEXT NOT NULL DEFAULT '',
  enabled    BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (name, type, value)
);

-- Query counters per minute, for the dashboard graph (kept 30 days).
CREATE TABLE IF NOT EXISTS dns_stats_minute (
  minute    TIMESTAMPTZ PRIMARY KEY,
  total     BIGINT NOT NULL DEFAULT 0,
  forwarded BIGINT NOT NULL DEFAULT 0,
  cached    BIGINT NOT NULL DEFAULT 0,
  blocked   BIGINT NOT NULL DEFAULT 0,
  refused   BIGINT NOT NULL DEFAULT 0,
  failed    BIGINT NOT NULL DEFAULT 0,
  local     BIGINT NOT NULL DEFAULT 0
);

-- Block lists downloaded from a URL and refreshed automatically.
CREATE TABLE IF NOT EXISTS blocklist_sources (
  id            BIGSERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  url           TEXT NOT NULL UNIQUE,
  category      TEXT NOT NULL DEFAULT 'subscription',
  enabled       BOOLEAN NOT NULL DEFAULT true,
  last_fetch_at TIMESTAMPTZ,
  last_status   TEXT NOT NULL DEFAULT '',
  entries       INT NOT NULL DEFAULT 0,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Entries that came from a subscription; NULL = added by hand.
ALTER TABLE dns_blocklist ADD COLUMN IF NOT EXISTS source_id BIGINT REFERENCES blocklist_sources(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS dns_blocklist_source ON dns_blocklist(source_id);

-- ---- v1.2.0 ---------------------------------------------------------------
-- Fast "Blocked / Refused / Failed" tabs in the query log.
CREATE INDEX IF NOT EXISTS dns_query_log_action_at ON dns_query_log(action, at DESC);
