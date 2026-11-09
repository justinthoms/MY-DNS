# Changelog

## v1.4.3 (2026-11-09)

### Fixed
- The Unbound instance of v1.4.2 could not start on Ubuntu ("Could not open
  /etc/isp-netcontrol/unbound.conf: Permission denied"): Ubuntu's AppArmor
  profile only lets unbound read files under /etc/unbound. The configuration
  is now `/etc/unbound/isp-netcontrol/unbound.conf` (still separate from the
  system Unbound's configuration). Upgrading moves it.

## v1.4.2 (2026-11-09)

### Fixed
- `--with-unbound` failed with "interface: 127.0.0.1 present twice" on
  servers that already had an Unbound configuration: v1.4.0 added its
  settings to the system Unbound's `conf.d`. ISP NetControl now runs its own
  Unbound instance (`isp-netcontrol-unbound` service,
  `/etc/isp-netcontrol/unbound.conf`, own DNSSEC trust anchor) and never
  changes the system Unbound. Upgrading removes the v1.4.0 file again.
- When the installer installs the unbound package itself, the package's own
  service (which would take port 53) is kept from starting.

## v1.4.1 (2026-11-09)

### Fixed
- The Anycast page showed "Application error" until the first health-check
  event (the event list was sent as `null`).
- The dashboard could fail the same way while DNS was not listening.

## v1.4.0 (2026-11-09)

### New
- **Built-in recursive resolver**: `install.sh --with-unbound` installs
  Unbound on 127.0.0.1:5335, sized for the server, with DNSSEC
  validation, prefetching and serve-expired, and makes it the default
  upstream. `NC_DEFAULT_UPSTREAMS` sets the default upstreams.
- **Query log modes**: log every query, only blocked/refused/failed ones,
  or nothing; allowed queries can be sampled (1 in 10, 100 or 1000).
  The console warns if log entries were dropped under load.
- **Attack protection** (new **Protection** page): per-client rate limit
  (default 500 queries/s, exempt networks), minimal answers to ANY queries
  (RFC 8482), and detection of random-subdomain ("water torture") attacks
  that limits lookups for the attacked domain while cached names keep
  working. Active attacks and rate-limited clients are shown on the
  Protection page, the dashboard's system health and the query log
  (`ratelimited`, `throttled`).
- **Encrypted DNS**: DNS over TLS (port 853) and DNS over HTTPS
  (`/dns-query`) for subscribers, using the console certificate (reloaded
  when renewed), switchable under DNS settings. Upstreams can be encrypted
  with `tls://IP#name` (certificate checked, connections reused).
- `dnsbench`: load generator and stand-in upstream for capacity tests.

### Faster
- Sharded answer cache with bounded eviction (`NC_CACHE_SIZE`, default
  100,000 answers), one UDP socket per CPU (SO_REUSEPORT), and identical
  in-flight upstream queries merged into one. Measured on 4 shared cores
  with 200 clients: cached answers 87.7k to 110k queries/s, blocked 92k to
  120k, forwarded 4.2k to 23.5k (median 59 ms to 7 ms).

### Fixed
- Upgrades now restart Nginx, so changes to its configuration apply.
- Re-running the installer with `--lm-ca`, `--tls-cert` or `--tls-key`
  pointing at the already-installed files no longer fails.
- `install.sh --help` no longer prints part of the script.

## v1.3.1 (2026-11-09)

### Changed
- The console shows every time in the viewer's own time zone (IST in
  India), labelled with the zone name, instead of UTC. CSV exports keep
  UTC (column `time_utc`).

## v1.3.0 (2026-11-09)

### New
- **NOC dashboard**: six headline figures with change vs the previous
  period (total queries, queries per second with peak, success rate,
  blocked share, upstream response time, cache hit rate); query rate by
  result; result distribution bar; top domains; response-time chart; query
  types; blocked queries by category; system health; top blocked domains,
  top clients and upstream resolvers. 15-minute range and auto refresh.
- **Dark navy theme** (default) with a Dark / Light / System switch.
- New data: upstream response time per query, per-upstream health,
  NXDOMAIN answers, block-list category of each blocked query.
- API: `/api/dns/breakdown` (query types, block categories) and
  `/api/system/health`.

## v1.2.0 (2026-11-09)

### New
- **Anycast health control** for iBGP, OSPF and IS-IS (via FRR): the
  anycast interface is taken down after repeated failed DNS health checks
  (routes withdrawn) and brought up after recovery. Auto, maintenance and
  force-announce modes, monitor-only mode, safety guards (never the
  default-route interface), withdrawal on clean shutdown, events in the
  console and audit log. Guide: docs/ANYCAST.md.
- **Choose DNS listen interfaces and addresses** in DNS settings, applied
  live with rollback; new addresses on chosen interfaces are picked up.
- **Query log paging** (25-200 rows, page numbers) with result tabs
  (Blocked, Refused, Failed, ...); dashboard top lists link to the queries.
- **Query log retention** set in the console (1 hour to 90 days).
- **Administrators page** and `isp-netcontrol admin list | reset-password |
  reset-2fa` for recovery.

### Fixed
- The DNS server now always releases sockets when a rebind partly fails.
- The installer restarts Docker after freeing port 53 (v1.1.x installs
  could fail with "lookup registry-1.docker.io on 127.0.0.53:53").

## v1.1.0 (2026-11-08)

### New
- **Dashboard graph**: queries over time (total, blocked, refused, failed)
  for 1 hour, 24 hours, 7 days or 30 days, with a hover readout, a table
  view and summary figures. Counters are stored per minute for 30 days.
- **Top lists** on the dashboard: most blocked domains and busiest clients.
- **DNS records**: local A, AAAA, CNAME, TXT, MX and PTR records, with
  wildcards (`*.name`) and PTR from an IP address. Answered before
  filtering, available in every license state.
- **Block and allow list export** as text, hosts file or CSV.
- **Import into either list**, merge or replace; also understands CSV and
  Adblock-style `||domain^` rules.
- **Block-list subscriptions**: download public lists by URL, refreshed every
  24 hours; failed or empty downloads keep the old list, hand-made entries
  are never overwritten.
- **Check a domain**: shows whether a name is blocked, allowed, answered
  locally or forwarded, and which entry decides it.
- **Query log export** to CSV.

### Changed
- New query result "local" in the query log and statistics.
- Integration tests for the API against PostgreSQL.

### Upgrading
Run the installer of the new release with the same options. The database
is migrated automatically; existing lists, rules, licenses and settings are kept.

## v1.0.0 (2026-11-08)

First release of **ISP NetControl**.

### DNS
- Filtering resolver for subscribers (UDP and TCP, IPv4 and IPv6).
- Block and allow lists; a listed domain covers all its subdomains; allow
  entries win over block entries.
- List import in plain-domain or hosts-file format.
- Blocked names answered with NXDOMAIN or a sinkhole address.
- Answer cache that respects TTLs.
- Client networks allow-list, so the server is never an open resolver.
- Query log with search and filters, kept 7 days by default.

### Firewall
- Blocks networks by source, destination or both, for IPv4 and IPv6.
- Uses one nftables table (`inet isp_netcontrol`), replaced atomically on
  every change; no other table is ever touched.
- Removed when the feature is not licensed, and on uninstall.

### Console
- Next.js web console behind Nginx with HTTPS.
- Mandatory two-factor authentication (TOTP), enrolment forced at first
  sign-in; the initial password must be changed.
- CSRF tokens and Origin checks, account lockout after 5 failures,
  session timeouts, and an audit log of every administrative action.

### Licensing
- 30-day trial with all features; DNS keeps answering after it ends.
- Ed25519-signed licenses bound to the server's hardware ID, activated
  online or offline.
- Optional status sync for renewals and revocations, protected against replay.
- Clock-rollback and state-file tamper detection; tampering never extends
  a trial or license.
- Signing-key rotation through signed key endorsements, with no software
  update needed.

### Deployment
- Docker Compose stack: Go API, Next.js console, PostgreSQL 16, Nginx.
- Ubuntu 24.04 installer: Docker setup, generated secrets, TLS, frees
  port 53 from the systemd-resolved stub, daily database backups.
- Uninstall script that leaves the host firewall intact.

### Known limits
- Revocation takes effect at the next status sync and does not reach
  servers that never sync. See [docs/LICENSING.md](docs/LICENSING.md).
- Someone with root access can wipe all state and reinstall to start a
  new trial; this cannot be prevented on hardware the customer controls.
