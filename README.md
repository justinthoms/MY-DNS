# MY-DNS: ISP NetControl

**ISP NetControl** is a filtering DNS resolver and firewall manager for
Internet service providers:

- DNS for subscribers with block lists and allow lists (export and import
  as text, hosts file or CSV), block-list subscriptions from a URL refreshed
  daily, sinkhole or NXDOMAIN answers, caching and a query log. Only
  configured client networks are answered, so it is never an open resolver.
- Local DNS records (A, AAAA, CNAME, TXT, MX, PTR, wildcards) for internal
  hosts, overrides and reverse lookups.
- A NOC dashboard: query rate, result distribution, response time, query
  types, blocked categories, top domains and clients, upstream and system
  health, with a dark theme.
- Choose which interfaces and IP addresses DNS listens on, applied live.
- Anycast support: health checks withdraw this server's anycast routes
  (iBGP, OSPF, IS-IS via FRR) when DNS fails, and announce them on recovery.
- Several administrators, and a recovery command for lost passwords or
  authenticators.
- Firewall management through its own nftables table (`inet isp_netcontrol`);
  the server's existing firewall rules are never changed.
- A web console with mandatory two-factor authentication, CSRF protection,
  account lockout and an audit log.
- Licensing: a 30-day trial, then a signed license (Ed25519) activated online
  or offline, with optional status sync for renewals and revocations.
  Licenses are issued by the vendor's separate license server, which is not
  part of this repository.

Stack: Go (Fiber), Next.js, PostgreSQL 16, Docker Compose, Nginx with HTTPS,
Ubuntu 24.04.

## Screenshots

The console of a running installation, with demo data (example domains,
documentation IP ranges, and a synthetic traffic history for the graph).

### Dashboard
A NOC-style overview for 15 minutes to 30 days, refreshed every 30 seconds:
total queries, queries per second, success rate, blocked share, upstream
response time and cache hit rate (each compared with the previous period);
query rate by result; result distribution; top domains; response time;
query types; blocked queries by category; system health (DNS listeners,
upstream resolvers, database, firewall, anycast, license, server load);
top blocked domains, top clients and upstream resolver status. Dark theme
by default, with a Light / System switch.

![Dashboard, dark theme](docs/screenshots/03-dashboard.png)

![Dashboard, light theme](docs/screenshots/03-dashboard-light.png)

### DNS filtering
"Check a domain" shows how a name is answered and which entry decides it.
Block and allow lists can be exported (text, hosts file, CSV) and a blocked
domain also blocks its subdomains.

![DNS filtering](docs/screenshots/04-dns-filtering.png)

### Import and subscriptions
Import into either list (merge, or replace the hand-made entries) from plain
lists, hosts files, Adblock-style rules or CSV. Subscribe to public block
lists by URL; they refresh every 24 hours.

![Import a list](docs/screenshots/12-import.png)

![Block list subscriptions](docs/screenshots/11-subscriptions.png)

### DNS records
Local A, AAAA, CNAME, TXT, MX and PTR records, answered before filtering.
`*.name` matches every name below it; PTR records accept an IP address.

![DNS records](docs/screenshots/10-dns-records.png)

### Query log
Every query with its client, type and result, in pages of 25 to 200 rows,
with tabs for blocked, refused and failed queries, CSV export, and a
retention setting (for example 12 hours) after which entries are deleted.

![Query log](docs/screenshots/05-query-log.png)

### Listen on
Serve DNS on all addresses, or only on chosen interfaces (e.g. `ens33`,
`anycast0`) or single IPs. Applied live; new addresses on a chosen
interface are picked up within a minute.

![Listen on](docs/screenshots/13-listen.png)

### Anycast
Health-based route control for anycast DNS with FRR. When DNS fails a
number of checks in a row, the anycast interface is taken down so FRR
withdraws the routes; it comes back up when DNS recovers. Maintenance
mode, force announce and a monitor-only mode. See [docs/ANYCAST.md](docs/ANYCAST.md).

![Anycast](docs/screenshots/14-anycast.png)

### Administrators
Each NOC engineer gets their own account with mandatory two-factor
authentication.

![Administrators](docs/screenshots/15-admins.png)

### Firewall
Networks blocked by source, destination or both, and the nftables ruleset
actually applied to the kernel (only the `inet isp_netcontrol` table).

![Firewall](docs/screenshots/06-firewall.png)

### DNS settings
Upstream resolvers, allowed client networks (no open resolver) and how
blocked names are answered.

![DNS settings](docs/screenshots/07-dns-settings.png)

### License
License status, hardware ID, online and offline activation, and status sync.

![License](docs/screenshots/08-license.png)

### Audit log
Every sign-in and administrative change.

![Audit log](docs/screenshots/09-audit-log.png)

### Sign-in with mandatory two-factor authentication

| Sign-in | Two-factor code |
|---|---|
| ![Sign-in](docs/screenshots/01-sign-in.png) | ![Two-factor code](docs/screenshots/02-two-factor.png) |

## Documentation

- [Installation](docs/INSTALL.md)
- [How licensing works and its limits](docs/LICENSING.md)
- [Operations: backups, upgrades, troubleshooting](docs/OPERATIONS.md)
- [Anycast with FRR (iBGP, OSPF, IS-IS)](docs/ANYCAST.md)
- [Architecture and security design](docs/ARCHITECTURE.md)
- [Changelog](CHANGELOG.md)

## Development

Requirements: Go 1.26 and Node.js 22.

```bash
go test ./...
```

Integration tests run the application against PostgreSQL when a database is given:

```bash
NC_TEST_DATABASE_URL=postgres://postgres:secret@127.0.0.1:5432/postgres go test ./isp-netcontrol/internal/nc/
```

Console in development mode (run the API with `NC_COOKIE_SECURE=false` for plain HTTP):

```bash
cd isp-netcontrol/web && npm ci && API_URL=http://127.0.0.1:8081 npm run dev
```

Release package (`dist/isp-netcontrol-<version>.zip`):

```bash
scripts/package.sh
```

`isp-netcontrol/internal/license/trusted_keys.go` is intentionally empty in
the repository. The vendor fills it with the license server's public key
using `isp-netcontrol/scripts/set-trusted-keys.sh` before building a release.
The installer and the Docker build refuse to run until that is done.
