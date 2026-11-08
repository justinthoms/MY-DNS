# MY-DNS: ISP NetControl

**ISP NetControl** is a filtering DNS resolver and firewall manager for
Internet service providers:

- DNS for subscribers with block lists and allow lists (export and import
  as text, hosts file or CSV), block-list subscriptions from a URL refreshed
  daily, sinkhole or NXDOMAIN answers, caching and a query log. Only
  configured client networks are answered, so it is never an open resolver.
- Local DNS records (A, AAAA, CNAME, TXT, MX, PTR, wildcards) for internal
  hosts, overrides and reverse lookups.
- A dashboard with a queries-over-time graph (total, blocked, refused,
  failed) for 1 hour to 30 days, and the top blocked domains and clients.
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
Queries over time for the chosen period (1 hour to 30 days) with a hover
readout for every series and a table view, summary figures, the top blocked
domains and top clients, and the state of licensing, DNS and the firewall.

![Dashboard](docs/screenshots/03-dashboard.png)

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
Every query with its client, type and result (forwarded, cached, local,
blocked, refused, failed), with CSV export.

![Query log](docs/screenshots/05-query-log.png)

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
