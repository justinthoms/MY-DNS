# MY-DNS: ISP NetControl

**ISP NetControl** is a filtering DNS resolver and firewall manager for
Internet service providers:

- DNS for subscribers with block lists, allow lists, list import, sinkhole
  or NXDOMAIN answers, caching and a query log. Only configured client
  networks are answered, so it is never an open resolver.
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

## Documentation

- [Installation](docs/INSTALL.md)
- [How licensing works and its limits](docs/LICENSING.md)
- [Operations: backups, upgrades, troubleshooting](docs/OPERATIONS.md)
- [Architecture and security design](docs/ARCHITECTURE.md)

## Development

Requirements: Go 1.26 and Node.js 22.

```bash
go test ./...
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
