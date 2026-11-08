# Changelog

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
