# Architecture

```
  Vendor license server  ◀── HTTPS: activation, status sync (optional) ──┐
  (separate product)                                                       │
                                        ┌──────────────────────────────────┴───────┐
  Subscribers ── DNS :53 ─────────────▶ │ ISP NetControl                           │
                                        │ Go API (Fiber)                           │
  Administrators ── HTTPS :443 ──▶ Nginx│   ├─ DNS resolver (miekg/dns)            │
                          ├─ Next.js    │   ├─ nft table inet isp_netcontrol       │
                          └─ /api ─────▶│   └─ license engine (trial, tamper)      │
                                        │ PostgreSQL 16 + /var/lib/isp-netcontrol  │
                                        └──────────────────────────────────────────┘
```

## Repository layout

| Path | Contents |
|------|----------|
| `shared/licensecore` | Signed-envelope format (Ed25519), license and status payloads, key endorsements, license bundles. |
| `shared/authkit` | Console authentication: Argon2id passwords, server-side sessions, forced TOTP enrolment, CSRF, lockout, audit log. |
| `isp-netcontrol/` | Go API with DNS resolver, firewall manager and license engine (`internal/…`), Next.js console (`web`), Docker deployment (`deploy`), scripts. |
| `docs/` | Installation, licensing, operations. |
| `scripts/` | Release packaging. |

## Security design

- **Licenses** are Ed25519-signed by the vendor's license server; this
  product holds only public keys. See [LICENSING.md](LICENSING.md).
- **Console**: Argon2id password hashes; random session IDs stored hashed;
  HttpOnly + Secure + SameSite=Strict cookies; 30-minute idle and 12-hour
  absolute timeouts; **TOTP is mandatory** (enrolment forced at first
  sign-in, codes cannot be reused); bootstrap passwords must be changed;
  5 failures lock an account for 15 minutes; a CSRF token on every
  state-changing request plus an Origin check; every action audited.
- **HTTP**: Nginx terminates TLS 1.2/1.3 and adds HSTS, CSP,
  `X-Frame-Options: DENY`, `nosniff`, `no-referrer`. The API only listens on
  loopback.
- **Containers**: all capabilities dropped; read-only root filesystems where
  possible; the ISP NetControl API keeps only `NET_ADMIN` (its own nft table)
  and `NET_BIND_SERVICE` (port 53).
- **DNS**: only clients in the allowed networks get answers (no open
  resolver). Upstream answers are cached per their TTL.
- **Firewall**: one table, replaced atomically per change; never touches
  other tables; removed when the feature is not licensed or on uninstall.

## Stack

Go 1.26 with Fiber v2, pgx v5, miekg/dns and pquerna/otp; Next.js 15 / React 19
console (TypeScript, standalone output); PostgreSQL 16; Nginx 1.28; Docker
Compose; Ubuntu 24.04.
