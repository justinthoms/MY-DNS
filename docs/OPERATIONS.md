# Operations

Commands assume the default install directory. Run `docker compose`
commands from `/opt/isp-netcontrol/src/isp-netcontrol/deploy`.

## Backups

The installer schedules a daily compressed `pg_dump` (in
`/opt/isp-netcontrol/backups/`, 14 kept). To take one now:

```bash
sudo /opt/isp-netcontrol/src/isp-netcontrol/scripts/backup.sh
```

Copy the dumps **and `/opt/isp-netcontrol/.env`** off the server.

A database restored on the *same* server keeps its
license and trial state. Restored on *different* hardware, the license
state fails its integrity check (it is bound to the hardware) and the
server must be activated again; use a hardware migration for that.

## Upgrading

Unpack the new release and run its installer with the same options as
before. Secrets, the database, certificates and the license state are
kept; the images are rebuilt and the containers replaced. Database schema
changes are applied automatically at start-up.

The vendor runs `set-trusted-keys.sh` on each new release before shipping
it ([installation guide, step 0](INSTALL.md#0-prepare-the-package-vendor)).

## Licenses: renewal, revocation, hardware migration

These are done by the vendor on the license server. The server picks up
renewals and revocations at its next status sync; force one with
**License → Sync now**. To move a license to a replacement server (or after
reinstalling the operating system, which changes the machine ID), the vendor
releases it from the old hardware and you activate it on the new server.
See [LICENSING.md](LICENSING.md).

## Block lists: export, import and subscriptions

- **Export** (DNS filtering → Export): text (one domain per line), hosts
  file, or CSV with category, note and source. The CSV re-imports with its
  categories, so it doubles as a backup of the lists.
- **Import**: into the block or allow list. *Merge* adds new entries;
  *Replace* first removes the hand-made entries of that list (subscription
  entries stay). Plain lists, hosts files, Adblock-style `||domain^` rules
  and CSV are understood; anything else is skipped and counted.
- **Subscriptions** download a list from a URL every 24 hours (or on
  **Refresh**). The server needs outbound HTTPS to the list's host. A failed
  or empty download keeps the previous entries, and an entry you add by hand
  is never overwritten or removed by a subscription.

## DNS records

**DNS records** holds local A, AAAA, CNAME, TXT, MX and PTR records. They
are answered before filtering, also when the license has expired, and take
effect immediately. A name may hold a CNAME or other records, not both.
Use **DNS filtering → Check a domain** to see how a name is answered.

## Statistics

Query counters are stored per minute in the database and kept for 30 days,
so the dashboard graph survives restarts. The top lists come from the query
log (7 days by default, `NC_QUERY_LOG_DAYS`) and need the query-log feature.

## Administrators and recovery

Add NOC staff under **Administrators**. If someone is locked out or has lost
their authenticator, run on the server:

```bash
sudo docker compose -f /opt/isp-netcontrol/src/isp-netcontrol/deploy/docker-compose.yml exec api isp-netcontrol admin list
```

```bash
sudo docker compose -f /opt/isp-netcontrol/src/isp-netcontrol/deploy/docker-compose.yml exec api isp-netcontrol admin reset-password noc@your-isp.example
```

`reset-password` prints a temporary password that must be changed at the
next sign-in; `reset-2fa` removes two-factor authentication so it is set up
again. Both end the user's sessions and are recorded in the audit log.

## Recursive resolver (Unbound)

By default ISP NetControl forwards the queries it cannot answer itself to
public resolvers (1.1.1.1 and 8.8.8.8). With `--with-unbound` the installer
sets up Unbound on the same server instead:

- it listens only on `127.0.0.1:5335` (never on port 53, never to the
  internet), so it serves only ISP NetControl;
- it resolves from the root servers and validates **DNSSEC** (forged
  answers become SERVFAIL);
- threads and cache are sized from the server's CPUs and memory
  (at most 8 threads; message cache RAM/16, 64 MB to 1 GB; record cache
  twice that), with prefetching and serve-expired (popular names are
  refreshed before they expire, and stale answers are served for up to a
  day if the authoritative servers are unreachable).

On a new installation, ISP NetControl uses Unbound automatically. On an
existing installation the saved upstreams are kept: set **DNS settings →
Upstream resolvers** to `127.0.0.1:5335` to switch. Keep a public resolver
as a second upstream if you want a fallback.

The configuration is `/etc/unbound/unbound.conf.d/isp-netcontrol.conf`;
re-running the installer rewrites it. Check Unbound:

```bash
systemctl status unbound
```

```bash
dig @127.0.0.1 -p 5335 example.com
```

```bash
dig @127.0.0.1 -p 5335 dnssec-failed.org
```

The last one must return `SERVFAIL` (that domain is deliberately signed
wrongly). Unbound needs outbound UDP and TCP port 53 to the internet.

## Query log retention

**Query log → Keep queries for** sets how long queries are kept (1 hour to
90 days). Older entries are deleted every 10 minutes. On a busy resolver a
short retention such as 12 hours keeps the database small.

## Listen addresses

**DNS settings → Listen on** chooses all addresses or specific interfaces
and IPs. A change is applied immediately; if an address cannot be used the
previous addresses stay active. If a chosen address disappears while the
server is stopped, it starts on `NC_DNS_LISTEN` from the installer instead,
so DNS keeps answering.

## Anycast

See [ANYCAST.md](ANYCAST.md). Before maintenance on an anycast server, set
**Anycast → Maintenance (withdraw)**, and set it back to **Auto** afterwards.

## Logs and health

```bash
sudo docker compose ps
```

```bash
sudo docker compose logs --tail 200 api
```

Every administrative action is recorded in the **Audit log** of the
console (sign-ins, failed sign-ins, lockouts, license changes, DNS and
firewall changes).

## Troubleshooting

**"license server: this license is already activated on a different server"**
The license is bound to other hardware. Ask the vendor to release it (hardware migration).

**Online activation: "certificate relies on legacy Common Name" or "unknown authority"**
The license server uses a self-signed or private certificate. Re-run the
installer with `--lm-ca <its CA certificate>`.

**DNS: clients get REFUSED**
Their address is not in **DNS settings → Allowed client networks**.

**DNS: SERVFAIL for every name with Unbound**
Check `systemctl status unbound` and that the server can reach the
internet on UDP and TCP port 53 (`dig @198.41.0.4 . NS`). A wrong system
clock also breaks DNSSEC validation: check `timedatectl`.

**DNS: SERVFAIL for every name**
No upstream resolver answers. Check **DNS settings → Upstream resolvers**
and that the server can reach them on port 53.

**Port 53 already in use during installation**
Another DNS server (bind9, dnsmasq, unbound) is running. Stop it, or use
`--dns-listen` with addresses it does not use.

**Firewall page shows an nft error**
The kernel lacks nftables support, or the container cannot use it. Check
`sudo docker compose exec api nft list tables`. Install with `--no-firewall`
to turn the feature off.

**Locked out after failed sign-ins**
Accounts lock for 15 minutes after 5 failures (password or two-factor code).

**An administrator lost their authenticator**
Reset two-factor in the database; the user enrols again at the next sign-in:

```bash
sudo docker compose exec postgres psql -U isp_netcontrol -d isp_netcontrol -c "UPDATE admin_users SET totp_enabled=false, totp_secret_enc=NULL WHERE email='you@example.com'"
```
