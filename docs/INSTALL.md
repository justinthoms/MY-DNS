# Installing ISP NetControl

ISP NetControl needs **Ubuntu 24.04 LTS** (server, 64-bit), root access, and
2 CPU cores, 2 GB RAM and 10 GB disk or more. The installer adds Docker and
Docker Compose from the Ubuntu archive if they are missing. Everything else
(PostgreSQL 16, Nginx, the application) runs in containers.

## 0. Prepare the package (vendor)

ISP NetControl only accepts licenses signed by keys it trusts. Before giving
the package to customers, the vendor builds the license server's public
key into it:

```bash
./isp-netcontrol/scripts/set-trusted-keys.sh https://licenses.example.com
```

The script downloads the public key(s) from `/api/v1/public-keys` and writes
them into `isp-netcontrol/internal/license/trusted_keys.go`. With a
self-signed license server certificate add `--cacert /path/to/ca.pem`. A
saved key file can be given instead of the URL.

The installer and the Docker build **refuse to run** until this is done.
After a key rotation on the license server, deployed servers learn the new
key automatically through the signed endorsement chain (see
[LICENSING.md](LICENSING.md#signing-key-rotation)).

## 1. Before you start (ISP)

- A dedicated Ubuntu 24.04 server. ISP NetControl serves DNS on port 53
  and manages its own nftables table on this server.
- Ports 53/udp and 53/tcp reachable from subscribers; 443 from
  administrators only (restrict it in your network firewall if possible).
- The package from your vendor (with their key built in, step 0), your
  license key, and the URL of the vendor's license server.

## 2. Install

```bash
unzip isp-netcontrol-1.3.1.zip -d isp-netcontrol-1.3.1
```

```bash
cd isp-netcontrol-1.3.1
```

```bash
sudo ./isp-netcontrol/scripts/install.sh --admin-email noc@your-isp.example --lm-url https://licenses.example.com
```

Useful options:

| Option | Purpose |
|--------|---------|
| `--lm-url URL` | Vendor's license server (online activation, status sync). Leave out for offline-only servers. |
| `--lm-ca FILE` | The license server's CA certificate, if it is self-signed. |
| `--dns-listen ADDRS` | Where to serve DNS. Default `:53` (all addresses). Example: `203.0.113.10:53,[2001:db8::10]:53`. |
| `--tls-cert/--tls-key` | Your own console certificate (default: self-signed). |
| `--no-firewall` | Do not manage nftables at all. |
| `--keep-resolved-stub` | Do not touch systemd-resolved (then use `--dns-listen` with specific addresses). |
| `--http-port/--https-port` | Console ports (default 80/443). |

On Ubuntu, systemd-resolved listens on 127.0.0.53:53. To free port 53 the
installer turns off only its *stub listener*
(`/etc/systemd/resolved.conf.d/isp-netcontrol.conf`); the server keeps
resolving names normally. Uninstalling restores it.

The installer prints the console URL, the **hardware ID** and an **initial
password** (shown only once). A **30-day trial** with every feature starts
at the first start.

Files:

| Path | Contents |
|------|----------|
| `/opt/isp-netcontrol/.env` | Secrets, including `NC_MASTER_KEY` (mode 600). Back it up. |
| `/opt/isp-netcontrol/tls/` | Console certificate and key |
| `/opt/isp-netcontrol/backups/` | Daily database dumps (02:43), the newest 14 are kept |
| `/var/lib/isp-netcontrol/` | License state file |

## 3. First sign-in and activation

1. Open the console URL and sign in with the email and initial password.
2. You must set up **two-factor authentication** (scan the QR code with an
   authenticator app) and **choose a new password** (12+ characters).
3. Open **License**:
   - **Online:** enter the license key and the license server URL, then
     click **Activate**. The status changes to *Licensed*.
   - **Offline:** send the **hardware ID** shown on this page to your
     vendor. They return a license file (`.lic`); upload or paste it under
     **Activate offline**.
4. Leave **status sync** enabled if the server can reach the license server,
   so renewals install themselves.

## 4. Configure and go live

1. **DNS settings**
   - *Upstream resolvers*: your existing recursive resolvers, or public ones.
   - *Allowed client networks*: the networks your subscribers use. The
     default covers private, CGNAT (100.64.0.0/10) and loopback ranges.
     **Add your public subscriber ranges** if subscribers have public
     addresses. All other clients are refused.
   - *Blocked domains get*: NXDOMAIN, or a sinkhole address.
2. **DNS filtering**: add domains, or import a list (plain domains or hosts-file format).
3. **Firewall**: add networks to block. Rules apply immediately to the
   `inet isp_netcontrol` table. Your existing firewall rules are never changed.
4. Test from a subscriber network:
   ```bash
   dig @<server-address> example.com
   ```
   then a blocked domain, which should return `NXDOMAIN`.
5. Point subscribers at the server (DHCP option 6 / IPv6 RDNSS, or your
   BRAS/PPPoE profile).

## Verifying the installation

```bash
cd /opt/isp-netcontrol/src/isp-netcontrol/deploy && sudo docker compose ps
```

Every service should be `Up` and the API `healthy`. Logs:

```bash
sudo docker compose logs --tail 100 api
```

## Uninstalling

```bash
sudo /opt/isp-netcontrol/src/isp-netcontrol/scripts/uninstall.sh
```

This removes the containers and ISP NetControl's nftables table only.
Without `--purge`, data is kept and a re-install continues with the same
trial or license. With `--purge`, the database, license state, certificates
and secrets are deleted.
