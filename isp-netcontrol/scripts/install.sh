#!/usr/bin/env bash
# Installs ISP NetControl on Ubuntu 24.04 with Docker Compose, PostgreSQL 16
# and Nginx (HTTPS).
#
#   sudo ./isp-netcontrol/scripts/install.sh --admin-email noc@isp.example --lm-url https://licenses.vendor.example
#
# Options:
#   --admin-email EMAIL   First administrator's sign-in email (required)
#   --domain NAME         Name for the console certificate (default: this host's FQDN)
#   --lm-url URL          License Manager URL for online activation and status sync
#   --lm-ca FILE          CA certificate of a License Manager with a private certificate
#   --dns-listen ADDRS    DNS listen addresses (default ":53" = all addresses, UDP+TCP)
#   --tls-cert FILE       Console certificate chain (PEM); default: self-signed
#   --tls-key FILE        Private key for --tls-cert
#   --no-firewall         Do not manage nftables
#   --with-unbound        Install Unbound on 127.0.0.1:5335 as the recursive resolver
#                         (full recursion from the root servers, DNSSEC validation)
#   --keep-resolved-stub  Do not disable systemd-resolved's stub listener on port 53
#   --dir DIR             Install directory (default /opt/isp-netcontrol)
#   --http-port N / --https-port N   Console ports (default 80 / 443)
#   --force               Continue on an OS other than Ubuntu 24.04
#
# Re-running the script upgrades the installation and keeps .env, the
# database, the license state and the certificates.
set -euo pipefail

ADMIN_EMAIL="" DOMAIN="" LM_URL="" LM_CA="" DNS_LISTEN=":53" TLS_CERT="" TLS_KEY=""
FIREWALL=true WITH_UNBOUND=0 KEEP_STUB=0 FORCE=0 DIR=/opt/isp-netcontrol HTTP_PORT=80 HTTPS_PORT=443
STATE_DIR=/var/lib/isp-netcontrol

die() { echo "error: $*" >&2; exit 1; }
say() { echo "==> $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --admin-email) ADMIN_EMAIL="${2:?}"; shift 2 ;;
    --domain) DOMAIN="${2:?}"; shift 2 ;;
    --lm-url) LM_URL="${2:?}"; shift 2 ;;
    --lm-ca) LM_CA="${2:?}"; shift 2 ;;
    --dns-listen) DNS_LISTEN="${2:?}"; shift 2 ;;
    --tls-cert) TLS_CERT="${2:?}"; shift 2 ;;
    --tls-key) TLS_KEY="${2:?}"; shift 2 ;;
    --no-firewall) FIREWALL=false; shift ;;
    --with-unbound) WITH_UNBOUND=1; shift ;;
    --keep-resolved-stub) KEEP_STUB=1; shift ;;
    --dir) DIR="${2:?}"; shift 2 ;;
    --http-port) HTTP_PORT="${2:?}"; shift 2 ;;
    --https-port) HTTPS_PORT="${2:?}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
[[ "$ADMIN_EMAIL" == *@* ]] || die "--admin-email is required"
[ -z "$LM_URL" ] || [[ "$LM_URL" =~ ^https?:// ]] || die "--lm-url must start with https://"
[ -z "$LM_CA" ] || [ -f "$LM_CA" ] || die "--lm-ca file not found"
if [ -n "$TLS_CERT$TLS_KEY" ]; then
  [ -f "$TLS_CERT" ] && [ -f "$TLS_KEY" ] || die "--tls-cert and --tls-key must both point to files"
fi
DOMAIN="${DOMAIN:-$(hostname -f 2>/dev/null || hostname)}"

. /etc/os-release
if [ "${ID:-}" != "ubuntu" ] || [ "${VERSION_ID:-}" != "24.04" ]; then
  [ "$FORCE" -eq 1 ] || die "this installer supports Ubuntu 24.04 (found ${PRETTY_NAME:-unknown}); use --force to continue anyway"
  echo "warning: unsupported OS ${PRETTY_NAME:-unknown}, continuing because of --force"
fi

PKG="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ -f "$PKG/go.mod" ] && [ -d "$PKG/isp-netcontrol" ] && [ -d "$PKG/shared" ] || die "run this script from the unpacked package"

# The vendor must have built their License Manager key into this package.
if ! grep -q "BEGIN MYDNS LICENSE SIGNING KEY" "$PKG/isp-netcontrol/internal/license/trusted_keys.go"; then
  die "no License Manager signing key is built into this package.
       The vendor must run isp-netcontrol/scripts/set-trusted-keys.sh <license-server-url> before distributing it."
fi
[ -s /etc/machine-id ] || die "/etc/machine-id is missing; it is needed for the hardware ID (run: systemd-machine-id-setup)"

# ---- Docker ---------------------------------------------------------------
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
  say "Installing Docker and Compose from the Ubuntu archive"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -y -q docker.io docker-compose-v2 openssl ca-certificates curl
fi
command -v openssl >/dev/null || { apt-get update -q && apt-get install -y -q openssl; }
systemctl enable --now docker >/dev/null 2>&1 || true
docker info >/dev/null 2>&1 || die "Docker is installed but not running"
[ "$FIREWALL" = true ] && { modprobe nf_tables 2>/dev/null || true; }

# ---- Port 53 ----------------------------------------------------------------
DNS_PORT="${DNS_LISTEN##*:}"
if [ "$DNS_PORT" = 53 ] && command -v ss >/dev/null; then
  if ss -lunH 'sport = :53' 2>/dev/null | grep -q "127.0.0.53"; then
    if [ "$KEEP_STUB" -eq 1 ]; then
      echo "warning: systemd-resolved's stub listener uses port 53; set --dns-listen to specific addresses"
    else
      say "Disabling systemd-resolved's stub listener so ISP NetControl can serve DNS on port 53"
      install -d /etc/systemd/resolved.conf.d
      printf '[Resolve]\nDNSStubListener=no\n' >/etc/systemd/resolved.conf.d/isp-netcontrol.conf
      [ -L /etc/resolv.conf ] && readlink /etc/resolv.conf >"$STATE_DIR.resolv-link.bak" 2>/dev/null || true
      ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
      systemctl restart systemd-resolved
      sleep 1
      # Without the stub, this server resolves names through the upstream
      # servers systemd-resolved knows about. Make sure there are some.
      if ! grep -q '^nameserver' /run/systemd/resolve/resolv.conf 2>/dev/null || ! getent hosts registry-1.docker.io >/dev/null; then
        rm -f /etc/systemd/resolved.conf.d/isp-netcontrol.conf
        ln -sf "$(cat "$STATE_DIR.resolv-link.bak" 2>/dev/null || echo ../run/systemd/resolve/stub-resolv.conf)" /etc/resolv.conf
        systemctl restart systemd-resolved
        die "this server has no upstream DNS servers configured outside the systemd-resolved stub, so it could not
       resolve names after the stub was turned off (the change has been undone). Configure DNS servers, e.g. in
       /etc/systemd/resolved.conf.d/upstream.conf:  [Resolve]  DNS=1.1.1.1 8.8.8.8  then: systemctl restart systemd-resolved
       and run the installer again."
      fi
      # The Docker daemon still holds the old stub address (127.0.0.53): restart it.
      systemctl restart docker
      for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
    fi
  fi
  OTHER="$(ss -lunpH 'sport = :53' 2>/dev/null | grep -v isp-netcontrol || true)"
  if [ -n "$OTHER" ] && ! docker ps --format '{{.Names}}' | grep -q '^isp-netcontrol-api'; then
    die "something else already listens on UDP port 53:
$OTHER
       Stop it, or choose addresses with --dns-listen."
  fi
fi

# ---- Unbound (optional recursive resolver) --------------------------------
# ISP NetControl runs its own Unbound instance (own configuration, systemd
# unit and trust anchor) on 127.0.0.1:5335. It never merges with or changes
# a system Unbound configuration that may already exist on the server.
# Under /etc/unbound so Ubuntu's AppArmor profile for unbound lets it read the
# file; the system Unbound only loads unbound.conf and conf.d/*.conf, so this
# directory is never part of its configuration.
UNBOUND_DIR=/etc/unbound/isp-netcontrol
UNBOUND_CONF="$UNBOUND_DIR/unbound.conf"
UNBOUND_UNIT=isp-netcontrol-unbound.service
UNBOUND_KEY=/var/lib/unbound/isp-netcontrol-root.key
OLD_UNBOUND_CONF=/etc/unbound/unbound.conf.d/isp-netcontrol.conf
have_systemd() { [ -d /run/systemd/system ]; }
# True when the system Unbound has a configuration of its own (beyond
# Ubuntu's defaults), i.e. the administrator uses it for something.
system_unbound_customised() {
  grep -hvE '^[[:space:]]*(#|$)|include' /etc/unbound/unbound.conf 2>/dev/null | grep -q . && return 0
  ls /etc/unbound/unbound.conf.d/*.conf 2>/dev/null | grep -qv -e /remote-control.conf -e /root-auto-trust-anchor-file.conf
}

# v1.4.0 put its settings into the system Unbound's conf.d; take them out
# again, so the system configuration is exactly as it was before.
# v1.4.2 kept the configuration in /etc/isp-netcontrol, which AppArmor does
# not let unbound read; move the marker and drop the old file.
if [ -d /etc/isp-netcontrol ]; then
  [ -f /etc/isp-netcontrol/unbound-was-ours ] && { install -d "$UNBOUND_DIR"; mv /etc/isp-netcontrol/unbound-was-ours "$UNBOUND_DIR/"; }
  pkill -f "unbound -c /etc/isp-netcontrol/unbound.conf" 2>/dev/null || true
  rm -f /etc/isp-netcontrol/unbound.conf
  rmdir /etc/isp-netcontrol 2>/dev/null || true
fi
if [ -f "$OLD_UNBOUND_CONF" ]; then
  say "Removing the v1.4.0 Unbound settings from /etc/unbound/unbound.conf.d"
  rm -f "$OLD_UNBOUND_CONF"
  if ! system_unbound_customised; then
    # The system Unbound only existed for ISP NetControl: stop it (port 53 stays free).
    if have_systemd; then systemctl disable --now unbound >/dev/null 2>&1 || true; else pkill -f "unbound -c /etc/unbound/unbound.conf" 2>/dev/null || true; fi
  elif have_systemd; then
    systemctl try-restart unbound >/dev/null 2>&1 || true
  fi
fi

if [ "$WITH_UNBOUND" -eq 1 ]; then
  say "Setting up Unbound for ISP NetControl on 127.0.0.1:5335"
  if ! command -v unbound >/dev/null; then
    # Installed only for ISP NetControl: keep the package's own service (which
    # would listen on port 53) from starting, now and at boot.
    install -d "$UNBOUND_DIR"
    touch "$UNBOUND_DIR/unbound-was-ours"
    have_systemd && systemctl mask unbound.service >/dev/null 2>&1 || true
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q unbound
    have_systemd && systemctl mask --now unbound.service unbound-resolvconf.service >/dev/null 2>&1 || true
  fi
  CPUS="$(nproc)"; THREADS=$(( CPUS > 8 ? 8 : CPUS ))
  SLABS=1; while [ "$SLABS" -lt "$THREADS" ]; do SLABS=$(( SLABS * 2 )); done
  MEM_MB="$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)"
  MSG_MB=$(( MEM_MB / 16 )); [ "$MSG_MB" -lt 64 ] && MSG_MB=64; [ "$MSG_MB" -gt 1024 ] && MSG_MB=1024
  RRSET_MB=$(( MSG_MB * 2 ))
  install -d "$UNBOUND_DIR"
  install -d -o unbound -g unbound /var/lib/unbound
  # DNSSEC trust anchor, kept up to date by Unbound itself (RFC 5011).
  if [ ! -s "$UNBOUND_KEY" ]; then
    if [ -s /usr/share/dns/root.key ]; then
      install -o unbound -g unbound -m 0644 /usr/share/dns/root.key "$UNBOUND_KEY"
    else
      unbound-anchor -a "$UNBOUND_KEY" || true
      chown unbound:unbound "$UNBOUND_KEY" 2>/dev/null || true
    fi
  fi
  cat >"$UNBOUND_CONF" <<UBCONF
# Written by the ISP NetControl installer: ISP NetControl's own recursive
# resolver (service $UNBOUND_UNIT). Separate from any system Unbound.
# Sized for $CPUS CPU(s) and $MEM_MB MB RAM. Re-run the installer to regenerate.
server:
    interface: 127.0.0.1@5335
    access-control: 127.0.0.0/8 allow
    username: "unbound"
    directory: "/var/lib/unbound"
    chroot: ""
    pidfile: ""
    use-syslog: yes
    auto-trust-anchor-file: "$UNBOUND_KEY"
    num-threads: $THREADS
    msg-cache-slabs: $SLABS
    rrset-cache-slabs: $SLABS
    infra-cache-slabs: $SLABS
    key-cache-slabs: $SLABS
    msg-cache-size: ${MSG_MB}m
    rrset-cache-size: ${RRSET_MB}m
    so-reuseport: yes
    outgoing-range: 8192
    num-queries-per-thread: 4096
    prefetch: yes
    prefetch-key: yes
    serve-expired: yes
    serve-expired-ttl: 86400
    qname-minimisation: yes
    aggressive-nsec: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    edns-buffer-size: 1232
    hide-identity: yes
    hide-version: yes
    verbosity: 0
remote-control:
    control-enable: no
UBCONF
  unbound-checkconf "$UNBOUND_CONF" >/dev/null || die "Unbound configuration check failed: run unbound-checkconf $UNBOUND_CONF"
  if have_systemd; then
    cat >/etc/systemd/system/$UNBOUND_UNIT <<UNIT
[Unit]
Description=Unbound recursive resolver for ISP NetControl (127.0.0.1:5335)
After=network-online.target
Wants=network-online.target

[Service]
ExecStartPre=/usr/sbin/unbound-checkconf $UNBOUND_CONF
ExecStart=/usr/sbin/unbound -d -p -c $UNBOUND_CONF
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable "$UNBOUND_UNIT" >/dev/null 2>&1
    systemctl restart "$UNBOUND_UNIT"
  else
    pkill -f "unbound -c $UNBOUND_CONF" 2>/dev/null || true
    sleep 1
    unbound -c "$UNBOUND_CONF"
    echo "warning: no systemd: Unbound will not start automatically at boot"
  fi
  for _ in $(seq 1 20); do ss -lunH 'sport = :5335' 2>/dev/null | grep -q 127.0.0.1 && break; sleep 1; done
  ss -lunH 'sport = :5335' 2>/dev/null | grep -q 127.0.0.1 || die "Unbound did not start on 127.0.0.1:5335 (see: journalctl -u $UNBOUND_UNIT)"
  say "Unbound is running ($THREADS threads, ${MSG_MB}m + ${RRSET_MB}m cache, DNSSEC validation)"
fi

# ---- Files ----------------------------------------------------------------
say "Installing to $DIR"
install -d -m 0750 "$DIR" "$DIR/src" "$DIR/backups"
install -d -m 0700 "$DIR/tls" "$STATE_DIR"
if [ "$PKG" != "$DIR/src" ]; then
  tar -C "$PKG" --exclude=node_modules --exclude=.next --exclude=.git -cf - go.mod go.sum shared isp-netcontrol | tar -C "$DIR/src" -xf -
fi
DEPLOY="$DIR/src/isp-netcontrol/deploy"

if [ -f "$DIR/.env" ]; then
  say "Keeping existing configuration $DIR/.env"
  ADMIN_PW=""
else
  ADMIN_PW="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)"
  umask 077
  cat >"$DIR/.env" <<EOF
# Generated by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ). Keep a backup of this file.
POSTGRES_PASSWORD=$(openssl rand -hex 24)
PG_PORT=5433
NC_MASTER_KEY=$(openssl rand -base64 32)
NC_BOOTSTRAP_ADMIN_EMAIL=$ADMIN_EMAIL
NC_BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_PW
NC_REQUIRE_TOTP=true
NC_SYNC_INTERVAL=6h
NC_QUERY_LOG_DAYS=7
EOF
  umask 022
fi
# Options that may change on every run.
sed -i '/^NC_DNS_LISTEN=/d; /^NC_DEFAULT_UPSTREAMS=/d; /^NC_FIREWALL_ENABLED=/d; /^NC_LM_URL=/d; /^NC_LM_CA_FILE=/d; /^HTTP_PORT=/d; /^HTTPS_PORT=/d; /^TLS_DIR=/d; /^NC_STATE_HOST_DIR=/d' "$DIR/.env"
{
  echo "NC_DNS_LISTEN=$DNS_LISTEN"
  if [ -f "$UNBOUND_CONF" ]; then echo "NC_DEFAULT_UPSTREAMS=127.0.0.1:5335"; fi
  echo "NC_FIREWALL_ENABLED=$FIREWALL"
  echo "NC_LM_URL=$LM_URL"
  [ -n "$LM_CA" ] && echo "NC_LM_CA_FILE=/etc/isp-netcontrol/lm-ca.pem" || echo "NC_LM_CA_FILE="
  echo "HTTP_PORT=$HTTP_PORT"
  echo "HTTPS_PORT=$HTTPS_PORT"
  echo "TLS_DIR=$DIR/tls"
  echo "NC_STATE_HOST_DIR=$STATE_DIR"
} >>"$DIR/.env"
chmod 600 "$DIR/.env"
ln -sf "$DIR/.env" "$DEPLOY/.env"

# Host-specific mounts: the DMI product UUID (part of the hardware ID) and the
# License Manager CA certificate.
{
  echo "# Generated by install.sh: host-specific mounts."
  echo "services:"
  echo "  api:"
  echo "    volumes:"
  if [ -r /sys/class/dmi/id/product_uuid ]; then
    echo "      - /sys/class/dmi/id/product_uuid:/host/product_uuid:ro"
  else
    echo "      - /dev/null:/host/product_uuid:ro"
  fi
  if [ -n "$LM_CA" ]; then
    [ "$LM_CA" -ef "$DIR/lm-ca.pem" ] || install -m 0644 "$LM_CA" "$DIR/lm-ca.pem"
    echo "      - $DIR/lm-ca.pem:/etc/isp-netcontrol/lm-ca.pem:ro"
  fi
} >"$DEPLOY/docker-compose.override.yml"

# ---- TLS --------------------------------------------------------------------
if [ -n "$TLS_CERT" ]; then
  # Re-running with the installed files themselves is fine.
  [ "$TLS_CERT" -ef "$DIR/tls/fullchain.pem" ] || install -m 0644 "$TLS_CERT" "$DIR/tls/fullchain.pem"
  [ "$TLS_KEY" -ef "$DIR/tls/privkey.pem" ] || install -m 0600 "$TLS_KEY" "$DIR/tls/privkey.pem"
elif [ ! -s "$DIR/tls/fullchain.pem" ]; then
  say "Creating a self-signed console certificate for $DOMAIN"
  SAN="DNS:$DOMAIN,DNS:localhost,IP:127.0.0.1"
  for ip in $(hostname -I 2>/dev/null); do SAN="$SAN,IP:$ip"; done
  openssl req -x509 -newkey rsa:3072 -nodes -days 825 -subj "/CN=$DOMAIN" -addext "subjectAltName=$SAN" \
    -keyout "$DIR/tls/privkey.pem" -out "$DIR/tls/fullchain.pem" 2>/dev/null
  chmod 600 "$DIR/tls/privkey.pem"
fi

# ---- Build and start --------------------------------------------------------
cd "$DEPLOY"
# Docker must be able to download base images. A daemon started before the
# resolver changed keeps using the old address; one restart fixes that.
if ! docker pull -q alpine:3.22 >/dev/null 2>&1; then
  if [ -d /run/systemd/system ]; then
    say "Docker cannot reach the image registry; restarting Docker and retrying"
    systemctl restart docker
    for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
  fi
  docker pull -q alpine:3.22 >/dev/null || die "Docker cannot download images from registry-1.docker.io.
       Check this server's DNS (getent hosts registry-1.docker.io) and internet access, then run the installer again."
fi
say "Building images (this takes a few minutes the first time)"
docker compose build
say "Starting services"
docker compose up -d
# Nginx renders its configuration from the templates when it starts: restart
# it so an upgrade's template changes apply (DNS is not affected).
docker compose restart nginx >/dev/null
say "Waiting for ISP NetControl to become healthy"
for _ in $(seq 1 60); do
  if curl -fsk "https://127.0.0.1:$HTTPS_PORT/healthz" >/dev/null 2>&1; then OK=1; break; fi
  sleep 3
done
[ "${OK:-0}" = 1 ] || { docker compose ps; docker compose logs --tail 40 api; die "ISP NetControl did not start"; }

if [ "$FIREWALL" = true ] && ! docker compose exec -T api nft list tables >/dev/null 2>&1; then
  echo "warning: nftables is not usable on this kernel; firewall management will report errors (use --no-firewall to turn it off)"
fi

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "$HTTPS_PORT/tcp" >/dev/null; ufw allow "$HTTP_PORT/tcp" >/dev/null
  ufw allow "$DNS_PORT/udp" >/dev/null; ufw allow "$DNS_PORT/tcp" >/dev/null
  say "Opened console and DNS ports in ufw"
fi

cat >/etc/cron.d/isp-netcontrol-backup <<EOF
43 2 * * * root $DIR/src/isp-netcontrol/scripts/backup.sh --dir $DIR >/dev/null 2>&1
EOF

HWID="$(docker compose exec -T api isp-netcontrol hardware-id 2>/dev/null || true)"
URL="https://$DOMAIN"; [ "$HTTPS_PORT" = 443 ] || URL="$URL:$HTTPS_PORT"
echo
echo "ISP NetControl is running. Console: $URL"
echo "  DNS is served on $DNS_LISTEN. A 30-day trial with all features has started."
[ -n "$HWID" ] && echo "  Hardware ID (for offline activation): $HWID"
if [ -n "$ADMIN_PW" ]; then
  echo
  echo "  First sign-in:    $ADMIN_EMAIL"
  echo "  Initial password: $ADMIN_PW"
  echo "  (You must set up two-factor authentication and change the password at first sign-in.)"
fi
echo
if [ "$WITH_UNBOUND" -eq 1 ]; then
  echo "Unbound: new installations use it automatically. If upstream resolvers were already saved"
  echo "  in the console, set DNS settings > Upstream resolvers to 127.0.0.1:5335 to switch to it."
fi
echo "Next: sign in, open License, and activate your license key."
echo "Before pointing subscribers at this server, review DNS settings > Allowed client networks."
