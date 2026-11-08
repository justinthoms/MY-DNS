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
#   --keep-resolved-stub  Do not disable systemd-resolved's stub listener on port 53
#   --dir DIR             Install directory (default /opt/isp-netcontrol)
#   --http-port N / --https-port N   Console ports (default 80 / 443)
#   --force               Continue on an OS other than Ubuntu 24.04
#
# Re-running the script upgrades the installation and keeps .env, the
# database, the license state and the certificates.
set -euo pipefail

ADMIN_EMAIL="" DOMAIN="" LM_URL="" LM_CA="" DNS_LISTEN=":53" TLS_CERT="" TLS_KEY=""
FIREWALL=true KEEP_STUB=0 FORCE=0 DIR=/opt/isp-netcontrol HTTP_PORT=80 HTTPS_PORT=443
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
    --keep-resolved-stub) KEEP_STUB=1; shift ;;
    --dir) DIR="${2:?}"; shift 2 ;;
    --http-port) HTTP_PORT="${2:?}"; shift 2 ;;
    --https-port) HTTPS_PORT="${2:?}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
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
    fi
  fi
  OTHER="$(ss -lunpH 'sport = :53' 2>/dev/null | grep -v isp-netcontrol || true)"
  if [ -n "$OTHER" ] && ! docker ps --format '{{.Names}}' | grep -q '^isp-netcontrol-api'; then
    die "something else already listens on UDP port 53:
$OTHER
       Stop it, or choose addresses with --dns-listen."
  fi
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
sed -i '/^NC_DNS_LISTEN=/d; /^NC_FIREWALL_ENABLED=/d; /^NC_LM_URL=/d; /^NC_LM_CA_FILE=/d; /^HTTP_PORT=/d; /^HTTPS_PORT=/d; /^TLS_DIR=/d; /^NC_STATE_HOST_DIR=/d' "$DIR/.env"
{
  echo "NC_DNS_LISTEN=$DNS_LISTEN"
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
    install -m 0644 "$LM_CA" "$DIR/lm-ca.pem"
    echo "      - $DIR/lm-ca.pem:/etc/isp-netcontrol/lm-ca.pem:ro"
  fi
} >"$DEPLOY/docker-compose.override.yml"

# ---- TLS --------------------------------------------------------------------
if [ -n "$TLS_CERT" ]; then
  install -m 0644 "$TLS_CERT" "$DIR/tls/fullchain.pem"
  install -m 0600 "$TLS_KEY" "$DIR/tls/privkey.pem"
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
say "Building images (this takes a few minutes the first time)"
docker compose build
say "Starting services"
docker compose up -d
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
echo "Next: sign in, open License, and activate your license key."
echo "Before pointing subscribers at this server, review DNS settings > Allowed client networks."
