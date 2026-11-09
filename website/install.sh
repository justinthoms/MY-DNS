#!/usr/bin/env bash
# ISP NetControl one-line installer and updater for Ubuntu 24.04.
#
#   curl -fsSL https://dns.netfixpro.in/install.sh | sudo bash
#
# Options are passed to the real installer, for example:
#   curl -fsSL https://dns.netfixpro.in/install.sh | sudo bash -s -- --domain dns.your-isp.example
#
# Environment: ADMIN_EMAIL (skip the question), NO_UNBOUND=1 (do not install
# the Unbound recursive resolver), LM_URL / LM_CA (another license server).
#
# What it does: installs git, downloads (or updates) the source from
# https://github.com/justinthoms/MY-DNS, builds in the license server's
# public signing key (public keys can only verify licenses), and runs
# isp-netcontrol/scripts/install.sh. Running it again upgrades in place and
# keeps your settings, database and license.
set -euo pipefail

REPO="${REPO:-https://github.com/justinthoms/MY-DNS.git}"
BRANCH="${BRANCH:-main}"
LM_URL="${LM_URL:-https://licenses.netfixpro.in:8443}"
SRC="${SRC:-/opt/isp-netcontrol-src}"

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run it with sudo: curl -fsSL https://dns.netfixpro.in/install.sh | sudo bash"
. /etc/os-release 2>/dev/null || true
if [ "${ID:-}" != "ubuntu" ] || [ "${VERSION_ID:-}" != "24.04" ]; then
  echo "warning: ISP NetControl supports Ubuntu 24.04 (this is ${PRETTY_NAME:-unknown}); the installer will refuse unless you add --force"
fi

say "Installing prerequisites"
export DEBIAN_FRONTEND=noninteractive
if ! command -v git >/dev/null || ! command -v curl >/dev/null; then
  apt-get update -q >/dev/null
  apt-get install -y -q git curl ca-certificates >/dev/null
fi

KEYS=isp-netcontrol/internal/license/trusted_keys.go
if [ -d "$SRC/.git" ]; then
  say "Updating $SRC"
  git -C "$SRC" checkout -q -- "$KEYS" 2>/dev/null || true # built-in key is re-added below
  git -C "$SRC" fetch -q --depth 1 origin "$BRANCH"
  git -C "$SRC" reset -q --hard FETCH_HEAD
else
  say "Downloading ISP NetControl to $SRC"
  git clone -q --depth 1 --branch "$BRANCH" "$REPO" "$SRC"
fi

say "Fetching the license server's public signing key from $LM_URL"
CA_ARGS=()
[ -n "${LM_CA:-}" ] && CA_ARGS=(--cacert "$LM_CA")
"$SRC/isp-netcontrol/scripts/set-trusted-keys.sh" "$LM_URL" "${CA_ARGS[@]}" >/dev/null \
  || die "could not get the signing key from $LM_URL (check that this server can reach it)"

EMAIL="${ADMIN_EMAIL:-}"
if [ -z "$EMAIL" ] && [ -f /opt/isp-netcontrol/.env ]; then
  EMAIL="$(sed -n 's/^NC_BOOTSTRAP_ADMIN_EMAIL=//p' /opt/isp-netcontrol/.env | head -1)"
fi
case " $* " in *" --admin-email "*) EMAIL="from-args" ;; esac
if [ -z "$EMAIL" ]; then
  [ -r /dev/tty ] || die "set ADMIN_EMAIL, e.g. curl -fsSL https://dns.netfixpro.in/install.sh | sudo ADMIN_EMAIL=noc@your-isp.example bash"
  while [[ "$EMAIL" != *@* ]]; do
    printf 'Administrator e-mail for the console: ' >/dev/tty
    read -r EMAIL </dev/tty
  done
fi

ARGS=(--lm-url "$LM_URL")
[ "$EMAIL" != "from-args" ] && ARGS+=(--admin-email "$EMAIL")
[ -n "${LM_CA:-}" ] && ARGS+=(--lm-ca "$LM_CA")
[ "${NO_UNBOUND:-0}" = 1 ] || ARGS+=(--with-unbound)

say "Running the ISP NetControl installer"
exec "$SRC/isp-netcontrol/scripts/install.sh" "${ARGS[@]}" "$@"
