#!/usr/bin/env bash
# Stops ISP NetControl and removes its nftables table. Nothing else in the
# host firewall is touched.
#   sudo isp-netcontrol/scripts/uninstall.sh [--dir DIR] [--purge]
# --purge also deletes the database, the license state (/var/lib/isp-netcontrol)
# and DIR. Without it, everything is kept and a re-install continues where it
# left off (same trial, same license).
set -euo pipefail
DIR=/opt/isp-netcontrol PURGE=0 STATE_DIR=/var/lib/isp-netcontrol
while [ $# -gt 0 ]; do
  case "$1" in --dir) DIR="${2:?}"; shift 2 ;; --purge) PURGE=1; shift ;; *) echo "unknown option $1" >&2; exit 2 ;; esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
if [ -d "$DIR/src/isp-netcontrol/deploy" ]; then
  cd "$DIR/src/isp-netcontrol/deploy"
  # Remove our nft table with the same nft the product uses (host may lack nft).
  docker compose run --rm --no-deps --entrypoint sh api -c \
    'nft list table inet isp_netcontrol >/dev/null 2>&1 && nft delete table inet isp_netcontrol || true' || true
  if [ "$PURGE" -eq 1 ]; then docker compose down -v; else docker compose down; fi
fi
if [ -f /etc/systemd/resolved.conf.d/isp-netcontrol.conf ]; then
  rm -f /etc/systemd/resolved.conf.d/isp-netcontrol.conf
  if [ -f "$STATE_DIR.resolv-link.bak" ]; then ln -sf "$(cat "$STATE_DIR.resolv-link.bak")" /etc/resolv.conf; rm -f "$STATE_DIR.resolv-link.bak"
  else ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf; fi
  systemctl restart systemd-resolved 2>/dev/null || true
  echo "Restored systemd-resolved's stub listener."
fi
rm -f /etc/cron.d/isp-netcontrol-backup
# ISP NetControl's own Unbound instance (--with-unbound). A system Unbound
# configuration of the administrator is not touched.
if [ -f /etc/isp-netcontrol/unbound.conf ] || [ -f /etc/systemd/system/isp-netcontrol-unbound.service ]; then
  systemctl disable --now isp-netcontrol-unbound.service >/dev/null 2>&1 || pkill -f "unbound -c /etc/isp-netcontrol/unbound.conf" 2>/dev/null || true
  rm -f /etc/systemd/system/isp-netcontrol-unbound.service /etc/isp-netcontrol/unbound.conf /var/lib/unbound/isp-netcontrol-root.key
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [ -f /etc/isp-netcontrol/unbound-was-ours ]; then
    # The unbound package was installed only for ISP NetControl.
    systemctl unmask unbound.service unbound-resolvconf.service >/dev/null 2>&1 || true
    rm -f /etc/isp-netcontrol/unbound-was-ours
    echo "Unbound stopped. The package stays installed; remove it with: sudo apt purge unbound"
  fi
  rmdir /etc/isp-netcontrol 2>/dev/null || true
fi
# Settings left by v1.4.0 in the system Unbound.
rm -f /etc/unbound/unbound.conf.d/isp-netcontrol.conf
if [ "$PURGE" -eq 1 ]; then
  rm -rf -- "$STATE_DIR"
  case "$DIR" in /opt/*) rm -rf -- "$DIR" ;; *) echo "not deleting $DIR automatically (outside /opt); remove it yourself" ;; esac
  echo "ISP NetControl removed, including its data."
else
  echo "ISP NetControl stopped and its firewall table removed. Data kept."
fi
