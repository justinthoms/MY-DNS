#!/usr/bin/env bash
# Writes a compressed PostgreSQL dump of the ISP NetControl to DIR/backups and
# keeps the newest 14. Also back up DIR/.env (it holds NC_MASTER_KEY) separately.
#   sudo isp-netcontrol/scripts/backup.sh [--dir /opt/isp-netcontrol]
set -euo pipefail
DIR=/opt/isp-netcontrol
[ "${1:-}" = "--dir" ] && DIR="${2:?}"
cd "$DIR/src/isp-netcontrol/deploy"
OUT="$DIR/backups/isp-netcontrol-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"
umask 077
docker compose exec -T postgres pg_dump -U isp_netcontrol -d isp_netcontrol --clean --if-exists | gzip >"$OUT"
ls -1t "$DIR"/backups/isp-netcontrol-*.sql.gz | tail -n +15 | xargs -r rm -f --
echo "$OUT"
