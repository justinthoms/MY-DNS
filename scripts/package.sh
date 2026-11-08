#!/usr/bin/env bash
# Builds the release package from the committed sources:
#   dist/isp-netcontrol-<version>.zip
# Only files tracked by git are included, so local secrets, certificates and
# build output never end up in the package.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="$(sed -n 's/^const Version = "\(.*\)"/\1/p' isp-netcontrol/internal/nc/app.go)"
[ -n "$VERSION" ] || { echo "cannot read version" >&2; exit 1; }
if ! git diff --quiet HEAD -- . ; then
  echo "warning: uncommitted changes are NOT included (packages are built from HEAD)" >&2
fi
if grep -q "BEGIN MYDNS LICENSE SIGNING KEY" isp-netcontrol/internal/license/trusted_keys.go; then
  echo "error: trusted_keys.go contains a key; packages must ship with the empty placeholder" >&2
  exit 1
fi
mkdir -p dist
COMMON=(go.mod go.sum README.md shared docs)
build() {
  local name="$1"; shift
  local out="dist/$name-$VERSION.zip" tmp
  tmp="$(mktemp -d)"
  git archive --format=tar HEAD -- "${COMMON[@]}" "$@" | tar -C "$tmp" -xf -
  rm -f "$out"
  (cd "$tmp" && zip -qr -X "$OLDPWD/$out" .)
  rm -rf -- "$tmp"
  echo "$out ($(du -h "$out" | cut -f1))"
}
build isp-netcontrol isp-netcontrol
(cd dist && sha256sum ./*-"$VERSION".zip > SHA256SUMS)
echo "dist/SHA256SUMS"
