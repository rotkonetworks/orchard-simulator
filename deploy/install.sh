#!/usr/bin/env bash
# Edge install: pull the latest static-site tarball from the
# rotkonetworks/orchard-simulator `latest-site` GH release and unpack
# it into /var/www/orchard-rotko-net/. Run on each Rotko edge box
# (bkk06/07/08) under a systemd timer or cron.
#
# Idempotent: if the local checksum already matches the release, do
# nothing. Safe to run every minute.
#
# Env vars (override at the systemd-unit level if needed):
#   ORCHARD_DEST     - target document root (default /var/www/orchard-rotko-net)
#   ORCHARD_TMP      - workdir            (default /tmp/orchard-deploy)
#   ORCHARD_REPO     - repo slug          (default rotkonetworks/orchard-simulator)
#   ORCHARD_TAG      - release tag        (default latest-site)

set -euo pipefail

DEST="${ORCHARD_DEST:-/var/www/orchard-rotko-net}"
TMP="${ORCHARD_TMP:-/tmp/orchard-deploy}"
REPO="${ORCHARD_REPO:-rotkonetworks/orchard-simulator}"
TAG="${ORCHARD_TAG:-latest-site}"

ASSET=orchard-simulator-site.tar.gz
HASH_ASSET="${ASSET}.sha256"

mkdir -p "$TMP" "$DEST"

current=""
if [[ -f "$DEST/.deploy-sha256" ]]; then
  current=$(cat "$DEST/.deploy-sha256")
fi

# Fetch latest checksum.
cd "$TMP"
curl -sSL -o "$HASH_ASSET" "https://github.com/$REPO/releases/download/$TAG/$HASH_ASSET"
latest=$(awk '{print $1}' "$HASH_ASSET")

if [[ "$current" == "$latest" ]]; then
  echo "orchard.rotko.net: already at $latest, no update needed."
  exit 0
fi

echo "orchard.rotko.net: pulling new build $latest..."
curl -sSL -o "$ASSET" "https://github.com/$REPO/releases/download/$TAG/$ASSET"

# Verify.
echo "$latest  $ASSET" | sha256sum -c -

# Stage into a fresh directory, then atomically swap.
STAGE="$TMP/stage-$$"
rm -rf "$STAGE"
mkdir -p "$STAGE"
tar -xzf "$ASSET" -C "$STAGE"

# Atomic swap via mv. Keep the previous release for rollback.
PREV="$DEST.prev"
[[ -d "$PREV" ]] && rm -rf "$PREV"
[[ -d "$DEST" ]] && mv "$DEST" "$PREV"
mv "$STAGE" "$DEST"
echo "$latest" > "$DEST/.deploy-sha256"

# Clean up.
rm -f "$TMP/$ASSET" "$TMP/$HASH_ASSET"

echo "orchard.rotko.net: deployed $latest"
