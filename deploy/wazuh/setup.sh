#!/usr/bin/env bash
# Fetch Wazuh's official single-node stack (vetted indexer/dashboard/cert config)
# and generate the indexer certificates. Run once before `docker compose up`.
set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-4.9.0}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SN_DIR="$HERE/wazuh-single-node"

echo "==> Fetching Wazuh $WAZUH_VERSION single-node deployment"
if [ ! -d "$SN_DIR" ]; then
  tmp="$(mktemp -d)"
  git clone --depth 1 --branch "v$WAZUH_VERSION" https://github.com/wazuh/wazuh-docker.git "$tmp"
  cp -R "$tmp/single-node" "$SN_DIR"
  rm -rf "$tmp"
else
  echo "    (already present at $SN_DIR)"
fi

echo "==> Generating indexer certificates"
( cd "$SN_DIR" && docker compose -f generate-indexer-certs.yml run --rm generator )

echo
echo "Done. Now bring the whole stack up with:"
echo
echo "  cd $HERE"
echo "  export CR_ADMIN_PASSWORD='choose-a-strong-password'"
echo "  docker compose \\"
echo "    -f wazuh-single-node/docker-compose.yml \\"
echo "    -f docker-compose.override.yml up -d --build"
echo
echo "Wazuh needs vm.max_map_count=262144 on the host:"
echo "  sudo sysctl -w vm.max_map_count=262144"
