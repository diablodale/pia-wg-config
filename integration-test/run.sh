#!/bin/bash
# Run the full VPN + port-forwarding integration test.
#
# Usage:
#   PIAWGCONFIG_USER=pXXXXXXX PIAWGCONFIG_PW=secret ./run.sh
#   PIA_REGION=us_california PIAWGCONFIG_USER=pXXXXXXX PIAWGCONFIG_PW=secret ./run.sh
#
# Requires: docker with compose v2, NET_ADMIN capability (must run as root or
# with sufficient privilege to create WireGuard interfaces).
set -euo pipefail

cd "$(dirname "$0")"

[[ -n "${PIAWGCONFIG_USER:-}" ]] || { echo "error: PIAWGCONFIG_USER is not set" >&2; exit 1; }
[[ -n "${PIAWGCONFIG_PW:-}"   ]] || { echo "error: PIAWGCONFIG_PW is not set" >&2; exit 1; }

cleanup() {
    echo "--- cleaning up ---"
    docker compose down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

echo "--- building and starting integration test ---"
docker compose up \
    --build \
    --abort-on-container-exit \
    --exit-code-from prober
