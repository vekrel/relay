#!/usr/bin/env bash
# Smoke a running relay: scripts/smoke.sh https://relay-staging.<domain>  (or http://127.0.0.1:8080)
set -euo pipefail
URL=${1:?usage: smoke.sh RELAY_URL}
URL=${URL%/}

body=$(curl -fsS "$URL/health")
echo "health: $body"
[ "$body" = '{"ok":true,"service":"relay"}' ] || { echo "FAIL: unexpected /health body" >&2; exit 1; }
echo "PASS"
