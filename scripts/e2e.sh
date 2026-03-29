#!/usr/bin/env bash
# Run end-to-end tests against live infrastructure.
#
# Builds and starts the proxy, waits for it to be ready, runs the e2e suite,
# then cleans up regardless of test outcome.
#
# Required env vars:
#   E2E_ADMIN_USER   username with admin role
#   E2E_ADMIN_PASS   password for admin user
#   E2E_USER_USER    username with user role
#   E2E_USER_PASS    password for user
#
# Optional env vars (with defaults):
#   E2E_BROKER_ADDR  mosquitto WebSocket addr  (default: garibaldi:9001)
#   E2E_PROXY_ADDR   proxy WebSocket URL        (default: ws://localhost:8883/mqtt)
#   E2E_PROXY_PORT   proxy listen port          (default: 8883)
#   E2E_AUTH_URL     auth server base URL       (default: https://id.swee.net)
#   E2E_CONFIG       path to proxy config file  (default: generated from env)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# --- Defaults ---
BROKER_ADDR="${E2E_BROKER_ADDR:-garibaldi:1883}"
PROXY_PORT="${E2E_PROXY_PORT:-8883}"
export E2E_PROXY_ADDR="${E2E_PROXY_ADDR:-ws://localhost:${PROXY_PORT}/mqtt}"
export E2E_AUTH_URL="${E2E_AUTH_URL:-https://id.swee.net}"

# --- Check required vars ---
missing=()
for var in E2E_ADMIN_USER E2E_ADMIN_PASS E2E_USER_USER E2E_USER_PASS; do
    [[ -z "${!var:-}" ]] && missing+=("$var")
done
if [[ ${#missing[@]} -gt 0 ]]; then
    echo "error: missing required environment variables: ${missing[*]}" >&2
    echo ""
    echo "Usage:"
    echo "  E2E_ADMIN_USER=alice E2E_ADMIN_PASS=... \\"
    echo "  E2E_USER_USER=bob   E2E_USER_PASS=... \\"
    echo "  $0"
    exit 1
fi

# --- Cleanup on exit ---
PROXY_PID=""
CONFIG_FILE=""

cleanup() {
    if [[ -n "$PROXY_PID" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
        echo "--- stopping proxy (pid $PROXY_PID)"
        kill "$PROXY_PID"
        wait "$PROXY_PID" 2>/dev/null || true
    fi
    if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
        rm -f "$CONFIG_FILE"
    fi
}
trap cleanup EXIT

# --- Build ---
echo "--- building proxy"
cd "$ROOT"
go build -o /tmp/mqttproxy ./cmd/mqttproxy

# --- Generate config ---
CONFIG_FILE="$(mktemp /tmp/mqttproxy-e2e-XXXXXX.yaml)"
cat > "$CONFIG_FILE" <<EOF
listen:
  addr: "127.0.0.1:${PROXY_PORT}"
  path: "/mqtt"

broker:
  addr: "${BROKER_ADDR}"
  dial_timeout: "5s"

auth:
  well_known_url: "${E2E_AUTH_URL}/.well-known/oauth-authorization-server"
  issuer: "${E2E_AUTH_URL}"
  # audience omitted: e2e tokens come from /auth/login which does not set aud.
  # Production tokens from the OAuth flow will include aud: mqttproxy.
  jwks_cache_ttl: "1h"

acl:
  roles:
    admin:
      publish:   ["#"]
      subscribe: ["#"]
    user:
      publish:   []
      subscribe: ["#"]

logging:
  level: "debug"
EOF

# --- Start proxy ---
echo "--- starting proxy on :${PROXY_PORT} (broker: ${BROKER_ADDR})"
/tmp/mqttproxy -config "$CONFIG_FILE" &
PROXY_PID=$!

# --- Wait for proxy to be ready ---
echo "--- waiting for proxy to accept connections"
for i in $(seq 1 20); do
    if nc -z 127.0.0.1 "$PROXY_PORT" 2>/dev/null; then
        echo "--- proxy ready (${i} attempt(s))"
        break
    fi
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        echo "error: proxy exited unexpectedly" >&2
        exit 1
    fi
    sleep 0.3
    if [[ $i -eq 20 ]]; then
        echo "error: proxy did not become ready in time" >&2
        exit 1
    fi
done

# --- Run E2E tests ---
echo "--- running e2e tests"
go test ./test/e2e/... -tags e2e -v -timeout 60s
