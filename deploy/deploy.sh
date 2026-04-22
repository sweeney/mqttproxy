#!/usr/bin/env bash
#
# Build and deploy mqttproxy to a remote host.
#
# Usage:
#   ./deploy/deploy.sh sweeney@garibaldi
#
# Keeps the last 3 versioned binaries in /opt/mqttproxy/bin/ and symlinks
# the active one. Requires passwordless sudo for systemctl on the remote.
#
# First-time setup: run deploy/setup.sh on the target host with sudo.
#
set -euo pipefail

REMOTE="${1:?Usage: $0 user@host}"
BINARY="mqttproxy"
BUILD_DIR="bin"
DEPLOY_DIR="/opt/mqttproxy/bin"
HEALTH_URL="https://mqtt.swee.net/health"
KEEP_VERSIONS=3

VERSION=$(date +%Y%m%d-%H%M%S)
COMMIT=$(git rev-parse --short HEAD)
REMOTE_BIN="${BINARY}-${VERSION}"

echo "=== Building $BINARY (linux/amd64) ==="
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.version=${COMMIT}" -o "$BUILD_DIR/$BINARY" ./cmd/mqttproxy/
echo "  Built: $BUILD_DIR/$BINARY"

echo "=== Uploading to $REMOTE ==="
scp "$BUILD_DIR/$BINARY" "$REMOTE:$DEPLOY_DIR/$REMOTE_BIN"
ssh "$REMOTE" "chmod 755 $DEPLOY_DIR/$REMOTE_BIN"

echo "=== Activating $REMOTE_BIN ==="
ssh "$REMOTE" "ln -sfn $REMOTE_BIN $DEPLOY_DIR/$BINARY"
ssh "$REMOTE" "sudo systemctl restart mqttproxy"

echo "=== Verifying ==="
sleep 2
if ssh "$REMOTE" "sudo systemctl is-active --quiet mqttproxy"; then
    echo "  ✓ mqttproxy is running"
else
    echo "  ✗ mqttproxy failed to start"
    ssh "$REMOTE" "sudo journalctl -u mqttproxy -n 20 --no-pager"
    exit 1
fi
ADVERTISED=$(curl -sf "$HEALTH_URL" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
if [ "$ADVERTISED" = "$COMMIT" ]; then
    echo "  ✓ version $COMMIT confirmed at $HEALTH_URL"
else
    echo "  ✗ version mismatch: deployed $COMMIT but $HEALTH_URL reports '${ADVERTISED:-<no response>}'"
    exit 1
fi

echo "=== Cleaning old versions (keeping $KEEP_VERSIONS) ==="
ssh "$REMOTE" "\
  cd $DEPLOY_DIR && \
  ls -t ${BINARY}-* \
    | tail -n +$((KEEP_VERSIONS + 1)) \
    | xargs -r rm --"

echo ""
echo "=== Deployed $VERSION ==="
ssh "$REMOTE" "sudo journalctl -u mqttproxy -n 5 --no-pager"
