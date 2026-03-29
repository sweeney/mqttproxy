#!/usr/bin/env bash
#
# One-time setup for mqttproxy on a fresh Linux host.
# Run as root or with sudo from the repo root.
#
# Usage:
#   sudo ./deploy/setup.sh
#
set -euo pipefail

echo "=== Creating mqttproxy user ==="
if ! id mqttproxy &>/dev/null; then
    useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/mqttproxy mqttproxy
    echo "  Created user: mqttproxy"
else
    echo "  User already exists"
fi

echo "=== Creating directories ==="
mkdir -p /opt/mqttproxy/bin
# Deploy user (caller of deploy.sh) needs write access; mqttproxy user only needs read+exec
chown "${SUDO_USER:-root}:${SUDO_USER:-root}" /opt/mqttproxy/bin

mkdir -p /etc/mqttproxy
chown root:mqttproxy /etc/mqttproxy
chmod 750 /etc/mqttproxy

echo "=== Installing config ==="
if [ ! -f /etc/mqttproxy/config.yaml ]; then
    cp config.example.yaml /etc/mqttproxy/config.yaml
    chown root:mqttproxy /etc/mqttproxy/config.yaml
    chmod 640 /etc/mqttproxy/config.yaml
    echo "  Installed /etc/mqttproxy/config.yaml from template"
    echo "  *** Edit this file with your settings before starting the service ***"
else
    echo "  /etc/mqttproxy/config.yaml already exists, skipping"
fi

echo "=== Installing systemd unit ==="
cp deploy/mqttproxy.service /etc/systemd/system/mqttproxy.service
systemctl daemon-reload
systemctl enable mqttproxy
echo "  Installed and enabled mqttproxy.service"

echo ""
echo "=== Next steps ==="
echo "  1. Edit config:    sudo nano /etc/mqttproxy/config.yaml"
echo "  2. Deploy:         ./deploy/deploy.sh user@this-host"
echo "  3. Check status:   sudo systemctl status mqttproxy"
echo "  4. View logs:      sudo journalctl -u mqttproxy -f"
