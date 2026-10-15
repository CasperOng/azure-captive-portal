#!/usr/bin/env bash
# Finish admin-panel install in CT 150 (idempotent).
set -euo pipefail
CTID=150

echo "[*] Validating nftables.conf syntax..."
pct exec "$CTID" -- nft -c -f /etc/nftables.conf && echo "    config OK"

echo "[*] Setting admin credentials + allow-list..."
ADMIN_PASS=$(openssl rand -base64 15 | tr -d '/+=' | cut -c1-18)
pct exec "$CTID" -- bash -c "
  sed -i '/^ADMIN_PASSWORD=/d; /^ADMIN_ALLOW_NET=/d; /^DEFAULT_BANDWIDTH_KBPS=/d' /opt/captive-portal/.env
  {
    echo 'ADMIN_PASSWORD=${ADMIN_PASS}'
    echo 'ADMIN_ALLOW_NET=192.168.1.0/24'
    echo 'DEFAULT_BANDWIDTH_KBPS=0'
  } >> /opt/captive-portal/.env
  chmod 600 /opt/captive-portal/.env
"

echo "[*] Applying nftables ruleset..."
pct exec "$CTID" -- systemctl restart nftables

echo "[*] Initialising device database..."
pct exec "$CTID" -- bash -c 'cd /opt/captive-portal && ./venv/bin/python -c "
import common; common.db_init(); print(\"    db ready:\", common.DB_PATH)
"'

echo "[*] Enabling services..."
pct exec "$CTID" -- bash -c "
  systemctl daemon-reload
  systemctl enable captive-admin.service captive-bw-sync.service >/dev/null 2>&1
  systemctl restart captive-bw-sync.service
  systemctl restart captive-admin.service
  systemctl restart captive-portal.service
"
sleep 3

echo
echo "==================== STATUS ===================="
pct exec "$CTID" -- systemctl is-active nftables dnsmasq captive-portal.service captive-admin.service captive-bw-sync.service
echo "--- enabled ---"
pct exec "$CTID" -- systemctl is-enabled captive-portal.service captive-admin.service captive-bw-sync.service
echo
echo "PASSWORD=${ADMIN_PASS}"
