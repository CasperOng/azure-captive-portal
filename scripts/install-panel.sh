#!/usr/bin/env bash
# Install the captive-portal admin panel (bandwidth control) into CT 150.
# Run on the Proxmox host:  bash /root/deploy/install-panel.sh
set -euo pipefail

CTID=150
SRC=/root/deploy
DEST=/opt/captive-portal

echo "[*] Pushing application files into CT ${CTID}..."
pct push "$CTID" "$SRC/common.py" "$DEST/common.py" --perms 644
pct push "$CTID" "$SRC/admin.py"  "$DEST/admin.py"  --perms 644
pct push "$CTID" "$SRC/nftables.conf" "/etc/nftables.conf" --perms 644
pct push "$CTID" "$SRC/captive-admin.service"   "/etc/systemd/system/captive-admin.service"   --perms 644
pct push "$CTID" "$SRC/captive-bw-sync.service" "/etc/systemd/system/captive-bw-sync.service" --perms 644

echo "[*] Installing python-multipart into the venv..."
pct exec "$CTID" -- /opt/captive-portal/venv/bin/pip install --quiet python-multipart

echo "[*] Configuring admin credentials..."
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

echo "[*] Reloading nftables, enabling services..."
pct exec "$CTID" -- bash -c "
  systemctl restart nftables
  systemctl daemon-reload
  systemctl enable --now captive-bw-sync.service >/dev/null 2>&1
  systemctl enable --now captive-admin.service    >/dev/null 2>&1
  systemctl restart captive-portal.service
  sleep 3
  systemctl is-active nftables dnsmasq captive-portal.service captive-admin.service
"

echo
echo "======================================================"
echo "  ADMIN PANEL PASSWORD: ${ADMIN_PASS}"
echo "======================================================"
