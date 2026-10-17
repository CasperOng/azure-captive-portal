#!/usr/bin/env bash
# Install the captive-portal admin panel (bandwidth + access control) into CT 150.
# Run on the Proxmox host:  bash /root/deploy/install-panel.sh
set -euo pipefail

CTID=150
SRC=/root/deploy
DEST=/opt/captive-portal

echo "[*] Pushing application files into CT ${CTID}..."
pct push "$CTID" "$SRC/common.py"       "$DEST/common.py"       --perms 644
pct push "$CTID" "$SRC/admin.py"        "$DEST/admin.py"        --perms 644
pct push "$CTID" "$SRC/requirements.txt" "$DEST/requirements.txt" --perms 644
pct push "$CTID" "$SRC/nftables.conf"   "/etc/nftables.conf"    --perms 644
pct push "$CTID" "$SRC/backup-db.sh"    "$DEST/backup-db.sh"    --perms 755
for u in captive-admin.service captive-bw-sync.service \
         captive-device-sync.service captive-device-sync.timer \
         captive-db-backup.service   captive-db-backup.timer; do
  pct push "$CTID" "$SRC/$u" "/etc/systemd/system/$u" --perms 644
done

echo "[*] Installing pinned python dependencies..."
pct exec "$CTID" -- "$DEST/venv/bin/pip" install --quiet -r "$DEST/requirements.txt"

echo "[*] Generating the admin TLS certificate (self-signed)..."
pct exec "$CTID" -- bash -c '
  mkdir -p /opt/captive-portal/tls
  if [ ! -f /opt/captive-portal/tls/admin.crt ]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout /opt/captive-portal/tls/admin.key \
      -out /opt/captive-portal/tls/admin.crt \
      -days 825 -subj "/CN=captive-admin" \
      -addext "subjectAltName=IP:192.168.1.10,IP:127.0.0.1,DNS:localhost" 2>/dev/null
  fi
  chmod 600 /opt/captive-portal/tls/admin.key
  chmod 644 /opt/captive-portal/tls/admin.crt
'

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
  systemctl enable --now captive-bw-sync.service    >/dev/null 2>&1
  systemctl enable --now captive-admin.service      >/dev/null 2>&1
  systemctl enable --now captive-device-sync.timer  >/dev/null 2>&1
  systemctl enable --now captive-db-backup.timer    >/dev/null 2>&1
  systemctl restart captive-portal.service
  sleep 3
  systemctl is-active nftables dnsmasq captive-portal.service captive-admin.service
"

echo
echo "======================================================"
echo "  ADMIN PANEL PASSWORD: ${ADMIN_PASS}"
echo "======================================================"
