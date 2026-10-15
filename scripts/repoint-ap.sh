#!/usr/bin/env bash
# Repoint the local AP to vmbr50 and attach CT150 eth1 to it.
set -euo pipefail

STAMP=$(date +%Y%m%d-%H%M%S)

echo "=== [0] Backup hostapd.conf ==="
cp -a /etc/hostapd/hostapd.conf "/etc/hostapd/hostapd.conf.bak.${STAMP}"
echo "    saved -> /etc/hostapd/hostapd.conf.bak.${STAMP}"

echo "=== [1] Update SSID + bridge ==="
sed -i 's/^ssid=.*/ssid=Casper-SSO/'    /etc/hostapd/hostapd.conf
sed -i 's/^bridge=.*/bridge=vmbr50/'    /etc/hostapd/hostapd.conf
grep -q '^ssid='   /etc/hostapd/hostapd.conf || echo 'ssid=Casper-SSO' >> /etc/hostapd/hostapd.conf
grep -q '^bridge=' /etc/hostapd/hostapd.conf || echo 'bridge=vmbr50'  >> /etc/hostapd/hostapd.conf
sed -n '1,20p' /etc/hostapd/hostapd.conf | sed 's/^/    /'

echo "=== [2] Restart hostapd ==="
systemctl restart hostapd
sleep 4
echo "    hostapd: $(systemctl is-active hostapd)"
echo "    AP ssid: $(iw dev wlp1s0 info 2>/dev/null | awk '/ssid/{print $2}')"
echo "    AP type: $(iw dev wlp1s0 info 2>/dev/null | awk '/type/{print $2}')"

echo "=== [3] Repoint CT150 eth1 -> vmbr50 ==="
pct set 150 -net1 name=eth1,bridge=vmbr50,ip=10.50.0.1/24
pct config 150 | grep -E "^net" | sed 's/^/    /'

echo "=== [4] Reboot CT150 ==="
pct reboot 150
for i in $(seq 1 40); do
  if pct exec 150 -- ip -br addr show eth1 2>/dev/null | grep -q '10.50.0.1/24'; then
    echo "    eth1 up after ~$((i*2))s"; break
  fi
  sleep 2
done

echo
echo "=== [5] Bridge membership (must show wlp1s0 + veth150i1) ==="
ip link show master vmbr50

echo
echo "=== [6] CT150 interfaces ==="
pct exec 150 -- ip -br addr

echo
echo "=== [7] CT150 services ==="
pct exec 150 -- systemctl is-active nftables dnsmasq captive-portal.service captive-admin.service captive-bw-sync.service

echo
echo "=== [8] Listening ports (dnsmasq 53/67, app 3000/3001) ==="
pct exec 150 -- ss -ulpn 2>/dev/null | grep -E ':(53|67)\b' | sed 's/^/    /' || echo "    (no UDP 53/67)"
pct exec 150 -- ss -tlpn 2>/dev/null | grep -E ':(53|3000|3001)\b' | sed 's/^/    /' || echo "    (no TCP listeners)"

echo
echo "=== [9] nft captive table: prerouting / forward / input ==="
pct exec 150 -- nft list chain inet captive prerouting
pct exec 150 -- nft list chain inet captive forward
pct exec 150 -- nft list chain inet captive input
