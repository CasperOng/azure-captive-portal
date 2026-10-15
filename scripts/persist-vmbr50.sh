#!/usr/bin/env bash
# Persist vmbr50 across host reboots and remove the abandoned VLAN-50 leftovers.
set -euo pipefail
STAMP=$(date +%Y%m%d-%H%M%S)

echo "=== [1] Who references the leftover bridges? ==="
refs=$(grep -rln 'vmbr0v50\|vmbr0\.50' /etc/pve/lxc/ /etc/pve/qemu-server/ /etc/network/ 2>/dev/null || true)
if [ -n "$refs" ]; then
  echo "    REFERENCED BY:"; printf '      %s\n' $refs
else
  echo "    nothing references vmbr0v50 / vmbr0.50 -> safe to remove"
fi

echo "=== [2] Back up /etc/network/interfaces ==="
cp -a /etc/network/interfaces "/etc/network/interfaces.bak.${STAMP}"
echo "    saved -> /etc/network/interfaces.bak.${STAMP}"

echo "=== [3] Persist vmbr50 ==="
printf '%s\n' \
'# Isolated L2 for the local hostapd AP (SSID: Casper-SSO).' \
'# CT 150 (oauth-core) eth1 attaches here as the captive gateway 10.50.0.1/24.' \
'auto vmbr50' \
'iface vmbr50 inet manual' \
'	bridge-ports wlp1s0' \
'	bridge-stp off' \
'	bridge-fd 0' > /etc/network/interfaces.d/vmbr50
sed 's/^/    /' /etc/network/interfaces.d/vmbr50

echo "=== [4] Apply (vmbr0/enp3s0 untouched) ==="
ifreload -a
sleep 2
echo "    vmbr50: $(ip -br link show vmbr50 2>/dev/null | awk '{print $1,$2}' || echo MISSING)"

echo "=== [5] Remove abandoned VLAN-50 leftovers ==="
if [ -z "$refs" ]; then
  ip link set vmbr0v50 down 2>/dev/null || true
  ip link del vmbr0v50  2>/dev/null && echo "    removed bridge vmbr0v50" || echo "    vmbr0v50 already gone"
  ip link del vmbr0.50  2>/dev/null && echo "    removed vlan  vmbr0.50"  || echo "    vmbr0.50 already gone"
  if [ -f /etc/hostapd/hostapd-vlan50.conf ]; then
    mv /etc/hostapd/hostapd-vlan50.conf "/root/hostapd-vlan50.conf.removed.${STAMP}"
    echo "    parked unused hostapd-vlan50.conf -> /root/hostapd-vlan50.conf.removed.${STAMP}"
  fi
  if [ -f /root/setup-local-wifi-vlan50.sh ]; then
    mv /root/setup-local-wifi-vlan50.sh "/root/setup-local-wifi-vlan50.sh.removed.${STAMP}"
    echo "    parked stale setup-local-wifi-vlan50.sh (referenced vmbr0v50)"
  fi
else
  echo "    SKIPPED removal - leftovers are still referenced"
fi

echo "=== [6] Reconcile AP + container ==="
if ! systemctl is-active --quiet hostapd; then
  echo "    hostapd not active after ifreload -> restarting"
  systemctl restart hostapd
  sleep 4
fi
echo "    hostapd: $(systemctl is-active hostapd)"
echo "    AP ssid: $(iw dev wlp1s0 info 2>/dev/null | awk '/ssid/{print $2}')"

# Re-assert bridge membership (hostapd re-adds its port if ifreload dropped it)
ip link show wlp1s0 | grep -q 'master vmbr50' || ip link set wlp1s0 master vmbr50

echo
echo "=== [7] Bridge membership ==="
ip link show master vmbr50

echo
echo "=== [8] CT150 ==="
pct exec 150 -- ip -br addr show eth1
pct exec 150 -- systemctl is-active nftables dnsmasq captive-portal.service captive-admin.service captive-bw-sync.service

echo
echo "=== [9] Persistence proof ==="
grep -rn 'vmbr50' /etc/network/ | sed 's/^/    /'
