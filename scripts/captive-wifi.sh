#!/usr/bin/env bash
# Toggle the local captive AP (SSID: Casper-SSO) on the Proxmox host.
#   on      start + enable hostapd  (SSID broadcast, portal reachable)
#   off     stop + disable hostapd  (SSID disappears; nothing can connect)
#   status  show current state
set -euo pipefail
case "${1:-status}" in
  on)
    systemctl enable hostapd >/dev/null 2>&1 || true
    systemctl start hostapd
    sleep 3
    echo "hostapd: $(systemctl is-active hostapd)"
    echo "ssid   : $(iw dev wlp1s0 info 2>/dev/null | awk "/ssid/{print \$2}")"
    ;;
  off)
    systemctl stop hostapd
    systemctl disable hostapd >/dev/null 2>&1 || true
    echo "hostapd: $(systemctl is-active hostapd)"
    echo "ssid   : (off the air)"
    ;;
  status)
    echo "hostapd   : $(systemctl is-active hostapd)"
    echo "enabled   : $(systemctl is-enabled hostapd 2>/dev/null || echo disabled)"
    echo "ssid      : $(iw dev wlp1s0 info 2>/dev/null | awk "/ssid/{print \$2}")"
    echo "type      : $(iw dev wlp1s0 info 2>/dev/null | awk "/type/{print \$2}")"
    echo "encryption: $(grep -E "^wpa=" /etc/hostapd/hostapd.conf 2>/dev/null || echo "(none = open)")"
    ;;
  *) echo "usage: $0 {on|off|status}"; exit 2;;
esac
