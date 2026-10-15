# Captive Portal Gateway — Microsoft Entra ID (OAuth2)

A self-contained captive portal for an isolated Wi-Fi segment, running as a
privileged Debian 12 LXC container on Proxmox VE. Unauthenticated clients are
intercepted and forced through a **Microsoft Entra ID** sign-in; on success their
device MAC is authorized in `nftables` for 8 hours. An admin panel provides
per-device bandwidth limiting.

The access point is hosted **directly on the Proxmox host** (`hostapd` on the
internal PCIe Wi-Fi card) and confined to an isolated bridge, so the captive
segment shares no layer-2 path with the household LAN.

---

## 1. Architecture

```
        Wi-Fi clients (open SSID: Casper-SSO)
                     │
                     │  802.11 (open / no PSK)
                     ▼
        ┌────────────────────────────────────────┐
        │  Proxmox host  (pve-prod-1)            │
        │                                        │
        │  wlp1s0  ── hostapd (AP mode)          │
        │     │                                  │
        │     └── enslaved to ──► vmbr50         │  isolated bridge,
        │                          │             │  NO uplink to vmbr0
        │                          │             │
        │              veth150i1 ──┘             │
        └──────────────────────────┬─────────────┘
                                   │
   ┌───────────────────────────────┼──────────────────────────────────┐
   │  CT 150  "oauth-core"  (Debian 12, privileged, nesting=1)        │
   │                                                                  │
   │   eth1  10.50.0.1/24  ◄── captive gateway (vmbr50)               │
   │    ├── dnsmasq      :53 / :67   DHCP + DNS + RFC 8910 Option 114 │
   │    ├── nftables     DNAT 80►3000, forward-drop, masquerade       │
   │    ├── FastAPI      :3000       captive portal + Entra ID OAuth2 │
   │    └── FastAPI      :3001       admin panel (WAN-side only)      │
   │                                                                  │
   │   eth0  192.168.1.10/24 (dhcp) ── WAN / OAuth2 backchannel    │
   └───────────────────────────────┬──────────────────────────────────┘
                                   │
                            vmbr0 / household LAN
                            192.168.1.0/24 ──► internet
```

### Network layout

| Interface | Bridge | Address | Role |
|---|---|---|---|
| `wlp1s0` (host) | `vmbr50` | — | AP radio, `hostapd` |
| CT 150 `eth1` | `vmbr50` | `10.50.0.1/24` | Captive gateway (DHCP/DNS/HTTP) |
| CT 150 `eth0` | `vmbr0` | `192.168.1.10/24` (DHCP) | WAN + Entra ID token exchange |

`vmbr50` has exactly two members — the radio and the container's `eth1` — and no
uplink. The only route off the captive segment is through CT 150, which enforces
the `nftables` policy.

### DHCP / captive-portal discovery

`dnsmasq` serves `10.50.0.50–10.50.0.250/24` with an 8-hour lease, advertising
gateway and DNS as `10.50.0.1`, plus:

- **RFC 8910 Option 114** → `http://10.50.0.1:3000/api/capport` (modern OSes
  fetch this directly to discover the portal).
- **RFC 8908 API** → `/api/capport` returns `{"captive": false}` for authorized
  MACs, otherwise `{"captive": true, "user-portal-url": ...}`.
- OS probe endpoints (`/generate_204`, `/hotspot-detect.html`, `/connecttest.txt`,
  `/ncsi.txt`) return the login page so legacy detection also triggers a popup.

### Authentication flow

1. Client gets a lease; `nftables` prerouting DNATs its port 80 to `:3000`.
2. Portal renders a sign-in page showing the detected IP/MAC.
3. **Sign in with Microsoft** → `/auth/login` builds the Entra v2 authorize URL
   (`scope=openid profile email`) with an **HMAC-signed `state`** carrying the
   client IP + MAC.
4. `/auth/callback` verifies the state signature, exchanges the `code` for an ID
   token over `eth0`, reads `preferred_username` / `name`, then runs
   `nft add element inet captive authorized_macs { <MAC> timeout 8h }` and
   appends to `/var/log/captive-auth.log`.

### Walled garden

Devices that are not yet authorized must still reach Microsoft's SSO
infrastructure. `dnsmasq`'s `nftset=` directive watches lookups for the relevant
domains and dynamically inserts the resolved IPs into the `walled_garden_ips`
`nftables` set (1h timeout), which the forward chain permits:

```
login.microsoftonline.com  login.live.com  aadcdn.msftauth.net  aadcdn.msauth.net
msftauth.net  msauth.net  graph.microsoft.com
```

---

## 2. Repository layout

```
app/                        FastAPI application -> /opt/captive-portal
  main.py                     captive portal + Entra ID OAuth2
  common.py                   shared: SQLite store, nftables control, HMAC signing
  admin.py                    admin panel (bandwidth + access control)
  .env.example                template -> /.env  (real .env is gitignored)
  systemd/
    captive-portal.service      portal on :3000
    captive-admin.service       admin panel on :3001
    captive-bw-sync.service     re-applies limits after nftables (re)loads
config/
  nftables.conf               -> /etc/nftables.conf            (CT 150)
  dnsmasq-captive.conf        -> /etc/dnsmasq.d/captive.conf   (CT 150)
  hostapd.conf                -> /etc/hostapd/hostapd.conf     (host)
  vmbr50                      -> /etc/network/interfaces.d/vmbr50 (host)
scripts/
  install-panel.sh            install/refresh the admin panel in CT 150
  finish-panel.sh             idempotent finish + credential setup
  repoint-ap.sh               point hostapd + CT 150 eth1 at vmbr50
  persist-vmbr50.sh           persist vmbr50 across reboots, clean leftovers
```

---

## 3. Deployment

All commands run **as root on the Proxmox host** (`pve-prod-1`).

### 3.1 Host-side bridge (persist across reboots)

```bash
install -m 644 config/vmbr50 /etc/network/interfaces.d/vmbr50
ifreload -a
ip link show master vmbr50          # expect: wlp1s0 + veth150i1
```

### 3.2 Access point

```bash
install -m 644 config/hostapd.conf /etc/hostapd/hostapd.conf
systemctl restart hostapd
systemctl is-active hostapd
iw dev wlp1s0 info | grep -E 'ssid|type'
```

### 3.3 Container (CT 150)

```bash
pct create 150 local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst \
  --hostname oauth-core --cores 2 --memory 1024 --swap 512 \
  --rootfs local:8 --unprivileged 0 --features nesting=1 --onboot 1 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --net1 name=eth1,bridge=vmbr50,ip=10.50.0.1/24
pct start 150
```

### 3.4 Gateway services

```bash
pct exec 150 -- bash -c '
  printf "net.ipv4.ip_forward=1\n" > /etc/sysctl.d/99-captive.conf
  sysctl --system
  apt-get update
  apt-get install -y --no-install-recommends \
    dnsmasq nftables python3 python3-venv python3-pip curl iproute2 ca-certificates
  python3 -m venv /opt/captive-portal/venv
  /opt/captive-portal/venv/bin/pip install fastapi uvicorn httpx python-dotenv python-multipart
'
```

Then copy the files in and enable everything:

```bash
for f in main.py common.py admin.py; do
  pct push 150 app/$f /opt/captive-portal/$f --perms 644
done
pct push 150 config/nftables.conf         /etc/nftables.conf           --perms 644
pct push 150 config/dnsmasq-captive.conf  /etc/dnsmasq.d/captive.conf  --perms 644
for u in app/systemd/*.service; do
  pct push 150 "$u" "/etc/systemd/system/$(basename "$u")" --perms 644
done

pct exec 150 -- bash -c '
  systemctl daemon-reload
  systemctl enable --now nftables dnsmasq
  systemctl enable --now captive-portal.service captive-admin.service captive-bw-sync.service
'
```

### 3.5 Credentials

```bash
cp app/.env.example /tmp/portal.env    # then edit, or:
pct exec 150 -- nano /opt/captive-portal/.env
pct exec 150 -- chmod 600 /opt/captive-portal/.env
pct exec 150 -- systemctl restart captive-portal.service captive-admin.service
```

Set `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`, and a real
`SESSION_SECRET`. In the Entra app registration, add
`http://localhost:3000/auth/callback` as a **Web** redirect URI.

Until real credentials are entered, leave `DEMO_BYPASS_MODE=true` and use the
**1-Click Demo Authorize** button to exercise the firewall path.

---

## 4. Admin panel

Reachable at `http://<host>:3001`, bound to the **WAN side only** — blocked at
both `nftables` (`iifname "eth1" tcp dport 3001 drop`) and in the app (source IP
must match `ADMIN_ALLOW_NET`). Login is throttled after 5 failures.

**Bandwidth control** — one limit per device, applied to **both** directions:

- `0 kbps` / ticking **Unlimited** removes the limit entirely.
- Any other value installs two rules in the `bandwidth_limits` chain, e.g. for
  5000 kbps (= 625 kbytes/s each way):

```
ether saddr aa:bb:cc:dd:ee:ff limit rate over 625 kbytes/second drop comment "bw:aa:bb:cc:dd:ee:ff"
ether daddr aa:bb:cc:dd:ee:ff limit rate over 625 kbytes/second drop comment "bw:aa:bb:cc:dd:ee:ff"
```

The chain hooks `forward` at **priority -10**, so shaping drops happen *before*
the forward chain accepts the packet. Labels and limits live in SQLite
(`/opt/captive-portal/portal.db`); rules are volatile and re-applied on boot by
`captive-bw-sync.service`.

The panel also offers **Authorize** / **Revoke** per device, and a JSON view at
`/api/devices`.

> Note: `nft limit` is a per-rule token bucket, not `tc`/HTB shaping. It is
> effective for keeping the segment fair but is not a byte-accurate shaper.

---

## 5. Operations

```bash
# Watch successful logins
pct exec 150 -- tail -f /var/log/captive-auth.log

# Currently authorized devices
pct exec 150 -- nft list set inet captive authorized_macs

# Dynamically permitted SSO endpoints
pct exec 150 -- nft list set inet captive walled_garden_ips

# Active bandwidth rules
pct exec 150 -- nft list chain inet captive bandwidth_limits

# Service health
pct exec 150 -- systemctl status captive-portal.service captive-admin.service

# Re-apply stored limits manually
pct exec 150 -- systemctl restart captive-bw-sync.service
```

### Troubleshooting

| Symptom | Check |
|---|---|
| No captive popup | `nft list chain inet captive prerouting` — DNAT 80→3000 present? |
| Client reaches household LAN | `ip link show master vmbr50` — must list **only** `wlp1s0` + `veth150i1` |
| No DHCP lease | `pct exec 150 -- ss -ulpn \| grep :67` — dnsmasq bound to `%eth1` |
| SSO page fails to load | walled garden: `nft list set inet captive walled_garden_ips` non-empty? |
| Host vanishes briefly | Intel I226-V (`igc`) link flap; `dmesg -T \| grep "NIC Link"` |

---

## 6. Security notes

- `os.environ` secrets live in `/opt/captive-portal/.env` (`chmod 600`) and are
  **gitignored**. Only `.env.example` is tracked.
- The SSID is **open and unencrypted** — required for captive-portal interception.
  Client traffic is readable over the air until it reaches HTTPS.
- The captive segment is isolated at layer 2; `vmbr50` has no path to `vmbr0`.
- The admin panel is never exposed to the captive segment.
- `/auth/callback` verifies an HMAC-signed, 1-hour-expiring `state` before
  authorizing a MAC, so the callback cannot be replayed to authorize an
  arbitrary device.
