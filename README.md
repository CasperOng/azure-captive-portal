# Captive Portal Gateway

A self-contained captive portal for an isolated Wi-Fi segment, running as a
privileged Debian 12 LXC container on Proxmox VE. Unauthenticated clients are
intercepted and forced through a sign-in page — **email + password**, or
**Microsoft Entra ID SSO** — after which their device MAC is authorized in
`nftables` for 8 hours. A separate admin console provides per-device bandwidth
limiting, account management and provisioning of fixed devices.

The access point is hosted **directly on the Proxmox host** (`hostapd` on the
internal PCIe Wi-Fi card) and confined to an isolated bridge, so the captive
segment shares no layer-2 path with the household LAN.

---

## 1. Architecture

```
        Wi-Fi clients (SSID: Casper-SSO, WPA2/WPA3-Personal)
                     │
                     │  802.11, client isolation ON (ap_isolate)
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
   │    ├── FastAPI      :3000       captive portal (HTTP, captive)   │
   │    └── FastAPI      :3001       admin console (HTTPS, WAN only)  │
   │                                                                  │
   │   eth0  192.168.1.10/24 (dhcp) ── WAN / OAuth2 backchannel    │
   └───────────────────────────────┬──────────────────────────────────┘
                                   │
                            vmbr0 / household LAN
                            192.168.1.0/24 ──► internet

   CT 115  cloudflared  ──► Cloudflare Tunnel ──► portal.example.com   (portal)
                                               └─► admin.example.com (console,
                                                   behind Cloudflare Access)
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

- **RFC 8910 Option 114** → `http://10.50.0.1:3000/api/capport`.
- **RFC 8908 API** → `/api/capport` returns `{"captive": false}` for authorized
  MACs, otherwise `{"captive": true, "user-portal-url": ...}`.
- OS probe endpoints (`/generate_204`, `/hotspot-detect.html`, `/connecttest.txt`,
  `/ncsi.txt`) return the login page.

Unauthenticated HTTP is DNAT'd to the portal, so macOS/Windows/Android probes land
on the sign-in page regardless of which OS endpoint they use.

### Authentication flows

**Email + password (primary).** `POST /login` verifies against the `users` table
(PBKDF2-SHA256, 200k rounds, per-user salt), then runs
`nft add element inet captive authorized_macs { <MAC> timeout 8h }`. Refused
outside the captive segment, where the device MAC cannot be resolved.

**Microsoft Entra ID SSO (secondary).** `/auth/login` builds the Entra v2
authorize URL with an **HMAC-signed `state`** carrying the client IP, MAC and a
per-request `nonce`. `/auth/callback` verifies the state signature, exchanges the
code for an ID token over `eth0`, **verifies that token's RS256 signature against
the tenant JWKS** plus `iss`/`aud`/`exp`/`iat`/`nonce`, requires the email to
already exist as an account, and then authorizes the MAC. Because the MAC rides
inside the signed state, the flow still works when the callback arrives through
the Cloudflare tunnel.

Sign-in is throttled after 6 failures per source address within 5 minutes.

### Walled garden

Devices that are not yet authorized must still reach the SSO infrastructure.
`dnsmasq`'s `nftset=` directive watches lookups for the relevant domains and
dynamically inserts the resolved IPs into the `walled_garden_ips` `nftables` set
(1h timeout), which the forward chain permits:

```
login.microsoftonline.com  login.live.com  aadcdn.msftauth.net  aadcdn.msauth.net
msftauth.net  msauth.net  graph.microsoft.com  portal.example.com
```

---

## 2. Repository layout

```
app/                        FastAPI applications -> /opt/captive-portal
  main.py                     captive portal + Entra ID OAuth2
  common.py                   shared: SQLite store, nftables control, HMAC signing
  admin.py                    admin console (bandwidth, accounts, profiles)
  .env.example                template -> .env  (real .env is gitignored)
  requirements.txt            pinned runtime dependencies
  systemd/
    captive-portal.service      portal on :3000
    captive-admin.service       console on :3001 (TLS)
    captive-bw-sync.service     re-applies limits after nftables (re)loads
    captive-device-sync.*       keeps auto-authorize devices online (5 min timer)
    captive-db-backup.*         daily database backup (14 kept)
config/
  nftables.conf               -> /etc/nftables.conf            (CT 150)
  dnsmasq-captive.conf        -> /etc/dnsmasq.d/captive.conf   (CT 150)
  hostapd.conf                -> /etc/hostapd/hostapd.conf     (host)
  vmbr50                      -> /etc/network/interfaces.d/vmbr50 (host)
scripts/
  install-panel.sh            install/refresh the console in CT 150
  finish-panel.sh             idempotent finish + credential setup
  backup-db.sh                online SQLite backup, rotation
  repoint-ap.sh               point hostapd + CT 150 eth1 at vmbr50
  persist-vmbr50.sh           persist vmbr50 across reboots, clean leftovers
security/AUDIT.md             security & stability audit + remediation status
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
# then set a real wpa_passphrase in that file
systemctl restart hostapd
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

pct exec 150 -- bash -c '
  printf "net.ipv4.ip_forward=1\n" > /etc/sysctl.d/99-captive.conf
  sysctl --system
  apt-get update
  apt-get install -y --no-install-recommends \
    dnsmasq nftables python3 python3-venv python3-pip curl iproute2 ca-certificates openssl
  python3 -m venv /opt/captive-portal/venv
'
```

### 3.4 Gateway services

Copy the application in, then install dependencies, TLS and units:

```bash
for f in main.py common.py admin.py requirements.txt; do
  pct push 150 app/$f /opt/captive-portal/$f --perms 644
done
pct push 150 config/nftables.conf        /etc/nftables.conf           --perms 644
pct push 150 config/dnsmasq-captive.conf /etc/dnsmasq.d/captive.conf  --perms 644
for u in app/systemd/*; do
  pct push 150 "$u" "/etc/systemd/system/$(basename "$u")" --perms 644
done
pct push 150 scripts/backup-db.sh /opt/captive-portal/backup-db.sh --perms 755

pct exec 150 -- /opt/captive-portal/venv/bin/pip install -r /opt/captive-portal/requirements.txt
pct exec 150 -- bash -c 'mkdir -p /opt/captive-portal/tls && cd /opt/captive-portal/tls &&
  openssl req -x509 -newkey rsa:2048 -nodes -keyout admin.key -out admin.crt \
    -days 825 -subj "/CN=captive-admin" \
    -addext "subjectAltName=IP:192.168.1.10,IP:127.0.0.1,DNS:localhost" &&
  chmod 600 admin.key'

pct exec 150 -- bash -c '
  systemctl daemon-reload
  systemctl enable --now nftables dnsmasq
  systemctl enable --now captive-portal.service captive-admin.service captive-bw-sync.service
  systemctl enable --now captive-device-sync.timer captive-db-backup.timer
'
```

`scripts/install-panel.sh` automates the above on an existing container.

### 3.5 Credentials

```bash
cp app/.env.example /tmp/portal.env    # then edit, or:
pct exec 150 -- nano /opt/captive-portal/.env
pct exec 150 -- chmod 600 /opt/captive-portal/.env
pct exec 150 -- systemctl restart captive-portal.service captive-admin.service
```

Set `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`, and a
`SESSION_SECRET` of **at least 32 characters**. Both apps refuse to start
otherwise — the secret signs the admin session cookie and the OAuth `state`, so a
weak or missing value must never silently degrade to a known constant.

---

## 4. Admin console

| | |
|---|---|
| LAN | `https://192.168.1.10:3001` (self-signed certificate) |
| External | `https://admin.example.com` (Cloudflare Access in front) |

Bound to the **WAN side only** — blocked at `nftables`
(`iifname "eth1" tcp dport 3001 drop`) and in the app (source IP must match
`ADMIN_ALLOW_NET`). Login is throttled after 5 failures, and the session cookie is
`Secure`, `HttpOnly`, `SameSite=strict` and bound to the peer address.

When published through the tunnel, requests arriving from the tunnel origin must
carry a valid **Cloudflare Access JWT**; the app verifies the signature itself.
Until `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` are set, such requests are refused
outright, so publishing the hostname can never leave the console exposed.

**Accounts** — email + password with a role of `wifi` or `admin`. Admins sign
into the console; both roles can sign into the captive portal. The shared
`ADMIN_PASSWORD` remains as a bootstrap (leave the email field blank) so you
cannot be locked out before the first admin account exists.

**Bandwidth control** — one limit per device, applied to **both** directions:

- `0 kbps` / ticking **Unlimited** removes the limit entirely.
- Any other value installs two rules in the `bandwidth_limits` chain, e.g. for
  5000 kbps (= 625 kbytes/s each way):

```
ether saddr aa:bb:cc:dd:ee:ff limit rate over 625 kbytes/second drop comment "bw:aa:bb:cc:dd:ee:ff"
ether daddr aa:bb:cc:dd:ee:ff limit rate over 625 kbytes/second drop comment "bw:aa:bb:cc:dd:ee:ff"
```

The chain hooks `forward` at **priority -10**, so shaping drops happen *before*
the forward chain accepts the packet. Labels and limits live in SQLite; rules are
volatile and re-applied on boot by `captive-bw-sync.service`.

> Note: `nft limit` is a per-rule token bucket, not `tc`/HTB shaping. It is
> effective for keeping the segment fair but is not a byte-accurate shaper.

---

## 5. Device profiles

The **Profiles & devices** page provisions fixed kit — whiteboards, public PCs —
without a browser sign-in. A profile carries a bandwidth limit, a session length,
an identity method (`mac`/`psk`/`cert`/`sso`) and an **Auto-authorize** flag.

Devices assigned to an auto-authorize profile are re-asserted in
`authorized_macs` every 5 minutes by `captive-device-sync.timer`. Because
`nftables` state is volatile, this also means they survive a container reboot or
ruleset reload instead of silently dropping off.

Identity is currently **MAC-based**, which is spoofable by anyone who knows the
Wi-Fi passphrase. The `auth_method` column is the hook for moving these devices
to per-device PSK or 802.1X.

---

## 6. Operations

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
pct exec 150 -- systemctl list-timers 'captive-*'

# Backups
pct exec 150 -- ls -l /var/backups/captive-portal/
pct exec 150 -- /opt/captive-portal/backup-db.sh      # run one now

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
| Admin console 403 | Cloudflare Access not configured, or no valid Access JWT |
| Service won't start | `SESSION_SECRET` missing or < 32 chars (fails closed by design) |
| Host vanishes briefly | Intel I226-V (`igc`) link flap; `dmesg -T \| grep "NIC Link"` |

---

## 7. Security notes

- Secrets live in `/opt/captive-portal/.env` (`chmod 600`) and are **gitignored**.
  Only `.env.example` is tracked.
- `SESSION_SECRET` is **fail-closed**: both apps refuse to start on a missing,
  short or placeholder value.
- The SSID uses **WPA2/WPA3-Personal** with **client isolation** (`ap_isolate=1`),
  so associated clients cannot sniff or attack one another.
- The captive segment is isolated at layer 2; `vmbr50` has no path to `vmbr0`.
- The admin console is HTTPS-only, never exposed to the captive segment, and
  fronted by Cloudflare Access when published externally.
- Entra ID tokens are signature-verified against the tenant JWKS, and SSO
  requires an account that an administrator has provisioned.
- The OAuth `state` is HMAC-signed, single-window (10 minutes) and carries a
  `nonce`; `/auth/callback` will not authorize an arbitrary device.
- Both apps send CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options`,
  `Referrer-Policy` and `Permissions-Policy`; the API schema is not published.
- `portal.db` is mode 600, runs in WAL mode, and is backed up daily.

See `security/AUDIT.md` for the full audit, what was remediated, and what remains
(the MAC trust model, the single-container SPOF, host NIC flaps, monitoring).
