# Entra ID Captive Portal

**A self-hosted captive portal that authorises devices by MAC after an OIDC sign-in — no 802.1X, no RADIUS, no controller.**

[![License: MIT](https://img.shields.io/badge/license-MIT-1f7a4e.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](app/requirements.txt)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.143-009688?logo=fastapi&logoColor=white)](app/requirements.txt)
[![Platform](https://img.shields.io/badge/platform-Proxmox%20LXC%20%C2%B7%20Debian%2012-E57000?logo=proxmox&logoColor=white)](#deployment)
[![Status](https://img.shields.io/badge/status-proof%20of%20concept-d99a26)](#limitations)
[![Security](https://img.shields.io/badge/security-reviewed%20%C2%B7%2027%20findings-1f7a4e)](security/AUDIT.md)

> **Status: proof of concept.** This is a working research build, not a product. It was written to answer a specific question — *can a usable captive portal be built with nothing but a Linux host, `nftables` and an OIDC provider?* — and the answer is "yes, with one structural caveat". Read [Limitations](#limitations) before deploying it anywhere real.

---

## The problem

A small network needs guest Wi-Fi with per-device accountability: who is online, for how long, at what speed. The textbook answer is 802.1X with RADIUS and per-user certificates. That needs a CA, a supplicant on every client, and a RADIUS server — infrastructure that is disproportionate for a dozen devices and impossible for a smart TV or a whiteboard.

This project takes the cheaper route: a **captive portal** that intercepts unauthenticated HTTP, makes the user sign in through an OIDC provider, and then allow-lists the device's **MAC address** in the kernel firewall for a fixed lease.

That trade is the whole point of the PoC — and its central weakness.

---

## Design

```
        Wi-Fi clients (SSID, WPA2/WPA3-Personal)
                     │
                     │  802.11, client isolation ON (ap_isolate)
                     ▼
        ┌────────────────────────────────────────┐
        │  Proxmox host                          │
        │  wlp1s0 ── hostapd (AP mode)           │
        │     └── enslaved to ──► vmbr50         │  isolated bridge,
        │                          │             │  NO uplink
        │              veth150i1 ──┘             │
        └──────────────────────────┬─────────────┘
                                   │
   ┌───────────────────────────────┼──────────────────────────────────┐
   │  CT 150  (Debian, privileged)                                    │
   │   eth1  10.50.0.1/24  ◄── captive gateway                       │
   │    ├── dnsmasq   :53/:67   DHCP + DNS + RFC 8910 Option 114     │
   │    ├── nftables  DNAT 80►3000, default-drop forward, masquerade │
   │    ├── FastAPI   :3000     captive portal (HTTP, captive net)   │
   │    └── FastAPI   :3001     admin console (HTTPS, WAN side only) │
   │   eth0  192.168.1.10/24 ── WAN / OIDC backchannel               │
   └──────────────────────────────────────────────────────────────────┘
```

The captive segment is a bridge with exactly two members — the radio and the container's second interface — and no uplink. The only route off the segment is through the container, which enforces the policy.

---

## How a device gets online

1. Client takes a DHCP lease. Any HTTP request is DNAT'd to the portal.
2. The portal renders a sign-in page showing the detected IP and MAC.
3. The user signs in — **email + password** (PBKDF2-SHA256, 200k rounds) or **OIDC**.
4. On success the server runs:

   ```bash
   nft add element inet captive authorized_macs { <MAC> timeout 8h }
   ```

5. The forward chain now accepts that MAC's traffic; accounting counters start; an optional bandwidth limit is installed.

Three details make this work in practice:

**The MAC travels inside the OIDC `state`.** A callback arrives over the public hostname, so the request's source address is the tunnel, not the device. The signed `state` carries IP + MAC + nonce, so the right device is authorised regardless.

**The walled garden is DNS-driven.** Unauthenticated clients may only reach the SSO endpoints. `dnsmasq` watches lookups for those domains and inserts the resolved IPs into an `nftables` set with a one-hour timeout, so the allow-list stays current without hardcoding addresses.

**Plain HTTP is enough for the probe.** Redirecting port 80 catches every OS captive probe — macOS, Windows, Android — without allowing the probe destination through, which is what would otherwise make the OS think it is online.

---

## What the investigation found

The interesting part of this build was not the happy path. A full security review is in [`security/AUDIT.md`](security/AUDIT.md); the findings that changed the design:

| Finding | Consequence |
|---|---|
| A fail-open `SESSION_SECRET` fallback | One missing env var would have signed admin cookies and OAuth `state` with a **publicly known constant**. Now both apps refuse to start. |
| The ID token was base64-decoded, never verified | Any well-formed token was trusted. Now RS256 against the tenant JWKS, plus `iss`/`aud`/`exp`/`nonce`. |
| The admin console spoke plaintext HTTP | Password and session cookie crossed the LAN in the clear. Now TLS-only with a `Secure`, IP-bound cookie. |
| The portal login posted credentials over the air | Mitigated by WPA2/WPA3 plus `ap_isolate=1`, so clients cannot sniff each other. |
| **MAC is the entire trust boundary** | Any client can clone an authorised MAC. This is inherent and cannot be fixed inside the portal — see below. |
| Firewall state is volatile | A reboot silently deauthorised every provisioned device. A timer now re-asserts them every five minutes. |

Two of these were found by testing, not by reading: the OAuth callback was authorising the **tunnel's** MAC instead of the client's, and a `:` in an `nftables` comment was silently corrupting MAC addresses.

---

## Limitations

**MAC authorisation is spoofable.** This is the honest, central caveat. A MAC address is not a secret; anyone who can join the SSID can impersonate an authorised device. Everything else in this project is hardening around that fact. The real fix is per-device PSK (hostapd `wpa_psk_file`) or 802.1X — which is the infrastructure this PoC set out to avoid. The `auth_method` column exists to make that migration possible.

**Other known limits:**

- The captive portal serves HTTP on the captive segment. TLS there means certificate warnings or a custom CA on every client.
- Single container is a single point of failure for portal, admin, DHCP and NAT.
- `nft limit` is a token bucket, not `tc` shaping — fine for fairness, not byte-accurate.
- The admin console is protected by a password and, when published, Cloudflare Access. It is not hardened for multi-tenant use.

---

## Deployment

Runs on a Proxmox host with an isolated bridge and one privileged Debian container.

```bash
# 1. isolated bridge + AP
install -m 644 config/vmbr50 /etc/network/interfaces.d/vmbr50 && ifreload -a
install -m 644 config/hostapd.conf /etc/hostapd/hostapd.conf   # set a real passphrase
systemctl restart hostapd

# 2. container
pct create 150 local:vztmpl/debian-12-standard_*.tar.zst \
  --hostname captive --cores 2 --memory 1024 --unprivileged 0 --features nesting=1 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --net1 name=eth1,bridge=vmbr50,ip=10.50.0.1/24

# 3. application
pct exec 150 -- apt-get install -y dnsmasq nftables python3 python3-venv openssl
pct exec 150 -- python3 -m venv /opt/captive-portal/venv
# copy app/, config/, install requirements.txt, then:
bash scripts/install-panel.sh
```

Configuration lives in `.env` (see [`app/.env.example`](app/.env.example)): OIDC client credentials, a 32+ character `SESSION_SECRET`, an admin bootstrap password, and optional Cloudflare Access settings. Both applications **fail closed** if the secret is missing or weak.

`scripts/install-panel.sh` installs the units, generates the admin TLS certificate, and enables the portal, admin console, bandwidth re-sync, device re-assertion and database backup timers.

---

## Admin console

HTTPS on `:3001`, WAN-side only, blocked from the captive VLAN in both `nftables` and the application.

- **Accounts** — email + password, role `wifi` or `admin`, keyed on email so a later OIDC identity can link by verified address.
- **Devices** — live list, per-device bandwidth (one value, both directions, `0` = unlimited), revoke, delete.
- **Profiles** — provision fixed kit (displays, public PCs) with a bandwidth, a session length and an auto-authorise flag, so they stay online without a browser sign-in.
- **Download** — a per-profile provisioning sheet with the SSID, passphrase and per-OS steps.

When published through a tunnel, the app verifies the Cloudflare Access JWT itself rather than trusting the edge alone.

---

## Layout

```
app/            FastAPI portal + admin console, shared helpers, systemd units
config/         nftables, dnsmasq, hostapd, bridge definition
scripts/        install / finish / AP control / DB backup
security/       security review and remediation status
```

---

## Licence

MIT — see [LICENSE](LICENSE). The code is yours to run, fork and learn from.

If you deploy this, the MAC-spoofing limitation is yours to solve. It is documented here precisely so nobody ships it believing it is 802.1X.
