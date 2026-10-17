# Security & Stability Audit — Captive Portal Gateway

**Date:** 2026-10-17
**Scope:** `app/main.py`, `app/common.py`, `app/admin.py`, `config/nftables.conf`,
`config/hostapd.conf`, `config/dnsmasq-captive.conf`, `scripts/*`, plus live probes
against the deployed target (`https://portal.example.com`, `http://192.168.1.10:3000|3001`
and CT 150 on `10.50.0.1`).
**Method:** manual review against the `vibe-security-audit` 30-point checklist + targeted live
probes. Automated scanners (`vibe-check`, Vibeship) were **not** run yet.

## Detected stack

| Component | Detail |
|---|---|
| Framework | FastAPI + uvicorn (Python), two apps: portal `:3000`, admin `:3001` |
| Database | SQLite `portal.db` (devices, users, profiles) |
| Auth | Custom: PBKDF2-SHA256 (200k) + HMAC-SHA256 signed cookies; Microsoft Entra OAuth2 (secondary) |
| Edge | Cloudflare Tunnel → portal for `portal.example.com` |
| Network | nftables `inet captive` (firewall/NAT/accounting), hostapd AP, dnsmasq DHCP/DNS |
| Not present | payments, email, AI, cloud storage, webhooks |

## Result

**27 findings — 5 critical, 6 high, 9 medium, 7 stability/ops.**
Raw formula (100 − Σseverity) = **0/100 (Critical)**. That is unforgiving for a
single-user lab. Weighted judgement: the *architecture* is sound (no SQLi, parameterised
queries, HMAC-signed sessions, PBKDF2, WAN-restricted admin, default-deny forward chain),
but **four deployment decisions make it unsafe the moment a second person is on the Wi-Fi.**
Those are listed first. Fixing them raises the effective score to roughly **70 (Good)**.

---

## Critical — fix before trusting this on a shared network

### C1. Fail-open `SESSION_SECRET` (10/10)
`app/main.py:51`, `app/admin.py:38`
```python
os.getenv("SESSION_SECRET", "default-fallback-secret-change-me")
```
If the env var is ever missing or unreadable, the HMAC key becomes a **publicly known
constant**. That forges both the admin session cookie (`{"role":"admin"}`) *and* the OAuth
`state` parameter. It fails **open**, silently.
**Fix:** refuse to start (or return 500) when `SESSION_SECRET` is unset or < 32 chars.

### C2. Admin console is cleartext HTTP; session cookie has no `Secure` (9/10)
`app/admin.py:540`; live `http://192.168.1.10:3001` → 200
The admin password and the `admin_session` cookie travel unencrypted across the LAN. Any
host on `192.168.1.0/24` can sniff the password or replay the cookie.
**Fix:** bind the admin to loopback and reach it via SSH tunnel, or terminate TLS. Add
`secure=True` to the cookie once TLS exists.

### C3. Portal credentials travel in cleartext over the air (9/10)
`POST http://10.50.0.1:3000/login` — email + password posted in the clear.
Every client on `Casper-SSO` shares one PSK, so any of them can capture another's
credentials off the air.
**Fix:** serve the portal over TLS (self-signed + a trust exception, or the tunnel), or
replace password auth on the captive segment with a device-code / one-time flow.

### C4. MAC address is the entire trust boundary (8/10)
`config/nftables.conf:45` (`ether saddr @authorized_macs`); `app/main.py:74` (`get_client_mac` via ARP)
Any client can set its MAC to an authorized value and receive full access. ARP is also
poisonable, so `get_client_mac` can be lied to.
**Fix:** per-device PSK (hostapd `wpa_psk_file`) or 802.1X, so identity is a secret key or a
certificate rather than a spoofable L2 field. Until then, treat MAC auth as convenience,
not security.

### C5. Entra ID token is never validated (8/10)
`app/main.py:187` `decode_jwt_claims` base64-decodes the payload; `:567` reads claims from it.
No signature check, and **no `iss` / `aud` / `exp` / `nonce` validation either.**
The server-side code exchange mitigates the practical risk, but this is the trust root for
identity and audit attribution (`preferred_username` is logged unverified).
**Fix:** verify the JWKS signature and validate `iss`, `aud`, `exp`; add a `nonce`.

---

## High

| # | Issue | Evidence |
|---|---|---|
| H1 | **SSO authorises any account in the tenant** — no allow-list; the `users` table is never consulted, so `preferred_username` is only logged. | `app/main.py:567-574` |
| H2 | **`/docs`, `/redoc`, `/openapi.json` publicly reachable** — full API schema exposed via the tunnel (verified HTTP 200). | live probe |
| H3 | **`GET /api/devices` has no session check** — leaks the full MAC inventory and which devices are authorized/limited. (The `POST` sibling at `:663` *is* protected.) | `app/admin.py:643` |
| H4 | **No dependency manifest** — no `requirements.txt`; deps unpinned and un-scannable. | repo root |
| H5 | **`app/.env.example` (tracked) ships `DEMO_BYPASS_MODE=true`** — a footgun that grants unauthenticated auto-authorize if copied. Also `ADMIN_PASSWORD=change-this...`. | `app/.env.example:22` |
| H6 | **Portal `:3000` exposed on the LAN** with no `eth0` restriction (verified 200 from `192.168.1.10`). Extra attack surface. | live probe |

## Medium

| # | Issue | Evidence |
|---|---|---|
| M1 | No security headers on either app (no CSP, `X-Frame-Options`, HSTS, `X-Content-Type-Options`) → admin console is clickjackable. | both apps |
| M2 | `portal.db` is **world-readable** (`-rw-r--r--`) and holds password hashes. `.env` is correctly `600`. | CT150 |
| M3 | Portal login throttle is in-memory and **leaks memory** — `_LOGIN_FAILURES[ip]` is written for every distinct IP and empty entries are never pruned. | `app/main.py:28-41` |
| M4 | Admin session is **not bound to the recorded IP**, so a stolen cookie replays from anywhere. | `app/admin.py:110` |
| M5 | Upstream token-exchange error body is echoed to the browser. | `app/main.py:560` |
| M6 | OAuth `state` is replayable for its full 1-hour window (no single-use nonce). | `app/main.py:173-184` |
| M7 | `is_mac_authorized` parses `nft` output by **substring match** — fragile, could false-positive across element boundaries. | `app/main.py:129` |

## Stability / operations

| # | Issue | Evidence |
|---|---|---|
| S1 | **All authorization state is volatile kernel state.** A container reboot or `flush ruleset` silently deauthorizes every device; `config/nftables.conf` begins with `flush ruleset`. | nft design |
| S2 | **Single container is a SPOF** for portal + admin + DHCP + NAT — if CT 150 dies, captive clients lose DHCP *and* internet. | architecture |
| S3 | **No database backup** — losing `portal.db` loses all accounts, profiles and device settings. | ops |
| S4 | Host NIC link flaps on the `igc`/I226-V interface have taken the host off the network before. | hardware |
| S5 | Auth log (`/var/log/captive-auth.log`) grows unbounded — no rotation. | `app/common.py:621` |
| S6 | SQLite without WAL, two writer processes (portal + admin) → `database is locked` under concurrency. | `app/common.py:85` |
| S7 | No health monitoring/alerting beyond `/healthz`; container clock is UTC while the host is HKT. | ops |

## Passed / not applicable

- **No SQL injection** — all `execute()` calls are parameterised; no f-string/`+`/`.format()` in SQL.
- **No `eval`/`exec`/`os.system`/`shell=True`** — `nft` is invoked with argument lists and MACs are regex-validated.
- **No CORS misconfiguration** — no CORS middleware at all.
- **No path traversal** — `/brand/{name}` sanitises and re-checks containment; live probes returned 404/400.
- **No exposed secrets in tracked files** — `.env`, `*.local.md|txt|env`, `portal.db` are gitignored; nothing sensitive tracked.
- **No webhook / payment / AI / cloud-storage surface.**
- Methods limited (OPTIONS/TRACE → 405).

---

## Fix plan (prioritised)

**Now**
1. Fail hard when `SESSION_SECRET` is unset/short (C1).
2. Disable FastAPI docs in production: `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)` (H2).
3. Add a session check to `GET /api/devices` (H3).
4. Add security headers middleware (CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options`, `Referrer-Policy`) (M1).
5. `chmod 600 portal.db` (M2).
6. Fix the memory leak in the portal throttle; reap empty IP entries (M3).
7. Stop echoing upstream errors to the browser (M5).
8. Restrict portal `:3000` to the captive interface in nftables; leave `:80`+`:443` for DNAT only (H6).
9. Fix `.env.example`: `DEMO_BYPASS_MODE=false`, placeholder password (H5).

**Next**
10. TLS for the admin console (C2) — loopback bind + SSH tunnel is the cheapest correct answer.
11. TLS or a credential-free flow for the captive login (C3).
12. JWKS verification + `iss`/`aud`/`exp`/`nonce` (C5); optionally allow-list tenant emails or require a `users` row (H1).
13. Bind the admin session to its IP (M4); add a `state` nonce (M6).
14. Write `requirements.txt` with pinned versions (H4).
15. SQLite WAL + a `portal.db` backup timer (S3, S6).
16. Log rotation for the auth log (S5).

**Structural**
17. Address the MAC trust model with per-device PSK or 802.1X (C4) — this is also the
    foundation for the Profiles & devices feature (BenQ boards, public PCs).
18. Reduce the CT 150 SPOF: watchdog/auto-restart, or split DHCP off the portal host (S2).

> Findings are reported with `file:line`, the affected principal, and the smallest effective
> fix, per the repository's rules of engagement. No source was modified as part of this audit.
