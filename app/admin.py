"""Admin panel for the captive portal: per-device bandwidth limits and access control.

Served on a separate port (default 3001) and restricted to the WAN side
(eth0 / the main LAN) so users on the captive VLAN 50 cannot reach it.

Bandwidth model: one limit value per device, applied to BOTH directions.
A value of 0 (or the "Unlimited" checkbox) removes the limit entirely.
"""
from __future__ import annotations

import html
import ipaddress
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

import common

ENV_PATH = Path("/opt/captive-portal/.env")
COOKIE_NAME = "admin_session"
SESSION_MAX_AGE = 43200  # 12h

# Login throttling: N failures within WINDOW seconds locks the IP for LOCK seconds.
MAX_FAILURES = 5
FAILURE_WINDOW = 300
LOCK_SECONDS = 300


def get_config() -> Dict:
    load_dotenv(ENV_PATH, override=True)
    return {
        "ADMIN_PASSWORD": os.getenv("ADMIN_PASSWORD", ""),
        "SESSION_SECRET": os.getenv("SESSION_SECRET", "default-fallback-secret-change-me"),
        "ADMIN_ALLOW_NET": os.getenv("ADMIN_ALLOW_NET", "192.168.1.0/24"),
        "DEFAULT_BANDWIDTH_KBPS": int(os.getenv("DEFAULT_BANDWIDTH_KBPS", "0") or 0),
    }


# --------------------------------------------------------------------------- #
# Access control (WAN side only)
# --------------------------------------------------------------------------- #
def _allowed_networks() -> List:
    cfg = get_config()
    nets = []
    for part in str(cfg["ADMIN_ALLOW_NET"]).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    # loopback: only reachable from inside the container (e.g. health checks)
    nets.append(ipaddress.ip_network("127.0.0.0/8"))
    nets.append(ipaddress.ip_network("::1/128"))
    return nets


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def enforce_wan_only(request: Request) -> str:
    ip = client_ip(request)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=403, detail="Forbidden")
    for net in _allowed_networks():
        if addr.version == net.version and addr in net:
            return ip
    raise HTTPException(status_code=403, detail="Admin panel is restricted to the WAN side (eth0).")


# --------------------------------------------------------------------------- #
# Login throttling
# --------------------------------------------------------------------------- #
_FAILURES: Dict[str, List[float]] = {}


def _prune(ip: str) -> None:
    now = time.time()
    _FAILURES[ip] = [t for t in _FAILURES.get(ip, []) if now - t < FAILURE_WINDOW]
    if not _FAILURES[ip]:
        _FAILURES.pop(ip, None)


def is_locked_out(ip: str) -> bool:
    _prune(ip)
    return len(_FAILURES.get(ip, [])) >= MAX_FAILURES


def record_failure(ip: str) -> None:
    _prune(ip)
    _FAILURES.setdefault(ip, []).append(time.time())


def clear_failures(ip: str) -> None:
    _FAILURES.pop(ip, None)


# --------------------------------------------------------------------------- #
# Session
# --------------------------------------------------------------------------- #
def session_valid(request: Request) -> bool:
    cfg = get_config()
    token = request.cookies.get(COOKIE_NAME, "")
    data = common.verify_payload(token, cfg["SESSION_SECRET"], SESSION_MAX_AGE)
    return bool(data and data.get("role") == "admin")


def require_session(request: Request) -> None:
    if not session_valid(request):
        raise HTTPException(status_code=303, headers={"Location": "/login"}, detail="Login required")


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def fmt_limit(kbps: int) -> str:
    if not kbps or int(kbps) <= 0:
        return "Unlimited"
    kbps = int(kbps)
    mbps = kbps / 1000
    pretty = f"{mbps:g}" if kbps % 1000 == 0 else f"{mbps:.2f}"
    return f"{kbps} kbps ({pretty} Mbit/s)"


def esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


BASE_CSS = """
:root {
  --bg:#0f172a; --card:#1e293b; --border:#334155; --text:#f8fafc; --muted:#94a3b8;
  --accent:#3b82f6; --accent-hover:#2563eb; --green:#10b981; --red:#ef4444; --amber:#f59e0b;
}
* { box-sizing:border-box; margin:0; padding:0; }
body {
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:radial-gradient(circle at top,#1e293b 0%,#0f172a 100%);
  color:var(--text); min-height:100vh; padding:2rem 1.25rem; line-height:1.5;
}
.wrap { max-width:1080px; margin:0 auto; }
h1 { font-size:1.5rem; letter-spacing:-0.02em; }
h2 { font-size:1.05rem; margin-bottom:1rem; }
.sub { color:var(--muted); font-size:0.875rem; }
.card {
  background:var(--card); border:1px solid var(--border); border-radius:14px;
  padding:1.5rem; margin-bottom:1.25rem; box-shadow:0 10px 30px rgba(0,0,0,0.35);
}
.top { display:flex; justify-content:space-between; align-items:center; gap:1rem; margin-bottom:1.5rem; flex-wrap:wrap; }
.stats { display:flex; gap:0.75rem; flex-wrap:wrap; margin-bottom:1.25rem; }
.stat {
  flex:1 1 150px; background:var(--card); border:1px solid var(--border);
  border-radius:12px; padding:0.9rem 1.1rem;
}
.stat .k { color:var(--muted); font-size:0.75rem; text-transform:uppercase; letter-spacing:0.06em; }
.stat .v { font-size:1.5rem; font-weight:700; margin-top:0.15rem; }
label { display:block; font-size:0.8rem; color:var(--muted); margin-bottom:0.3rem; }
input[type=text], input[type=password], input[type=number] {
  width:100%; padding:0.6rem 0.75rem; border-radius:9px; border:1px solid var(--border);
  background:#0f172a; color:var(--text); font-size:0.9rem;
}
input:focus { outline:2px solid var(--accent); outline-offset:-1px; }
.btn {
  display:inline-flex; align-items:center; justify-content:center; gap:0.4rem;
  padding:0.6rem 1rem; border-radius:9px; border:none; cursor:pointer;
  font-size:0.875rem; font-weight:600; background:var(--accent); color:#fff;
  text-decoration:none; white-space:nowrap;
}
.btn:hover { background:var(--accent-hover); }
.btn-sm { padding:0.4rem 0.7rem; font-size:0.8rem; }
.btn-ghost { background:transparent; border:1px solid var(--border); color:var(--text); }
.btn-ghost:hover { background:#0f172a; }
.btn-green { background:var(--green); } .btn-green:hover { background:#059669; }
.btn-red { background:var(--red); } .btn-red:hover { background:#dc2626; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:1rem; align-items:end; }
table { width:100%; border-collapse:collapse; font-size:0.875rem; }
th {
  text-align:left; color:var(--muted); font-size:0.72rem; text-transform:uppercase;
  letter-spacing:0.06em; padding:0.6rem 0.5rem; border-bottom:1px solid var(--border);
}
td { padding:0.7rem 0.5rem; border-bottom:1px solid rgba(51,65,85,0.5); vertical-align:middle; }
tr:last-child td { border-bottom:none; }
.mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:0.82rem; }
.badge { font-size:0.72rem; padding:0.15rem 0.55rem; border-radius:9999px; font-weight:600; white-space:nowrap; }
.b-ok { background:rgba(16,185,129,0.15); color:#34d399; border:1px solid rgba(16,185,129,0.3); }
.b-no { background:rgba(148,163,184,0.12); color:#94a3b8; border:1px solid rgba(148,163,184,0.25); }
.b-lim { background:rgba(59,130,246,0.15); color:#60a5fa; border:1px solid rgba(59,130,246,0.3); }
.b-unl { background:rgba(245,158,11,0.12); color:#fbbf24; border:1px solid rgba(245,158,11,0.28); }
.rowform { display:flex; gap:0.4rem; align-items:center; flex-wrap:wrap; }
.rowform input[type=number] { width:92px; }
.rowform input[type=text] { width:150px; }
.ck { display:flex; align-items:center; gap:0.35rem; color:var(--muted); font-size:0.78rem; white-space:nowrap; }
.ck input { width:auto; }
.alert { padding:0.7rem 1rem; border-radius:10px; font-size:0.85rem; margin-bottom:1rem; }
.a-ok { background:rgba(16,185,129,0.12); border:1px solid rgba(16,185,129,0.35); color:#6ee7b7; }
.a-err { background:rgba(239,68,68,0.12); border:1px solid rgba(239,68,68,0.35); color:#fca5a5; }
.note { color:var(--muted); font-size:0.78rem; margin-top:0.6rem; }
.actions { display:flex; gap:0.35rem; flex-wrap:wrap; }
.loginbox { max-width:380px; margin:8vh auto 0; }
"""


def page(title: str, body: str, *, warn: str = "", info: str = "") -> str:
    banners = ""
    if info:
        banners += f'<div class="alert a-ok">{esc(info)}</div>'
    if warn:
        banners += f'<div class="alert a-err">{esc(warn)}</div>'
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(title)} | Captive Portal Admin</title>
<style>{BASE_CSS}</style>
</head><body><div class="wrap">{banners}{body}</div></body></html>"""


def render_login(warn: str = "") -> str:
    body = f"""
<div class="loginbox">
  <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:1.25rem">
    <div style="width:42px;height:42px;border-radius:10px;background:linear-gradient(135deg,#3b82f6,#1d4ed8);
                display:flex;align-items:center;justify-content:center;font-weight:700">CP</div>
    <div><h1>Captive Portal Admin</h1><div class="sub">Bandwidth &amp; access control</div></div>
  </div>
  <div class="card">
    <form method="post" action="/login">
      <label for="password">Admin password</label>
      <input type="password" id="password" name="password" autocomplete="current-password" autofocus required>
      <button class="btn" type="submit" style="width:100%;margin-top:1rem">Sign in</button>
    </form>
    <div class="note">Restricted to the WAN side (eth0). Password is set as
      <span class="mono">ADMIN_PASSWORD</span> in <span class="mono">/opt/captive-portal/.env</span>.</div>
  </div>
</div>"""
    return page("Sign in", body, warn=warn)


def render_dashboard(info: str = "", warn: str = "") -> str:
    devices = {d["mac"]: d for d in common.list_devices()}
    authorized = set(common.list_authorized_macs())
    enforced = {mac for mac, _ in common.list_bw_rules()}
    all_macs = sorted(set(devices) | authorized)

    limited = sum(1 for mac in all_macs if int(devices.get(mac, {}).get("limit_kbps") or 0) > 0)
    unlimited = len(all_macs) - limited

    stats = f"""
<div class="stats">
  <div class="stat"><div class="k">Known devices</div><div class="v">{len(all_macs)}</div></div>
  <div class="stat"><div class="k">Authorized now</div><div class="v">{len(authorized)}</div></div>
  <div class="stat"><div class="k">Limited</div><div class="v">{limited}</div></div>
  <div class="stat"><div class="k">Unlimited</div><div class="v">{unlimited}</div></div>
</div>"""

    add_form = """
<div class="card">
  <h2>Add or update a device</h2>
  <form method="post" action="/devices">
    <div class="grid">
      <div><label for="mac">MAC address</label>
        <input type="text" id="mac" name="mac" placeholder="aa:bb:cc:dd:ee:ff" required></div>
      <div><label for="label">Label</label>
        <input type="text" id="label" name="label" placeholder="Student laptop"></div>
      <div><label for="limit_kbps">Download = Upload limit (kbps)</label>
        <input type="number" id="limit_kbps" name="limit_kbps" min="0" step="1" value="0"></div>
      <div><label class="ck" style="margin-bottom:0.6rem">
        <input type="checkbox" name="unlimited" value="1"> Unlimited</label>
        <button class="btn" type="submit" style="width:100%">Save &amp; apply</button></div>
    </div>
  </form>
  <div class="note">The single value is applied to <strong>both</strong> download and upload.
    Tick <em>Unlimited</em> (or set 0) to remove the limit. 1000 kbps = 1 Mbit/s.</div>
</div>"""

    if not all_macs:
        rows = ('<tr><td colspan="5" class="sub" style="padding:1.5rem 0.5rem">'
                'No devices yet. They appear here automatically after a client gets a DHCP lease, '
                'or add one above.</td></tr>')
    else:
        rows = ""
        for mac in all_macs:
            dev = devices.get(mac, {})
            label = dev.get("label", "")
            limit = int(dev.get("limit_kbps") or 0)
            is_auth = mac in authorized
            is_enforced = mac in enforced

            auth_badge = ('<span class="badge b-ok">Authorized</span>' if is_auth
                          else '<span class="badge b-no">Blocked</span>')
            lim_badge = ('<span class="badge b-lim">Limit active</span>' if is_enforced
                         else ('<span class="badge b-unl">Unlimited</span>' if limit <= 0
                               else '<span class="badge b-no">Not applied</span>'))

            auth_action = (f'<form method="post" action="/devices/deauthorize" style="display:inline">'
                           f'<input type="hidden" name="mac" value="{esc(mac)}">'
                           f'<button class="btn btn-sm btn-ghost" type="submit">Revoke</button></form>'
                           if is_auth else
                           f'<form method="post" action="/devices/authorize" style="display:inline">'
                           f'<input type="hidden" name="mac" value="{esc(mac)}">'
                           f'<button class="btn btn-sm btn-green" type="submit">Authorize</button></form>')

            rows += f"""
<tr>
  <td class="mono">{esc(mac)}</td>
  <td>{esc(label) or '<span class="sub">—</span>'}</td>
  <td>{esc(fmt_limit(limit))}<div style="margin-top:0.35rem">{lim_badge}</div></td>
  <td>{auth_badge}</td>
  <td>
    <form method="post" action="/devices" class="rowform">
      <input type="hidden" name="mac" value="{esc(mac)}">
      <input type="text" name="label" value="{esc(label)}" placeholder="Label">
      <input type="number" name="limit_kbps" min="0" step="1" value="{limit}">
      <label class="ck"><input type="checkbox" name="unlimited" value="1"
        {'checked' if limit <= 0 else ''}>Unlim</label>
      <button class="btn btn-sm" type="submit">Apply</button>
    </form>
    <div class="actions" style="margin-top:0.4rem">
      {auth_action}
      <form method="post" action="/devices/delete" style="display:inline">
        <input type="hidden" name="mac" value="{esc(mac)}">
        <button class="btn btn-sm btn-red" type="submit">Delete</button>
      </form>
    </div>
  </td>
</tr>"""

    table = f"""
<div class="card">
  <h2>Devices</h2>
  <div style="overflow-x:auto">
  <table>
    <thead><tr><th>MAC</th><th>Label</th><th>Bandwidth</th><th>Access</th><th>Manage</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  </div>
  <div class="note">"Revoke" removes the device from <span class="mono">authorized_macs</span>
    (it must sign in again). "Delete" also removes the stored label and limit.</div>
</div>"""

    top = """
<div class="top">
  <div><h1>Captive Portal Admin</h1><div class="sub">Per-user bandwidth and access control</div></div>
  <form method="post" action="/logout"><button class="btn btn-ghost" type="submit">Sign out</button></form>
</div>"""

    return page("Dashboard", top + stats + add_form + table, info=info, warn=warn)


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #
app = FastAPI(title="Captive Portal Admin")


@app.on_event("startup")
def _startup() -> None:
    common.db_init()
    # nft rules are volatile: re-apply stored limits whenever the panel starts.
    common.sync_all_limits()


@app.middleware("http")
async def wan_only_middleware(request: Request, call_next):
    try:
        enforce_wan_only(request)
    except HTTPException as exc:
        return JSONResponse(
            {"detail": exc.detail, "hint": "Admin panel is reachable only from the WAN side (eth0)."},
            status_code=exc.status_code,
        )
    return await call_next(request)


@app.get("/healthz")
async def healthz() -> JSONResponse:
    return JSONResponse({"status": "ok", "devices": len(common.list_devices())})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    if session_valid(request):
        return RedirectResponse("/", status_code=303)
    ip = client_ip(request)
    warn = "Too many failed attempts. Try again in a few minutes." if is_locked_out(ip) else ""
    return HTMLResponse(render_login(warn))


@app.post("/login")
async def login_submit(request: Request, password: str = Form("")):
    ip = client_ip(request)
    if is_locked_out(ip):
        return HTMLResponse(render_login("Too many failed attempts. Try again in a few minutes."),
                            status_code=429)

    cfg = get_config()
    if not cfg["ADMIN_PASSWORD"]:
        return HTMLResponse(render_login("No ADMIN_PASSWORD configured in .env"), status_code=500)

    import hmac as _hmac
    if not _hmac.compare_digest(password, cfg["ADMIN_PASSWORD"]):
        record_failure(ip)
        return HTMLResponse(render_login("Incorrect password."), status_code=401)

    clear_failures(ip)
    token = common.sign_payload(
        {"role": "admin", "ip": ip, "ts": int(time.time())}, cfg["SESSION_SECRET"]
    )
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax", max_age=SESSION_MAX_AGE)
    return resp


@app.post("/logout")
async def logout() -> RedirectResponse:
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(COOKIE_NAME)
    return resp


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, msg: str = "", err: str = ""):
    if not session_valid(request):
        return RedirectResponse("/login", status_code=303)
    return HTMLResponse(render_dashboard(info=msg, warn=err))


@app.post("/devices")
async def save_device(
    request: Request,
    mac: str = Form(""),
    label: str = Form(""),
    limit_kbps: str = Form("0"),
    unlimited: Optional[str] = Form(None),
):
    if not session_valid(request):
        return RedirectResponse("/login", status_code=303)

    mac = mac.strip().lower()
    if not common.valid_mac(mac):
        return HTMLResponse(render_dashboard(warn=f"Invalid MAC address: {mac!r}"), status_code=400)

    value = 0 if unlimited else max(0, int(limit_kbps or 0))

    try:
        common.upsert_device(mac, label.strip(), value)
        applied = common.apply_limit(mac, value)
    except Exception as exc:  # noqa: BLE001
        return HTMLResponse(render_dashboard(warn=f"Failed to save {mac}: {exc}"), status_code=500)

    if not applied:
        return HTMLResponse(
            render_dashboard(warn=f"Saved {mac} but nftables did not accept the limit rule."),
            status_code=500,
        )
    return RedirectResponse(
        f"/?msg={esc(f'{mac} set to {fmt_limit(value)}')}", status_code=303
    )


@app.post("/devices/authorize")
async def authorize(mac: str = Form("")):
    mac = mac.strip().lower()
    if not common.valid_mac(mac):
        return RedirectResponse("/?err=Invalid+MAC", status_code=303)
    common.authorize_mac(mac)
    common.log_auth_event("-", mac, "admin", "admin", "ADMIN_MANUAL")
    return RedirectResponse(f"/?msg={esc(f'{mac} authorized')}", status_code=303)


@app.post("/devices/deauthorize")
async def deauthorize(mac: str = Form("")):
    mac = mac.strip().lower()
    if not common.valid_mac(mac):
        return RedirectResponse("/?err=Invalid+MAC", status_code=303)
    common.deauthorize_mac(mac)
    return RedirectResponse(f"/?msg={esc(f'{mac} revoked')}", status_code=303)


@app.post("/devices/delete")
async def delete(mac: str = Form("")):
    mac = mac.strip().lower()
    if not common.valid_mac(mac):
        return RedirectResponse("/?err=Invalid+MAC", status_code=303)
    common.apply_limit(mac, 0)  # remove any rules first
    common.delete_device(mac)
    return RedirectResponse(f"/?msg={esc(f'{mac} deleted')}", status_code=303)


# --------------------------------------------------------------------------- #
# JSON API (same WAN-only restriction)
# --------------------------------------------------------------------------- #
@app.get("/api/devices")
async def api_devices() -> JSONResponse:
    devices = {d["mac"]: d for d in common.list_devices()}
    authorized = set(common.list_authorized_macs())
    enforced = {mac for mac, _ in common.list_bw_rules()}
    out = []
    for mac in sorted(set(devices) | authorized):
        dev = devices.get(mac, {})
        limit = int(dev.get("limit_kbps") or 0)
        out.append({
            "mac": mac,
            "label": dev.get("label", ""),
            "limit_kbps": limit,
            "unlimited": limit <= 0,
            "limit_enforced": mac in enforced,
            "authorized": mac in authorized,
        })
    return JSONResponse({"devices": out})


@app.post("/api/devices/{mac}/limit")
async def api_set_limit(mac: str, limit_kbps: int = Form(0), request: Request = None):  # type: ignore[assignment]
    if not session_valid(request):  # type: ignore[arg-type]
        raise HTTPException(status_code=401, detail="Login required")
    mac = mac.strip().lower()
    if not common.valid_mac(mac):
        raise HTTPException(status_code=400, detail="Invalid MAC address")
    label = (common.get_device(mac) or {}).get("label", "")
    common.upsert_device(mac, label, limit_kbps)
    ok = common.apply_limit(mac, limit_kbps)
    if not ok:
        raise HTTPException(status_code=500, detail="nftables rejected the rule")
    return JSONResponse({"mac": mac, "limit_kbps": max(0, limit_kbps), "applied": True})
