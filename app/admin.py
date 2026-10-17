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
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse

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
        "SESSION_SECRET": common.require_session_secret(os.getenv("SESSION_SECRET")),
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
    if not data or data.get("role") != "admin":
        return False
    # Bind the session to the address that created it, so a stolen cookie is
    # useless from anywhere else.
    bound = data.get("ip")
    return bool(bound) and bound == client_ip(request)


def require_session(request: Request) -> None:
    if not session_valid(request):
        raise HTTPException(status_code=303, headers={"Location": "/login"}, detail="Login required")


def session_subject(request: Request) -> str:
    """Who is signed in: an admin email, or 'bootstrap' for the shared password."""
    cfg = get_config()
    data = common.verify_payload(
        request.cookies.get(COOKIE_NAME, ""), cfg["SESSION_SECRET"], SESSION_MAX_AGE
    )
    return (data or {}).get("sub", "admin")


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


ADMIN_CSS = """
.top{display:flex;justify-content:space-between;align-items:center;gap:1rem;
  flex-wrap:wrap;margin-bottom:1.5rem}
.top h1{font-size:1.5rem;font-weight:700}
.top .sub{margin-top:.15rem;font-size:.875rem;color:rgba(23,32,51,.55)}
.stats{display:flex;gap:.75rem;flex-wrap:wrap;margin-bottom:1.25rem}
.stat{flex:1 1 150px;background:#fff;border:1px solid rgba(23,32,51,.1);
  border-radius:14px;padding:.9rem 1.1rem;box-shadow:var(--shadow-panel)}
.stat .k{font-size:.7rem;font-weight:700;text-transform:uppercase;
  letter-spacing:.12em;color:rgba(23,32,51,.5)}
.stat .v{margin-top:.3rem;font-size:1.5rem;font-weight:700;letter-spacing:-.03em}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));
  gap:1rem;align-items:end}
.section-title{font-size:1.05rem;font-weight:700;margin-bottom:1rem}
.rowform{display:flex;gap:.4rem;align-items:center;flex-wrap:wrap}
.rowform .input{width:auto;min-height:36px;padding:.35rem .6rem;font-size:.8rem;
  border-radius:10px}
.rowform input[type=number]{width:96px}
.rowform input[type=text]{width:150px}
.ck{display:flex;align-items:center;gap:.35rem;font-size:.78rem;
  color:rgba(23,32,51,.6);white-space:nowrap}
.ck input{width:auto}
.actions{display:flex;gap:.35rem;flex-wrap:wrap;margin-top:.45rem}
.loginbox{max-width:380px;margin:7vh auto 0}
.muted{color:rgba(23,32,51,.45)}
.page-head{display:flex;align-items:center;gap:.75rem}
.page-head .mark img{width:76%;height:76%;object-fit:contain;display:block}
.brandmark{display:grid;place-items:center;width:44px;height:44px;border-radius:12px;
  background:#fff;border:1px solid rgba(23,32,51,.1);overflow:hidden;flex-shrink:0}
.brandmark img{width:78%;height:78%;object-fit:contain;display:block}
/* ---- app shell ---- */
.shell{display:flex;gap:1.5rem;align-items:flex-start}
.side{flex:0 0 200px;position:sticky;top:1.5rem;background:#fff;
  border:1px solid rgba(23,32,51,.1);border-radius:14px;padding:1rem;
  box-shadow:var(--shadow-panel)}
.side .brand{display:flex;align-items:center;gap:.6rem;padding-bottom:.9rem;
  margin-bottom:.9rem;border-bottom:1px solid rgba(23,32,51,.08)}
.side .brand .nm{font-weight:700;font-size:.9rem;letter-spacing:-.02em;line-height:1.2}
.side .brand .rl{font-size:.7rem;color:rgba(23,32,51,.5)}
.side nav{display:flex;flex-direction:column;gap:.15rem}
.side nav a{display:block;padding:.5rem .65rem;border-radius:9px;font-size:.875rem;
  font-weight:600;color:rgba(23,32,51,.7);text-decoration:none}
.side nav a:hover{background:var(--paper);color:var(--ink)}
.side nav a.on{background:var(--mint);color:var(--brand-ink)}
.main{flex:1;min-width:0}
@media (max-width:820px){.shell{flex-direction:column}
  .side{position:static;flex:none;width:100%}
  .side nav{flex-direction:row;flex-wrap:wrap}}
.overflow{overflow-x:auto}
.stack-gap{margin-bottom:1.25rem}
"""


def page(title: str, body: str, *, warn: str = "", info: str = "") -> str:
    banners = ""
    if info:
        banners += f'<p class="alert alert-ok" role="status">{esc(info)}</p>'
    if warn:
        banners += f'<p class="alert alert-error" role="alert">{esc(warn)}</p>'
    block = f'<div class="stack-gap">{banners}</div>' if banners else ""
    return common.page_shell(title, block + body, compact_credit=True,
                             extra_css=ADMIN_CSS)


def render_login(warn: str = "") -> str:
    alert = (
        f'<p class="alert alert-error" role="alert" style="margin-bottom:1rem">{esc(warn)}</p>'
        if warn
        else ""
    )
    body = f"""
<div class="loginbox">
  <div class="page-head" style="margin-bottom:1.25rem">
    <span class="brandmark"><img src="/brand/logo.svg" alt=""></span>
    <div>
      <h1>Captive Portal Admin</h1>
      <div class="sub">Bandwidth &amp; access control</div>
    </div>
  </div>
  <div class="card">
    {alert}
    <form method="post" action="/login">
      <label class="label" for="email">Admin email</label>
      <input class="input" type="email" id="email" name="email"
             autocomplete="username" placeholder="you@example.com" autofocus>
      <label class="label" for="password" style="margin-top:.85rem">Password</label>
      <input class="input" type="password" id="password" name="password"
             autocomplete="current-password" required>
      <button class="btn btn-primary btn-block" type="submit" style="margin-top:1rem">Sign in</button>
    </form>
    <p class="note" style="text-align:left">Restricted to the WAN side (eth0).
      Leave the email blank to use the shared bootstrap password
      (<code>ADMIN_PASSWORD</code> in <code>/opt/captive-portal/.env</code>).</p>
  </div>
</div>"""
    return page("Sign in", body)


def render_dashboard(info: str = "", warn: str = "", subject: str = "admin") -> str:
    devices = {d["mac"]: d for d in common.list_devices()}
    authorized = set(common.list_authorized_macs())
    enforced = {mac for mac, _ in common.list_bw_rules()}
    all_macs = sorted(set(devices) | authorized)

    limited = sum(1 for m in all_macs if int(devices.get(m, {}).get("limit_kbps") or 0) > 0)
    unlimited = len(all_macs) - limited

    stats = f"""
<div class="stats">
  <div class="stat"><div class="k">Known devices</div><div class="v">{len(all_macs)}</div></div>
  <div class="stat"><div class="k">Authorized now</div><div class="v">{len(authorized)}</div></div>
  <div class="stat"><div class="k">Limited</div><div class="v">{limited}</div></div>
  <div class="stat"><div class="k">Unlimited</div><div class="v">{unlimited}</div></div>
</div>"""

    add_form = """
<div class="card" style="margin-bottom:1.25rem">
  <h2 class="section-title">Add or update a device</h2>
  <form method="post" action="/devices">
    <div class="grid">
      <div>
        <label class="label" for="mac">MAC address</label>
        <input class="input" type="text" id="mac" name="mac" placeholder="aa:bb:cc:dd:ee:ff" required>
      </div>
      <div>
        <label class="label" for="label">Label</label>
        <input class="input" type="text" id="label" name="label" placeholder="Student laptop">
      </div>
      <div>
        <label class="label" for="limit_kbps">Download = Upload (kbps)</label>
        <input class="input" type="number" id="limit_kbps" name="limit_kbps" min="0" step="1" value="0">
      </div>
      <div>
        <label class="ck" style="margin-bottom:.6rem">
          <input type="checkbox" name="unlimited" value="1"> Unlimited
        </label>
        <button class="btn btn-primary btn-block" type="submit">Save &amp; apply</button>
      </div>
    </div>
  </form>
  <p class="note" style="text-align:left">The single value applies to <strong>both</strong> download
    and upload. Tick <em>Unlimited</em> (or set 0) to remove the limit. 1000 kbps = 1 Mbit/s.</p>
</div>"""

    users = common.list_users()
    if users:
        parts = []
        for u in users:
            role_badge = ('<span class="badge badge-green">admin</span>'
                          if u.get("role") == "admin"
                          else '<span class="badge badge-default">wifi</span>')
            parts.append(
                f'<tr><td class="mono">{esc(u["email"])}</td>'
                f'<td>{esc(u.get("label") or "")}</td>'
                f'<td>{role_badge}</td>'
                f'<td>{esc(u.get("last_login_at") or "&mdash;")}</td>'
                f'<td><form method="post" action="/users/delete" style="display:inline">'
                f'<input type="hidden" name="email" value="{esc(u["email"])}">'
                f'<button class="btn btn-danger btn-sm" type="submit">Delete</button></form></td></tr>'
            )
        urows = "".join(parts)
    else:
        urows = ('<tr><td colspan="5" class="muted" style="padding:1.25rem .5rem">'
                 'No accounts yet. Sign-in is impossible until you add one.</td></tr>')

    users_card = f"""
<div class="card" style="margin-bottom:1.25rem">
  <h2 class="section-title">Wi-Fi accounts</h2>
  <form method="post" action="/users">
    <div class="grid">
      <div><label class="label" for="u-email">Email</label>
        <input class="input" type="email" id="u-email" name="email" placeholder="you@example.com" required></div>
      <div><label class="label" for="u-label">Label</label>
        <input class="input" type="text" id="u-label" name="label" placeholder="Ms Chan"></div>
      <div><label class="label" for="u-pass">Password (min 8)</label>
        <input class="input" type="text" id="u-pass" name="password" autocomplete="new-password" required></div>
      <div><label class="label" for="u-role">Role</label>
        <select class="input" id="u-role" name="role">
          <option value="wifi">Wi-Fi user</option>
          <option value="admin">Console admin</option>
        </select></div>
      <div><button class="btn btn-primary btn-block" type="submit">Save account</button></div>
    </div>
  </form>
  <p class="note" style="text-align:left">Saving an email that already exists resets its
    password and role. Wi-Fi users sign in to the captive portal; console admins sign in here.</p>
  <div class="overflow" style="margin-top:1rem">
    <table>
      <thead><tr><th>Email</th><th>Label</th><th>Role</th><th>Last sign-in</th><th></th></tr></thead>
      <tbody>{urows}</tbody>
    </table>
  </div>
</div>"""

    if not all_macs:
        rows = ('<tr><td colspan="7" class="muted" style="padding:1.5rem .5rem">'
                'No devices yet. They appear here once a client takes a DHCP lease, '
                'or add one above.</td></tr>')
    else:
        rows = ""
        for mac in all_macs:
            dev = devices.get(mac, {})
            label = dev.get("label", "")
            limit = int(dev.get("limit_kbps") or 0)
            is_auth = mac in authorized
            is_enforced = mac in enforced
            sess = common.session_summary(mac)

            auth_badge = ('<span class="badge badge-green">Authorized</span>' if is_auth
                          else '<span class="badge badge-default">Blocked</span>')
            if is_enforced:
                lim_badge = '<span class="badge badge-green">Limit active</span>'
            elif limit <= 0:
                lim_badge = '<span class="badge badge-orange">Unlimited</span>'
            else:
                lim_badge = '<span class="badge badge-default">Not applied</span>'

            auth_action = (
                f'<form method="post" action="/devices/deauthorize" style="display:inline">'
                f'<input type="hidden" name="mac" value="{esc(mac)}">'
                f'<button class="btn btn-ghost btn-sm" type="submit">Revoke</button></form>'
                if is_auth else
                f'<form method="post" action="/devices/authorize" style="display:inline">'
                f'<input type="hidden" name="mac" value="{esc(mac)}">'
                f'<button class="btn btn-primary btn-sm" type="submit">Authorize</button></form>'
            )

            rows += f"""
<tr>
  <td class="mono">{esc(mac)}</td>
  <td>{esc(label) or '<span class="muted">&mdash;</span>'}</td>
  <td>{esc(fmt_limit(limit))}<div style="margin-top:.35rem">{lim_badge}</div></td>
  <td>{esc(sess["connected_human"]) if sess["active"] else '<span class="muted">&mdash;</span>'}</td>
  <td>{esc(sess["bytes_human"]) if sess["active"] else '<span class="muted">&mdash;</span>'}</td>
  <td>{auth_badge}</td>
  <td>
    <form method="post" action="/devices" class="rowform">
      <input type="hidden" name="mac" value="{esc(mac)}">
      <input class="input" type="text" name="label" value="{esc(label)}" placeholder="Label">
      <input class="input" type="number" name="limit_kbps" min="0" step="1" value="{limit}">
      <label class="ck"><input type="checkbox" name="unlimited" value="1" {'checked' if limit <= 0 else ''}>Unlim</label>
      <button class="btn btn-secondary btn-sm" type="submit">Apply</button>
    </form>
    <div class="actions">
      {auth_action}
      <form method="post" action="/devices/delete" style="display:inline">
        <input type="hidden" name="mac" value="{esc(mac)}">
        <button class="btn btn-danger btn-sm" type="submit">Delete</button>
      </form>
    </div>
  </td>
</tr>"""

    table = f"""
<div class="card">
  <h2 class="section-title">Devices</h2>
  <div class="overflow">
    <table>
      <thead><tr><th>MAC</th><th>Label</th><th>Bandwidth</th><th>Connected</th><th>Used</th><th>Access</th><th>Manage</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <p class="note" style="text-align:left">"Revoke" removes the device from
    <span class="mono">authorized_macs</span> (it must sign in again). "Delete" also removes the
    stored label and limit.</p>
</div>"""

    top = f"""
<div class="top">
  <div class="page-head">
    <span class="brandmark"><img src="/brand/logo.svg" alt=""></span>
    <div>
      <h1>Captive Portal Admin</h1>
      <div class="sub">Example Secondary School</div>
    </div>
  </div>
  <div style="display:flex;align-items:center;gap:.75rem">
    <div style="text-align:right">
      <div style="font-size:.8rem;font-weight:600">{esc(subject)}</div>
      <div style="font-size:.7rem;color:rgba(23,32,51,.5)">signed in</div>
    </div>
    <form method="post" action="/logout">
      <button class="btn btn-secondary btn-sm" type="submit">Sign out</button>
    </form>
  </div>
</div>"""

    shell = f"""
<div class="shell">
  <aside class="side">
    <div class="brand">
      <span class="brandmark"><img src="/brand/logo.svg" alt=""></span>
      <div><div class="nm">Captive Portal</div><div class="rl">Admin console</div></div>
    </div>
    <nav>
      <a href="#overview" class="on">Overview</a>
      <a href="#add">Add device</a>
      <a href="#users">Accounts</a>
      <a href="#devices">Devices</a>
      <a href="/profiles">Profiles &amp; devices</a>
    </nav>
  </aside>
  <div class="main">
    {top}
    <div id="overview">{stats}</div>
    <div id="add">{add_form}</div>
    <div id="users">{users_card}</div>
    <div id="devices">{table}</div>
  </div>
</div>"""

    return page("Dashboard", shell, info=info, warn=warn)


def render_profiles_page(info: str = "", warn: str = "", subject: str = "admin") -> str:
    profiles = common.list_profiles()
    devices = common.list_devices()
    authorized = set(common.list_authorized_macs())

    form = f"""
<div class="card" style="margin-bottom:1.25rem">
  <h2 class="section-title">Create or update a profile</h2>
  <form method="post" action="/profiles">
    <div class="grid">
      <div><label class="label" for="p-name">Name</label>
        <input class="input" type="text" id="p-name" name="name" placeholder="BenQ Whiteboard" required></div>
      <div><label class="label" for="p-bw">Bandwidth (kbps, 0 = unlimited)</label>
        <input class="input" type="number" id="p-bw" name="bandwidth_kbps" min="0" step="1" value="0"></div>
      <div><label class="label" for="p-hours">Session hours</label>
        <input class="input" type="number" id="p-hours" name="session_hours" min="1" step="1" value="8"></div>
      <div><label class="label" for="p-auth">Identity</label>
        <select class="input" id="p-auth" name="auth_method">
          <option value="mac">MAC (pre-registered)</option>
          <option value="psk">Per-device PSK</option>
          <option value="cert">802.1X certificate</option>
          <option value="sso">User sign-in (Entra)</option>
        </select></div>
      <div><label class="label" for="p-desc">Description</label>
        <input class="input" type="text" id="p-desc" name="description" placeholder="Fixed displays in classrooms"></div>
      <div>
        <label class="ck" style="margin-bottom:.6rem">
          <input type="checkbox" name="auto_authorize" value="1"> Auto-authorize (no sign-in)
        </label>
        <button class="btn btn-primary btn-block" type="submit">Save profile</button>
      </div>
    </div>
  </form>
  <p class="note" style="text-align:left">Identical names update in place. <strong>Auto-authorize</strong>
    keeps the device online with no browser sign-in — intended for fixed kit like whiteboards.</p>
</div>"""

    if profiles:
        prows = []
        for p in profiles:
            count = len(common.devices_for_profile(p["id"]))
            access = ('<span class="badge badge-green">Auto</span>'
                      if int(p["auto_authorize"] or 0)
                      else '<span class="badge badge-default">Sign-in</span>')
            prows.append(
                f'<tr><td><strong>{esc(p["name"])}</strong>'
                f'<div class="muted" style="font-size:.78rem">{esc(p["description"] or "")}</div></td>'
                f'<td>{esc(fmt_limit(int(p["bandwidth_kbps"] or 0)))}</td>'
                f'<td>{access}</td>'
                f'<td>{int(p["session_hours"] or 8)}h</td>'
                f'<td class="mono">{esc(p["auth_method"])}</td>'
                f'<td>{count}</td>'
                f'<td><form method="post" action="/profiles/delete" style="display:inline">'
                f'<input type="hidden" name="profile_id" value="{p["id"]}">'
                f'<button class="btn btn-danger btn-sm" type="submit">Delete</button></form></td></tr>'
            )
        ptable = "".join(prows)
    else:
        ptable = ('<tr><td colspan="7" class="muted" style="padding:1.25rem .5rem">'
                  'No profiles yet. Create one above &mdash; e.g. "BenQ Whiteboard".</td></tr>')

    if devices:
        drows = []
        for d in devices:
            mac = d["mac"]
            badge = ('<span class="badge badge-green">Authorized</span>' if mac in authorized
                     else '<span class="badge badge-default">Blocked</span>')
            opts = ""
            for p in profiles:
                mark = " selected" if d.get("profile_id") == p["id"] else ""
                opts += f'<option value="{p["id"]}"{mark}>{esc(p["name"])}</option>'
            drows.append(
                f'<tr><td class="mono">{esc(mac)}</td>'
                f'<td>{esc(d.get("label") or "")}</td>'
                f'<td>{esc(d.get("profile_name") or "&mdash;")}</td>'
                f'<td>{badge}</td>'
                f'<td><form method="post" action="/devices/profile" class="rowform">'
                f'<input type="hidden" name="mac" value="{esc(mac)}">'
                f'<select class="input" name="profile_id">'
                f'<option value="">&mdash; none &mdash;</option>{opts}</select>'
                f'<button class="btn btn-secondary btn-sm" type="submit">Assign</button>'
                f'</form></td></tr>'
            )
        dtable = "".join(drows)
    else:
        dtable = ('<tr><td colspan="5" class="muted" style="padding:1.25rem .5rem">'
                  'No devices known yet. They appear once a client takes a DHCP lease, '
                  'or add one on the dashboard.</td></tr>')

    top = f"""
<div class="top">
  <div class="page-head">
    <span class="brandmark"><img src="/brand/logo.svg" alt=""></span>
    <div>
      <h1>Profiles &amp; devices</h1>
      <div class="sub">Provision fixed kit &mdash; whiteboards, public PCs</div>
    </div>
  </div>
  <div style="display:flex;align-items:center;gap:.75rem">
    <div style="text-align:right">
      <div style="font-size:.8rem;font-weight:600">{esc(subject)}</div>
      <div style="font-size:.7rem;color:rgba(23,32,51,.5)">signed in</div>
    </div>
    <form method="post" action="/logout">
      <button class="btn btn-secondary btn-sm" type="submit">Sign out</button>
    </form>
  </div>
</div>"""

    shell = f"""
<div class="shell">
  <aside class="side">
    <div class="brand">
      <span class="brandmark"><img src="/brand/logo.svg" alt=""></span>
      <div><div class="nm">Captive Portal</div><div class="rl">Admin console</div></div>
    </div>
    <nav>
      <a href="/">Overview</a>
      <a href="/profiles" class="on">Profiles &amp; devices</a>
    </nav>
  </aside>
  <div class="main">
    {top}
    {form}
    <div class="card" style="margin-bottom:1.25rem">
      <h2 class="section-title">Profiles</h2>
      <div class="overflow">
        <table>
          <thead><tr><th>Name</th><th>Bandwidth</th><th>Access</th><th>Session</th><th>Identity</th><th>Devices</th><th></th></tr></thead>
          <tbody>{ptable}</tbody>
        </table>
      </div>
    </div>
    <div class="card">
      <h2 class="section-title">Devices</h2>
      <div class="overflow">
        <table>
          <thead><tr><th>MAC</th><th>Label</th><th>Profile</th><th>Access</th><th>Assign</th></tr></thead>
          <tbody>{dtable}</tbody>
        </table>
      </div>
      <p class="note" style="text-align:left">Devices in an <em>Auto</em> profile are kept
        authorized by <span class="mono">captive-device-sync</span> and need no sign-in.</p>
    </div>
  </div>
</div>"""

    return page("Profiles", shell, info=info, warn=warn)


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #
app = FastAPI(
    title="Captive Portal Admin",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'self'"
    ),
}


@app.on_event("startup")
def _startup() -> None:
    get_config()  # raises if SESSION_SECRET is missing or weak (fail closed)
    common.db_init()
    # nft rules are volatile: re-apply stored limits whenever the panel starts.
    common.sync_all_limits()
    # Re-assert access for profile-managed fixed devices (whiteboards, public PCs).
    common.sync_static_authorizations()


@app.middleware("http")
async def wan_only_middleware(request: Request, call_next):
    try:
        enforce_wan_only(request)
    except HTTPException as exc:
        response = JSONResponse(
            {"detail": exc.detail, "hint": "Admin panel is reachable only from the WAN side (eth0)."},
            status_code=exc.status_code,
        )
    else:
        response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response


@app.get("/brand/{name}")
async def brand_asset(name: str):
    path = common.brand_file(name)
    if path is None:
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(path, media_type=common.brand_media_type(name))


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
async def login_submit(request: Request, password: str = Form(""), email: str = Form("")):
    ip = client_ip(request)
    if is_locked_out(ip):
        return HTMLResponse(render_login("Too many failed attempts. Try again in a few minutes."),
                            status_code=429)

    cfg = get_config()
    email = common.normalise_email(email)

    if email:
        # Named admin account.
        user = common.verify_admin(email, password)
        if not user:
            record_failure(ip)
            return HTMLResponse(render_login("Incorrect email or password."), status_code=401)
        identity = user["email"]
    else:
        # Shared bootstrap password (also the way in before any admin exists).
        import hmac as _hmac
        if not cfg["ADMIN_PASSWORD"]:
            return HTMLResponse(render_login("No ADMIN_PASSWORD configured in .env"), status_code=500)
        if not _hmac.compare_digest(password, cfg["ADMIN_PASSWORD"]):
            record_failure(ip)
            return HTMLResponse(render_login("Incorrect password."), status_code=401)
        identity = "bootstrap"

    clear_failures(ip)
    token = common.sign_payload(
        {"role": "admin", "sub": identity, "ip": ip, "ts": int(time.time())},
        cfg["SESSION_SECRET"],
    )
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="strict",
                    secure=True, max_age=SESSION_MAX_AGE)
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
    return HTMLResponse(render_dashboard(info=msg, warn=err, subject=session_subject(request)))


@app.get("/profiles", response_class=HTMLResponse)
async def profiles_page(request: Request, msg: str = "", err: str = ""):
    if not session_valid(request):
        return RedirectResponse("/login", status_code=303)
    return HTMLResponse(render_profiles_page(info=msg, warn=err, subject=session_subject(request)))


@app.post("/profiles")
async def save_profile(request: Request, name: str = Form(""), description: str = Form(""),
                       bandwidth_kbps: int = Form(0), session_hours: int = Form(8),
                       auth_method: str = Form("mac"), auto_authorize: str = Form("")):
    if not session_valid(request):
        return RedirectResponse("/login", status_code=303)
    try:
        prof = common.upsert_profile(name, description.strip(), bandwidth_kbps,
                                     bool(auto_authorize), session_hours, auth_method)
    except ValueError as exc:
        return RedirectResponse(f"/profiles?err={esc(str(exc))}", status_code=303)
    kept = common.sync_static_authorizations()
    msg = f"Saved profile {prof['name']} — {kept} device(s) kept online"
    return RedirectResponse(f"/profiles?msg={esc(msg)}", status_code=303)


@app.post("/profiles/delete")
async def delete_profile_route(request: Request, profile_id: str = Form("")):
    if not session_valid(request):
        return RedirectResponse("/login", status_code=303)
    for mac in common.devices_for_profile(profile_id):
        common.deauthorize_mac(mac)
    common.delete_profile(profile_id)
    return RedirectResponse("/profiles?msg=Profile deleted", status_code=303)


@app.post("/devices/profile")
async def assign_profile(request: Request, mac: str = Form(""), profile_id: str = Form("")):
    if not session_valid(request):
        return RedirectResponse("/login", status_code=303)
    try:
        if not common.get_device(mac):
            common.upsert_device(mac, "", 0)
        common.assign_device_profile(mac, profile_id)
        common.sync_static_authorizations()
    except ValueError as exc:
        return RedirectResponse(f"/profiles?err={esc(str(exc))}", status_code=303)
    return RedirectResponse("/profiles?msg=Profile assigned", status_code=303)


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
@app.post("/users")
async def save_user(request: Request, email: str = Form(""), password: str = Form(""),
                    label: str = Form(""), role: str = Form("wifi")):
    if not session_valid(request):
        return RedirectResponse("/login", status_code=303)
    try:
        common.create_user(email, password, label.strip(), role if role in ("wifi", "admin") else "wifi")
    except ValueError as exc:
        return HTMLResponse(render_dashboard(warn=f"User not saved: {exc}"), status_code=400)
    return RedirectResponse(f"/?msg={esc(f'{common.normalise_email(email)} saved')}", status_code=303)


@app.post("/users/delete")
async def delete_user_route(request: Request, email: str = Form("")):
    if not session_valid(request):
        return RedirectResponse("/login", status_code=303)
    common.delete_user(email)
    return RedirectResponse(f"/?msg={esc(f'{common.normalise_email(email)} deleted')}", status_code=303)


@app.get("/api/devices")
async def api_devices(request: Request) -> JSONResponse:
    if not session_valid(request):
        raise HTTPException(status_code=401, detail="Login required")
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
