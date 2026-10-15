import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import re
import subprocess
import time
import urllib.parse
from pathlib import Path
from typing import Optional, Tuple

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse

import common

ENV_PATH = Path("/opt/captive-portal/.env")
LOG_PATH = Path("/var/log/captive-auth.log")

app = FastAPI(title="Captive Portal - Microsoft Entra ID (OAuth2)")

# Simple in-memory brute-force throttle for the local email/password form.
_LOGIN_FAILURES: dict = {}
MAX_LOGIN_FAILURES = 6
LOGIN_FAILURE_WINDOW = 300


def _login_locked(ip: str) -> bool:
    now = time.time()
    fails = [t for t in _LOGIN_FAILURES.get(ip, []) if now - t < LOGIN_FAILURE_WINDOW]
    _LOGIN_FAILURES[ip] = fails
    return len(fails) >= MAX_LOGIN_FAILURES


def _login_record_failure(ip: str) -> None:
    _LOGIN_FAILURES.setdefault(ip, []).append(time.time())


def get_config() -> dict:
    load_dotenv(ENV_PATH, override=True)
    return {
        "AZURE_CLIENT_ID": os.getenv("AZURE_CLIENT_ID", ""),
        "AZURE_TENANT_ID": os.getenv("AZURE_TENANT_ID", ""),
        "AZURE_CLIENT_SECRET": os.getenv("AZURE_CLIENT_SECRET", ""),
        "REDIRECT_URI": os.getenv("REDIRECT_URI", "http://localhost:3000/auth/callback"),
        "SESSION_SECRET": os.getenv("SESSION_SECRET", "default-fallback-secret-change-me"),
    }


MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")

# The captive segment served by CT 150 on eth1.
CAPTIVE_NET = ipaddress.ip_network("10.50.0.0/24")


def on_captive_segment(ip: str) -> bool:
    """True only for addresses on the captive VLAN.

    Requests arriving via the Cloudflare tunnel come from the cloudflared
    container, so they are never on the captive segment and the device MAC
    cannot be resolved for them.
    """
    try:
        return ipaddress.ip_address(ip) in CAPTIVE_NET
    except ValueError:
        return False


def get_client_mac(ip: str) -> Optional[str]:
    if not ip:
        return None
    if ip in ("127.0.0.1", "::1", "10.50.0.1"):
        try:
            iface_mac = Path("/sys/class/net/eth1/address").read_text().strip().lower()
            if MAC_RE.match(iface_mac):
                return iface_mac
        except Exception:
            pass

    # 1. Check /proc/net/arp
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3].lower()
                    if mac != "00:00:00:00:00:00" and MAC_RE.match(mac):
                        return mac
    except Exception:
        pass

    # 2. Check ip neigh show dev eth1
    try:
        res = subprocess.run(
            ["ip", "neigh", "show", "dev", "eth1"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == ip and "lladdr" in parts:
                idx = parts.index("lladdr")
                if idx + 1 < len(parts):
                    mac = parts[idx + 1].lower()
                    if MAC_RE.match(mac):
                        return mac
    except Exception:
        pass

    return None


def is_mac_authorized(mac: Optional[str]) -> bool:
    if not mac or not MAC_RE.match(mac):
        return False
    try:
        res = subprocess.run(
            ["nft", "list", "set", "inet", "captive", "authorized_macs"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return mac.lower() in res.stdout.lower()
    except Exception:
        return False


def authorize_mac(mac: str) -> bool:
    mac = mac.lower()
    if not MAC_RE.match(mac):
        raise ValueError(f"Invalid MAC address: {mac}")
    res = subprocess.run(
        [
            "nft",
            "add",
            "element",
            "inet",
            "captive",
            "authorized_macs",
            f"{{ {mac} timeout 8h }}",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return res.returncode == 0


def log_auth_event(ip: str, mac: str, username: str, name: str, method: str) -> None:
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    entry = f"{ts} | method={method} | ip={ip} | mac={mac} | user={username} | name={name}\n"
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(entry)
    except Exception:
        pass


def sign_state(ip: str, mac: str, secret: str) -> str:
    payload = json.dumps({"ip": ip, "mac": mac, "ts": int(time.time())}, separators=(",", ":"))
    b64_payload = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("utf-8").rstrip("=")
    sig = hmac.new(secret.encode("utf-8"), b64_payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{b64_payload}.{sig}"


def verify_state(state: str, secret: str) -> Tuple[str, str]:
    if "." not in state:
        raise ValueError("Malformed state parameter")
    b64_payload, sig = state.rsplit(".", 1)
    expected_sig = hmac.new(secret.encode("utf-8"), b64_payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        raise ValueError("Invalid state signature")
    padding = "=" * (-len(b64_payload) % 4)
    data = json.loads(base64.urlsafe_b64decode(b64_payload + padding).decode("utf-8"))
    if int(time.time()) - int(data.get("ts", 0)) > 3600:
        raise ValueError("State parameter expired")
    return data.get("ip", ""), data.get("mac", "")


def decode_jwt_claims(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload_b64 + padding)
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}


def render_login_html(ip: str, mac: str, authorized: bool = False, error: str = "") -> str:
    e = common.esc
    captive = on_captive_segment(ip)

    if captive:
        net_label = "Captive segment (10.50.0.0/24)"
        tunnel_note = ""
    else:
        net_label = "External (via Cloudflare tunnel)"
        tunnel_note = (
            '<p class="alert alert-error" role="alert" style="margin-top:1rem">'
            'You are on the public hostname, not the captive Wi-Fi. Your device '
            'cannot be identified from here, so signing in will not authorize your '
            'phone or laptop. Connect to the <em>Casper-SSO</em> network and retry.</p>'
        )
    status_badge = (
        '<span class="badge badge-green">Authorized &middot; 8h active</span>'
        if authorized
        else '<span class="badge badge-orange">Authentication required</span>'
    )
    error_box = (
        f'<p class="alert alert-error" role="alert" style="margin-top:1rem">{e(error)}</p>'
        if error
        else ""
    )

    session_block = ""
    if authorized:
        sess = common.session_summary(mac)
        session_block = f"""
        <div class="detail-panel">
          <div class="detail-row">
            <span class="detail-label">Connected for</span>
            <span class="detail-value">{e(sess["connected_human"])}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Data used</span>
            <span class="detail-value">{e(sess["bytes_human"])}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Down / Up</span>
            <span class="detail-value">{e(sess["down_human"])} / {e(sess["up_human"])}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Session ends in</span>
            <span class="detail-value">{e(sess["remaining_human"])}</span>
          </div>
        </div>"""

    body = f"""
<div class="auth">
  <aside class="auth-aside">
    <div class="glow glow-1" aria-hidden="true"></div>
    <div class="glow glow-2" aria-hidden="true"></div>
    <div class="auth-aside-inner">
      <span class="crest"><img src="/brand/logo.svg" alt="School crest"></span>
      <h1>Campus Wi-Fi</h1>
      <p class="sub">Example Secondary School<br>
        <span class="zh">示例中學</span></p>
      <p class="accent">Sign in with your school account to get online</p>
    </div>
  </aside>
  <div class="auth-main">
    <main>
      <div class="auth-brand-mobile">
        <div class="row">
          <span class="crest-sm"><img src="/brand/logo.svg" alt=""></span>
          <h1>Campus Wi-Fi</h1>
        </div>
        <p class="event">Example Secondary School</p>
      </div>
      <div class="card auth-card">
        <h2>Sign in</h2>
        {error_box}
        <div class="detail-panel">
          <div class="detail-row">
            <span class="detail-label">Status</span>{status_badge}
          </div>
          <div class="detail-row">
            <span class="detail-label">Client IP</span>
            <span class="detail-value">{e(ip)}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Device MAC</span>
            <span class="detail-value">{e(mac)}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Network</span>
            <span class="detail-value">{e(net_label)}</span>
          </div>
        </div>
        {tunnel_note}
        <form method="post" action="/login" style="margin-top:1.25rem">
          <label class="label" for="email">School email</label>
          <input class="input" type="email" id="email" name="email"
                 autocomplete="username" placeholder="you@example.com" required>
          <label class="label" for="password" style="margin-top:.85rem">Password</label>
          <input class="input" type="password" id="password" name="password"
                 autocomplete="current-password" required>
          <button class="btn btn-primary btn-block" type="submit" style="margin-top:1rem">Sign in</button>
        </form>
        <div class="divider"><span>or</span></div>
        <a href="/auth/login" class="btn btn-secondary btn-block">
          {common.microsoft_mark()}
          Sign in with Microsoft
        </a>
        {session_block}
      </div>
    </main>
    {common.credit_html()}
  </div>
</div>"""
    return common.page_shell("Sign in", body, wrap=False, credit=False)


def render_welcome_html(name: str, username: str, ip: str, mac: str, method: str) -> str:
    e = common.esc
    sess = common.session_summary(mac)
    body = f"""
<div class="auth">
  <aside class="auth-aside">
    <div class="glow glow-1" aria-hidden="true"></div>
    <div class="glow glow-2" aria-hidden="true"></div>
    <div class="auth-aside-inner">
      <span class="crest">SSO</span>
      <h1>Campus Wi-Fi</h1>
      <p class="sub">You are online. This device stays authorised for the next eight hours.</p>
      <p class="accent">Microsoft Entra ID &middot; single sign-on</p>
    </div>
  </aside>
  <div class="auth-main">
    <main>
      <div class="auth-brand-mobile">
        <div class="row">
          <span class="crest-sm">SSO</span>
          <h1>Campus Wi-Fi</h1>
        </div>
        <p class="event">Connected</p>
      </div>
      <div class="card auth-card done">
        <span class="done-icon" aria-hidden="true">&#10003;</span>
        <h2>Welcome, {e(name)}</h2>
        <p class="lede">Your device is now authorised for internet access for the next 8 hours.</p>
        <div class="detail-panel" style="width:100%;text-align:left">
          <div class="detail-row">
            <span class="detail-label">Account</span>
            <span class="detail-value">{e(username)}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Auth method</span>
            <span class="detail-value">{e(method)}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Client IP</span>
            <span class="detail-value">{e(ip)}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Device MAC</span>
            <span class="detail-value">{e(mac)}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Session lease</span>
            <span class="detail-value">8 hours</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Connected for</span>
            <span class="detail-value">{e(sess["connected_human"])}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Data used</span>
            <span class="detail-value">{e(sess["bytes_human"])}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Down / Up</span>
            <span class="detail-value">{e(sess["down_human"])} / {e(sess["up_human"])}</span>
          </div>
        </div>
      </div>
    </main>
    {common.credit_html()}
  </div>
</div>"""
    return common.page_shell("Connected", body, wrap=False, credit=False)


@app.get("/brand/{name}")
async def brand_asset(name: str):
    path = common.brand_file(name)
    if path is None:
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(path, media_type=common.brand_media_type(name))


@app.get("/api/capport")
async def capport_api(request: Request):
    client_ip = request.client.host if request.client else ""
    mac = get_client_mac(client_ip)
    if is_mac_authorized(mac):
        return JSONResponse({"captive": False})
    return JSONResponse({
        "captive": True,
        "user-portal-url": "http://10.50.0.1:3000/login",
    })


@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
@app.get("/generate_204", response_class=HTMLResponse)
@app.get("/hotspot-detect.html", response_class=HTMLResponse)
@app.get("/connecttest.txt", response_class=HTMLResponse)
@app.get("/ncsi.txt", response_class=HTMLResponse)
async def portal_login_page(request: Request, error: str = ""):
    cfg = get_config()
    client_ip = request.client.host if request.client else "unknown"
    mac = get_client_mac(client_ip) or "00:00:00:00:00:00"
    authorized = is_mac_authorized(mac)
    html = render_login_html(
        ip=client_ip,
        mac=mac,
        authorized=authorized,
        error=error,
    )
    return HTMLResponse(content=html, status_code=200)


@app.post("/login", response_class=HTMLResponse)
async def portal_login_submit(request: Request, email: str = Form(""), password: str = Form("")):
    client_ip = request.client.host if request.client else "unknown"
    mac = get_client_mac(client_ip) or "00:00:00:00:00:00"

    if _login_locked(client_ip):
        return HTMLResponse(
            render_login_html(
                ip=client_ip, mac=mac,
                error="Too many failed attempts. Try again in a few minutes.",
            ),
            status_code=429,
        )

    user = common.verify_user(email, password)
    if not user:
        _login_record_failure(client_ip)
        return HTMLResponse(
            render_login_html(ip=client_ip, mac=mac, error="Incorrect email or password."),
            status_code=401,
        )

    if not common.valid_mac(mac) or mac == "00:00:00:00:00:00":
        raise HTTPException(status_code=400, detail=f"Cannot authorize invalid MAC address: {mac}")

    if not authorize_mac(mac):
        raise HTTPException(status_code=500, detail="Failed to add MAC to nftables authorized_macs set.")

    log_auth_event(client_ip, mac, user["email"], user.get("label") or user["email"], "LOCAL_PASSWORD")
    return HTMLResponse(
        render_welcome_html(
            name=user.get("label") or user["email"],
            username=user["email"],
            ip=client_ip,
            mac=mac,
            method="Email and password",
        )
    )


@app.get("/auth/login")
async def auth_login(request: Request):
    cfg = get_config()
    client_ip = request.client.host if request.client else "unknown"
    mac = get_client_mac(client_ip) or "00:00:00:00:00:00"

    state = sign_state(client_ip, mac, cfg["SESSION_SECRET"])
    tenant_id = cfg["AZURE_TENANT_ID"] or "common"
    params = {
        "client_id": cfg["AZURE_CLIENT_ID"],
        "response_type": "code",
        "redirect_uri": cfg["REDIRECT_URI"],
        "response_mode": "query",
        "scope": "openid profile email",
        "state": state,
    }
    auth_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url=auth_url, status_code=302)


@app.get("/auth/callback", response_class=HTMLResponse)
async def auth_callback(
    request: Request,
    code: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    error: Optional[str] = Query(default=None),
    error_description: Optional[str] = Query(default=None),
):
    cfg = get_config()
    req_ip = request.client.host if request.client else "unknown"

    if error:
        msg = f"Microsoft OAuth Error: {error} ({error_description or 'No details'})"
        return HTMLResponse(
            render_login_html(
                ip=req_ip,
                mac=get_client_mac(req_ip) or "00:00:00:00:00:00",
                        error=msg,
            ),
            status_code=400,
        )

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state parameter.")

    try:
        state_ip, state_mac = verify_state(state, cfg["SESSION_SECRET"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    mac = state_mac if (state_mac and state_mac != "00:00:00:00:00:00") else (get_client_mac(req_ip) or state_mac)
    client_ip = state_ip or req_ip

    tenant_id = cfg["AZURE_TENANT_ID"] or "common"
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            token_url,
            data={
                "client_id": cfg["AZURE_CLIENT_ID"],
                "client_secret": cfg["AZURE_CLIENT_SECRET"],
                "code": code,
                "redirect_uri": cfg["REDIRECT_URI"],
                "grant_type": "authorization_code",
                "scope": "openid profile email",
            },
        )

    if resp.status_code != 200:
        return HTMLResponse(
            render_login_html(
                ip=client_ip,
                mac=mac,
                        error=f"Token exchange failed ({resp.status_code}): {resp.text}",
            ),
            status_code=400,
        )

    token_data = resp.json()
    id_token = token_data.get("id_token", "")
    claims = decode_jwt_claims(id_token)
    preferred_username = claims.get("preferred_username") or claims.get("email") or claims.get("upn") or "unknown@microsoft"
    name = claims.get("name") or preferred_username

    if not mac or mac == "00:00:00:00:00:00" or not MAC_RE.match(mac):
        raise HTTPException(status_code=400, detail=f"Cannot authorize invalid MAC address: {mac}")

    if not authorize_mac(mac):
        raise HTTPException(status_code=500, detail="Failed to add MAC to nftables authorized_macs set.")

    log_auth_event(client_ip, mac, preferred_username, name, "ENTRA_OIDC")
    return HTMLResponse(
        render_welcome_html(
            name=name,
            username=preferred_username,
            ip=client_ip,
            mac=mac,
            method="Microsoft Entra ID (OAuth2)",
        )
    )
