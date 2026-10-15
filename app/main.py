import base64
import datetime
import hashlib
import hmac
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
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

ENV_PATH = Path("/opt/captive-portal/.env")
LOG_PATH = Path("/var/log/captive-auth.log")

app = FastAPI(title="Captive Portal - Microsoft Entra ID (OAuth2)")


def get_config() -> dict:
    load_dotenv(ENV_PATH, override=True)
    return {
        "AZURE_CLIENT_ID": os.getenv("AZURE_CLIENT_ID", ""),
        "AZURE_TENANT_ID": os.getenv("AZURE_TENANT_ID", ""),
        "AZURE_CLIENT_SECRET": os.getenv("AZURE_CLIENT_SECRET", ""),
        "REDIRECT_URI": os.getenv("REDIRECT_URI", "http://localhost:3000/auth/callback"),
        "SESSION_SECRET": os.getenv("SESSION_SECRET", "default-fallback-secret-change-me"),
        "DEMO_BYPASS_MODE": os.getenv("DEMO_BYPASS_MODE", "true").lower() in ("true", "1", "yes"),
    }


MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


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


def render_login_html(ip: str, mac: str, demo_mode: bool, authorized: bool = False, error: str = "") -> str:
    status_badge = (
        '<span class="badge badge-success">Authorized (Active 8h)</span>'
        if authorized
        else '<span class="badge badge-warn">Authentication Required</span>'
    )
    error_box = f'<div class="alert alert-error">{error}</div>' if error else ""
    demo_btn = ""
    if demo_mode:
        demo_btn = f"""
        <div class="demo-divider"><span>Testing &amp; Pre-Production</span></div>
        <a href="/auth/demo?mac={urllib.parse.quote(mac)}&ip={urllib.parse.quote(ip)}" class="btn btn-demo">
            1-Click Demo Authorize
        </a>
        <p class="demo-note">DEMO_BYPASS_MODE is enabled in <code>/opt/captive-portal/.env</code>.</p>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Campus Wi-Fi Portal | Sign In</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --muted: #94a3b8;
            --ms-blue: #0078d4;
            --ms-blue-hover: #106ebe;
            --demo-emerald: #10b981;
            --demo-emerald-hover: #059669;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: radial-gradient(circle at top, #1e293b 0%, #0f172a 100%);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
        }}
        .card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            max-width: 440px;
            width: 100%;
            padding: 2.25rem;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.45);
        }}
        .school-header {{
            display: flex;
            align-items: center;
            gap: 0.875rem;
            margin-bottom: 1.5rem;
        }}
        .school-logo {{
            width: 44px;
            height: 44px;
            border-radius: 10px;
            background: linear-gradient(135deg, #3b82f6, #1d4ed8);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1.2rem;
            color: #fff;
            flex-shrink: 0;
        }}
        h1 {{ font-size: 1.35rem; font-weight: 700; letter-spacing: -0.02em; }}
        .subtitle {{ color: var(--muted); font-size: 0.875rem; margin-top: 0.15rem; }}
        .info-panel {{
            background: rgba(15, 23, 42, 0.65);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1rem 1.15rem;
            margin-bottom: 1.5rem;
        }}
        .info-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.4rem 0;
            font-size: 0.875rem;
        }}
        .info-row:not(:last-child) {{ border-bottom: 1px solid rgba(51, 65, 85, 0.5); }}
        .info-label {{ color: var(--muted); }}
        .info-value {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-weight: 600; }}
        .badge {{
            font-size: 0.75rem;
            padding: 0.2rem 0.6rem;
            border-radius: 9999px;
            font-weight: 600;
        }}
        .badge-warn {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }}
        .badge-success {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }}
        .alert-error {{
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid rgba(239, 68, 68, 0.4);
            color: #fca5a5;
            padding: 0.75rem 1rem;
            border-radius: 10px;
            font-size: 0.85rem;
            margin-bottom: 1.25rem;
        }}
        .btn {{
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.65rem;
            width: 100%;
            padding: 0.85rem 1.25rem;
            border-radius: 10px;
            font-size: 0.95rem;
            font-weight: 600;
            text-decoration: none;
            transition: background 0.15s ease;
            border: none;
            cursor: pointer;
        }}
        .btn-ms {{ background: var(--ms-blue); color: #ffffff; }}
        .btn-ms:hover {{ background: var(--ms-blue-hover); }}
        .btn-demo {{ background: var(--demo-emerald); color: #ffffff; }}
        .btn-demo:hover {{ background: var(--demo-emerald-hover); }}
        .demo-divider {{
            display: flex;
            align-items: center;
            text-align: center;
            color: var(--muted);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin: 1.35rem 0 0.9rem;
        }}
        .demo-divider::before, .demo-divider::after {{
            content: "";
            flex: 1;
            border-bottom: 1px solid var(--border);
        }}
        .demo-divider span {{ padding: 0 0.75rem; }}
        .demo-note {{
            text-align: center;
            color: var(--muted);
            font-size: 0.75rem;
            margin-top: 0.6rem;
        }}
        code {{ color: #cbd5e1; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="school-header">
            <div class="school-logo">EDU</div>
            <div>
                <h1>School Wi-Fi Portal</h1>
                <div class="subtitle">Microsoft Entra ID Single Sign-On</div>
            </div>
        </div>
        {error_box}
        <div class="info-panel">
            <div class="info-row">
                <span class="info-label">Status</span>
                {status_badge}
            </div>
            <div class="info-row">
                <span class="info-label">Client IPv4</span>
                <span class="info-value">{ip}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Device MAC</span>
                <span class="info-value">{mac}</span>
            </div>
            <div class="info-row">
                <span class="info-label">VLAN Segment</span>
                <span class="info-value">VLAN 50 (10.50.0.0/24)</span>
            </div>
        </div>
        <a href="/auth/login" class="btn btn-ms">
            <svg width="18" height="18" viewBox="0 0 21 21" fill="none">
                <rect x="1" y="1" width="9" height="9" fill="#f25022"/>
                <rect x="11" y="1" width="9" height="9" fill="#7fba00"/>
                <rect x="1" y="11" width="9" height="9" fill="#00a4ef"/>
                <rect x="11" y="11" width="9" height="9" fill="#ffb900"/>
            </svg>
            Sign in with Microsoft
        </a>
        {demo_btn}
    </div>
</body>
</html>"""


def render_welcome_html(name: str, username: str, ip: str, mac: str, method: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connected | School Wi-Fi Portal</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: radial-gradient(circle at top, #064e3b 0%, #0f172a 100%);
            color: #f8fafc;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
            margin: 0;
        }}
        .card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 16px;
            max-width: 440px;
            width: 100%;
            padding: 2.25rem;
            text-align: center;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.45);
        }}
        .icon {{
            width: 56px;
            height: 56px;
            border-radius: 50%;
            background: rgba(16, 185, 129, 0.2);
            color: #34d399;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.75rem;
            margin: 0 auto 1.25rem;
        }}
        h1 {{ font-size: 1.4rem; margin-bottom: 0.4rem; }}
        p {{ color: #94a3b8; font-size: 0.9rem; margin-bottom: 1.5rem; }}
        .details {{
            background: rgba(15, 23, 42, 0.65);
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 1rem;
            text-align: left;
            font-size: 0.85rem;
        }}
        .row {{ display: flex; justify-content: space-between; padding: 0.35rem 0; }}
        .label {{ color: #94a3b8; }}
        .val {{ font-family: ui-monospace, monospace; font-weight: 600; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">&#10003;</div>
        <h1>Welcome, {name}!</h1>
        <p>Your device is now authorized for internet access for the next 8 hours.</p>
        <div class="details">
            <div class="row"><span class="label">Account</span><span class="val">{username}</span></div>
            <div class="row"><span class="label">Auth Method</span><span class="val">{method}</span></div>
            <div class="row"><span class="label">Client IP</span><span class="val">{ip}</span></div>
            <div class="row"><span class="label">Device MAC</span><span class="val">{mac}</span></div>
            <div class="row"><span class="label">Session Lease</span><span class="val">8 Hours</span></div>
        </div>
    </div>
</body>
</html>"""


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
        demo_mode=cfg["DEMO_BYPASS_MODE"],
        authorized=authorized,
        error=error,
    )
    return HTMLResponse(content=html, status_code=200)


@app.get("/auth/demo", response_class=HTMLResponse)
async def auth_demo_bypass(request: Request, mac: Optional[str] = None, ip: Optional[str] = None):
    cfg = get_config()
    if not cfg["DEMO_BYPASS_MODE"]:
        raise HTTPException(status_code=403, detail="Demo bypass mode is disabled.")

    client_ip = ip or (request.client.host if request.client else "unknown")
    resolved_mac = get_client_mac(client_ip) or mac or "00:00:00:00:00:00"
    if resolved_mac == "00:00:00:00:00:00" or not MAC_RE.match(resolved_mac):
        return HTMLResponse(
            render_login_html(
                ip=client_ip,
                mac=resolved_mac,
                demo_mode=True,
                error="Could not resolve a valid client MAC address from ARP/neighbor table on eth1.",
            ),
            status_code=400,
        )

    authorize_mac(resolved_mac)
    log_auth_event(client_ip, resolved_mac, "demo@school.local", "Demo User", "DEMO_BYPASS")
    return HTMLResponse(
        render_welcome_html(
            name="Demo User",
            username="demo@school.local",
            ip=client_ip,
            mac=resolved_mac,
            method="1-Click Demo Bypass",
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
                demo_mode=cfg["DEMO_BYPASS_MODE"],
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
                demo_mode=cfg["DEMO_BYPASS_MODE"],
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
