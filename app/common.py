"""Shared helpers for the captive portal: SQLite device store, nftables control, HMAC signing.

Used by both the captive portal app (main.py) and the admin panel (admin.py).
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DB_PATH = Path(os.getenv("PORTAL_DB", "/opt/captive-portal/portal.db"))
LOG_PATH = Path("/var/log/captive-auth.log")

NFT_FAMILY = "inet"
NFT_TABLE = "captive"
BW_CHAIN = "bandwidth_limits"
AUTH_SET = "authorized_macs"

MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")

# Sentinel stored in the DB / returned by the API to mean "no rate limit".
UNLIMITED = 0


# --------------------------------------------------------------------------- #
# Generic helpers
# --------------------------------------------------------------------------- #
def valid_mac(mac: Optional[str]) -> bool:
    return bool(mac) and bool(MAC_RE.match(mac))


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _run(args: List[str], timeout: int = 5) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


# --------------------------------------------------------------------------- #
# SQLite device store
# --------------------------------------------------------------------------- #
def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def db_init() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db_connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                mac        TEXT PRIMARY KEY,
                label      TEXT    NOT NULL DEFAULT '',
                limit_kbps INTEGER NOT NULL DEFAULT 0,
                created_at TEXT    NOT NULL,
                updated_at TEXT    NOT NULL
            )
            """
        )
        conn.commit()


def list_devices() -> List[Dict]:
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT * FROM devices ORDER BY label COLLATE NOCASE, mac"
        ).fetchall()
        return [dict(r) for r in rows]


def get_device(mac: str) -> Optional[Dict]:
    mac = (mac or "").lower()
    with db_connect() as conn:
        row = conn.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
        return dict(row) if row else None


def upsert_device(mac: str, label: str = "", limit_kbps: int = UNLIMITED) -> Dict:
    mac = (mac or "").lower().strip()
    if not valid_mac(mac):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    limit_kbps = max(0, int(limit_kbps or 0))
    now = _now()
    with db_connect() as conn:
        exists = conn.execute("SELECT 1 FROM devices WHERE mac=?", (mac,)).fetchone()
        if exists:
            conn.execute(
                "UPDATE devices SET label=?, limit_kbps=?, updated_at=? WHERE mac=?",
                (label, limit_kbps, now, mac),
            )
        else:
            conn.execute(
                "INSERT INTO devices (mac,label,limit_kbps,created_at,updated_at)"
                " VALUES (?,?,?,?,?)",
                (mac, label, limit_kbps, now, now),
            )
        conn.commit()
    return get_device(mac)  # type: ignore[return-value]


def delete_device(mac: str) -> None:
    mac = (mac or "").lower()
    with db_connect() as conn:
        conn.execute("DELETE FROM devices WHERE mac=?", (mac,))
        conn.commit()


# --------------------------------------------------------------------------- #
# nftables: bandwidth limits
# --------------------------------------------------------------------------- #
def list_bw_rules() -> List[Tuple[str, int]]:
    """Return [(mac, handle), ...] for bandwidth rules currently installed."""
    res = _run(["nft", "-j", "list", "chain", NFT_FAMILY, NFT_TABLE, BW_CHAIN])
    if res.returncode != 0:
        return []
    try:
        data = json.loads(res.stdout or "{}")
    except json.JSONDecodeError:
        return []
    out: List[Tuple[str, int]] = []
    for obj in data.get("nftables", []):
        rule = obj.get("rule")
        if not rule or rule.get("handle") is None:
            continue
        comment = rule.get("comment") or ""
        if comment.startswith("bw:"):
            out.append((comment[3:].lower(), int(rule["handle"])))
    return out


def clear_bw_rules(mac: Optional[str] = None) -> int:
    """Delete bandwidth rules, for one MAC or all when mac is None. Returns count removed."""
    mac = mac.lower() if mac else None
    removed = 0
    for rule_mac, handle in list_bw_rules():
        if mac is None or rule_mac == mac:
            res = _run(
                ["nft", "delete", "rule", NFT_FAMILY, NFT_TABLE, BW_CHAIN, "handle", str(handle)]
            )
            if res.returncode == 0:
                removed += 1
    return removed


def apply_limit(mac: str, limit_kbps: int) -> bool:
    """Install a bidirectional rate limit for a MAC. limit_kbps <= 0 means unlimited."""
    mac = (mac or "").lower().strip()
    if not valid_mac(mac):
        raise ValueError(f"Invalid MAC address: {mac!r}")

    clear_bw_rules(mac)  # idempotent: drop any previous rules for this MAC

    limit_kbps = int(limit_kbps or 0)
    if limit_kbps <= 0:
        return True  # unlimited: no rules needed

    # kbit/s -> kbyte/s (nft "kbytes" is 1000 bytes)
    kbytes = max(1, int(round(limit_kbps / 8)))

    ok = True
    for direction in ("saddr", "daddr"):  # saddr = upload, daddr = download
        res = _run(
            [
                "nft", "add", "rule", NFT_FAMILY, NFT_TABLE, BW_CHAIN,
                "ether", direction, mac,
                "limit", "rate", "over", str(kbytes), "kbytes/second",
                "drop",
                # nft's CLI requires the comment to be a quoted string literal.
                "comment", f'"bw:{mac}"',
            ]
        )
        ok = ok and res.returncode == 0
    return ok


def sync_all_limits() -> int:
    """Re-apply every stored limit. Required after reboot: nft rules are volatile."""
    applied = 0
    for dev in list_devices():
        if int(dev.get("limit_kbps") or 0) > 0:
            apply_limit(dev["mac"], dev["limit_kbps"])
            applied += 1
    return applied


# --------------------------------------------------------------------------- #
# nftables: authorized MACs
# --------------------------------------------------------------------------- #
def list_authorized_macs() -> List[str]:
    """Return currently authorized MAC addresses (from the nft set)."""
    res = _run(["nft", "-j", "list", "set", NFT_FAMILY, NFT_TABLE, AUTH_SET])
    if res.returncode != 0:
        return []
    try:
        data = json.loads(res.stdout or "{}")
    except json.JSONDecodeError:
        return []
    out: List[str] = []
    for obj in data.get("nftables", []):
        st = obj.get("set")
        if not st:
            continue
        for el in st.get("elem") or []:
            if isinstance(el, str):
                out.append(el.lower())
            elif isinstance(el, dict):
                val = el.get("elem")
                if isinstance(val, dict):
                    val = val.get("val")
                if isinstance(val, str):
                    out.append(val.lower())
    return out


def is_mac_authorized(mac: Optional[str]) -> bool:
    if not valid_mac(mac):
        return False
    return (mac or "").lower() in list_authorized_macs()


def authorize_mac(mac: str, timeout: str = "8h") -> bool:
    mac = (mac or "").lower().strip()
    if not valid_mac(mac):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    res = _run(
        ["nft", "add", "element", NFT_FAMILY, NFT_TABLE, AUTH_SET,
         f"{{ {mac} timeout {timeout} }}"]
    )
    return res.returncode == 0


def deauthorize_mac(mac: str) -> bool:
    mac = (mac or "").lower().strip()
    if not valid_mac(mac):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    res = _run(["nft", "delete", "element", NFT_FAMILY, NFT_TABLE, AUTH_SET, f"{{ {mac} }}"])
    return res.returncode == 0


# --------------------------------------------------------------------------- #
# HMAC signing (OAuth state + admin session cookie)
# --------------------------------------------------------------------------- #
def sign_payload(data: Dict, secret: str) -> str:
    payload = json.dumps(data, separators=(",", ":"), sort_keys=True)
    b64 = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("utf-8").rstrip("=")
    sig = hmac.new(secret.encode("utf-8"), b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


def verify_payload(token: str, secret: str, max_age_seconds: int = 43200) -> Optional[Dict]:
    if not token or "." not in token:
        return None
    b64, sig = token.rsplit(".", 1)
    expected = hmac.new(secret.encode("utf-8"), b64.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    padding = "=" * (-len(b64) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(b64 + padding).decode("utf-8"))
    except Exception:
        return None
    if max_age_seconds and int(time.time()) - int(data.get("ts", 0)) > max_age_seconds:
        return None
    return data


# --------------------------------------------------------------------------- #
# Auth audit log
# --------------------------------------------------------------------------- #
def log_auth_event(ip: str, mac: str, username: str, name: str, method: str) -> None:
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    entry = (
        f"{ts} | method={method} | ip={ip} | mac={mac} | user={username} | name={name}\n"
    )
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(entry)
    except Exception:
        pass
