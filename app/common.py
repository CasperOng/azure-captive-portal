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
ACCT_CHAIN = "accounting"
AUTH_SET = "authorized_macs"

# authorized_macs elements carry this timeout; connected time is derived from it.
SESSION_SECONDS = 8 * 3600

# Static brand assets (school crest, signature) served by both apps.
BRAND_DIR = Path(os.getenv("PORTAL_BRAND_DIR", "/opt/captive-portal/brand"))


def brand_media_type(name: str) -> str:
    lowered = name.lower()
    if lowered.endswith(".png"):
        return "image/png"
    if lowered.endswith(".svg"):
        return "image/svg+xml"
    if lowered.endswith(".ico"):
        return "image/x-icon"
    if lowered.endswith(".jpg") or lowered.endswith(".jpeg"):
        return "image/jpeg"
    return "application/octet-stream"


def brand_file(name: str) -> Optional[Path]:
    """Resolve a brand asset safely (no path traversal). None if missing."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "", name or "")
    if not safe:
        return None
    candidate = (BRAND_DIR / safe).resolve()
    try:
        candidate.relative_to(BRAND_DIR.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None

MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")

# Sentinel stored in the DB / returned by the API to mean "no rate limit".
UNLIMITED = 0

# Placeholder values that must never be accepted as a session-signing key.
WEAK_SECRETS = frozenset({
    "default-fallback-secret-change-me",
    "generate-a-real-32-byte-hex-secret",
    "changeme", "change-me", "secret", "password",
})


def require_session_secret(raw: Optional[str]) -> str:
    """Fail closed on a missing or weak SESSION_SECRET.

    Falling back to a known constant would let anyone forge the admin session
    cookie and the OAuth state parameter, so this raises instead.
    """
    secret = (raw or "").strip()
    if len(secret) < 32 or secret.lower() in WEAK_SECRETS:
        raise RuntimeError(
            "SESSION_SECRET is missing, shorter than 32 characters, or a known "
            'placeholder. Generate one with: python3 -c "import secrets; '
            'print(secrets.token_hex(32))"'
        )
    return secret


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
    try:
        # Two processes (portal + admin) write to this database: WAL plus a
        # busy timeout avoids "database is locked" under concurrent writes.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
    except sqlite3.Error:
        pass
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                email         TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                label         TEXT NOT NULL DEFAULT '',
                created_at    TEXT NOT NULL,
                last_login_at TEXT,
                role          TEXT NOT NULL DEFAULT 'wifi'
            )
            """
        )
        # Migrate databases created before roles existed.
        cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "role" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'wifi'")

        # Device profiles: a named policy bundle assigned to fixed devices
        # (whiteboards, public PCs) so they can be provisioned without a
        # browser sign-in.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS profiles (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                name           TEXT    NOT NULL UNIQUE,
                description    TEXT    NOT NULL DEFAULT '',
                bandwidth_kbps INTEGER NOT NULL DEFAULT 0,
                auto_authorize INTEGER NOT NULL DEFAULT 0,
                session_hours  INTEGER NOT NULL DEFAULT 8,
                auth_method    TEXT    NOT NULL DEFAULT 'mac',
                created_at     TEXT    NOT NULL,
                updated_at     TEXT    NOT NULL
            )
            """
        )
        # Migrate devices created before profiles existed.
        dcols = {row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}
        for col, decl in (
            ("profile_id", "INTEGER"),
            ("auth_method", "TEXT NOT NULL DEFAULT ''"),
            ("entra_device_id", "TEXT NOT NULL DEFAULT ''"),
            ("notes", "TEXT NOT NULL DEFAULT ''"),
            ("enrolled_at", "TEXT"),
            ("last_seen", "TEXT"),
        ):
            if col not in dcols:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {col} {decl}")
        conn.commit()
    # The database holds password hashes: keep it owner-only.
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass


def list_devices() -> List[Dict]:
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT d.*, p.name AS profile_name, p.auto_authorize AS profile_auto"
            " FROM devices d LEFT JOIN profiles p ON p.id = d.profile_id"
            " ORDER BY d.label COLLATE NOCASE, d.mac"
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
# Device profiles
#
# A profile is a named policy bundle. Assigning one to a fixed device
# (BenQ whiteboard, public PC) lets it be provisioned without a browser
# sign-in when auto_authorize is set.
# --------------------------------------------------------------------------- #
AUTH_METHODS = ("mac", "psk", "cert", "sso")


def list_profiles() -> List[Dict]:
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT * FROM profiles ORDER BY name COLLATE NOCASE"
        ).fetchall()
        return [dict(r) for r in rows]


def get_profile(profile_id: object) -> Optional[Dict]:
    try:
        pid = int(profile_id)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    with db_connect() as conn:
        row = conn.execute("SELECT * FROM profiles WHERE id=?", (pid,)).fetchone()
        return dict(row) if row else None


def upsert_profile(name: str, description: str = "", bandwidth_kbps: int = UNLIMITED,
                   auto_authorize: bool = False, session_hours: int = 8,
                   auth_method: str = "mac") -> Dict:
    name = (name or "").strip()
    if not name:
        raise ValueError("Profile name is required")
    if auth_method not in AUTH_METHODS:
        raise ValueError(f"Unknown auth_method: {auth_method!r}")
    now = _now()
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO profiles (name,description,bandwidth_kbps,auto_authorize,"
            " session_hours,auth_method,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET description=excluded.description,"
            " bandwidth_kbps=excluded.bandwidth_kbps, auto_authorize=excluded.auto_authorize,"
            " session_hours=excluded.session_hours, auth_method=excluded.auth_method,"
            " updated_at=excluded.updated_at",
            (name, description, max(0, int(bandwidth_kbps or 0)),
             1 if auto_authorize else 0, max(1, int(session_hours or 8)),
             auth_method, now, now),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM profiles WHERE name=?", (name,)).fetchone()
        return dict(row)


def delete_profile(profile_id: object) -> None:
    try:
        pid = int(profile_id)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return
    with db_connect() as conn:
        conn.execute("UPDATE devices SET profile_id=NULL WHERE profile_id=?", (pid,))
        conn.execute("DELETE FROM profiles WHERE id=?", (pid,))
        conn.commit()


def assign_device_profile(mac: str, profile_id: object) -> None:
    mac = (mac or "").lower().strip()
    if not valid_mac(mac):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    pid = None
    if profile_id not in (None, "", "0", 0):
        prof = get_profile(profile_id)
        if not prof:
            raise ValueError("Unknown profile")
        pid = prof["id"]
    with db_connect() as conn:
        conn.execute(
            "UPDATE devices SET profile_id=?, updated_at=? WHERE mac=?",
            (pid, _now(), mac),
        )
        conn.commit()
    # Apply the profile's bandwidth straight away. Previously this only happened
    # for auto-authorize profiles, so assigning a bandwidth-limited profile to a
    # device did nothing at all.
    if pid is not None:
        prof = get_profile(pid) or {}
        limit = int(prof.get("bandwidth_kbps") or 0)
        label = (get_device(mac) or {}).get("label") or ""
        upsert_device(mac, label, limit)
        apply_limit(mac, limit)


def devices_for_profile(profile_id: object) -> List[str]:
    try:
        pid = int(profile_id)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return []
    with db_connect() as conn:
        rows = conn.execute("SELECT mac FROM devices WHERE profile_id=?", (pid,)).fetchall()
        return [r[0] for r in rows]


def sync_static_authorizations() -> int:
    """Keep provisioned devices online even though nftables state is volatile.

    For every device whose profile sets auto_authorize, re-assert the MAC in
    authorized_macs with a long lease and enforce the profile's bandwidth.
    Also drops static access for devices whose profile no longer auto-authorizes.
    Returns the number of devices kept online.
    """
    static_macs = set()
    kept = 0
    for dev in list_devices():
        pid = dev.get("profile_id")
        if not pid:
            continue
        prof = get_profile(pid)
        if not prof or not int(prof.get("auto_authorize") or 0):
            continue
        mac = dev["mac"]
        static_macs.add(mac)
        want = int(prof.get("bandwidth_kbps") or 0)
        if int(dev.get("limit_kbps") or 0) != want:
            upsert_device(mac, dev.get("label") or "", want)
            apply_limit(mac, want)
        # The timer refreshes this well inside the lease, so the profile's
        # session length governs how long a device stays reachable if sync stops.
        hours = max(1, int(prof.get("session_hours") or 24))
        _run(["nft", "add", "element", NFT_FAMILY, NFT_TABLE, AUTH_SET,
              f"{{ {mac} timeout {hours}h }}"])
        kept += 1
    return kept


# --------------------------------------------------------------------------- #
# Local accounts (email + password)
#
# Email is the natural key so a later Microsoft/OIDC sign-in can link to an
# existing account by verified email without duplicating users.
# --------------------------------------------------------------------------- #
PBKDF2_ROUNDS = 200_000


def _hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, rounds, salt_hex, digest_hex = (stored or "").split("$")
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds)
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def normalise_email(email: str) -> str:
    return (email or "").strip().lower()


def create_user(email: str, password: str, label: str = "", role: str = "wifi") -> Dict:
    email = normalise_email(email)
    if not email or "@" not in email:
        raise ValueError(f"Invalid email address: {email!r}")
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    if role not in ("wifi", "admin"):
        raise ValueError(f"Unknown role: {role!r}")
    now = _now()
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO users (email,password_hash,label,created_at,role) VALUES (?,?,?,?,?)"
            " ON CONFLICT(email) DO UPDATE SET password_hash=excluded.password_hash,"
            " label=excluded.label, role=excluded.role",
            (email, _hash_password(password), label, now, role),
        )
        conn.commit()
    return get_user(email)  # type: ignore[return-value]


def set_user_role(email: str, role: str) -> None:
    if role not in ("wifi", "admin"):
        raise ValueError(f"Unknown role: {role!r}")
    email = normalise_email(email)
    with db_connect() as conn:
        conn.execute("UPDATE users SET role=? WHERE email=?", (role, email))
        conn.commit()


def list_admins() -> List[Dict]:
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT * FROM users WHERE role='admin' ORDER BY email"
        ).fetchall()
        return [dict(r) for r in rows]


def verify_admin(email: str, password: str) -> Optional[Dict]:
    """Return the admin record when credentials match an account with role=admin."""
    user = get_user(email)
    if not user or user.get("role") != "admin":
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    with db_connect() as conn:
        conn.execute(
            "UPDATE users SET last_login_at=? WHERE email=?", (_now(), user["email"])
        )
        conn.commit()
    return user


def set_user_password(email: str, password: str) -> None:
    email = normalise_email(email)
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    with db_connect() as conn:
        conn.execute("UPDATE users SET password_hash=? WHERE email=?", (_hash_password(password), email))
        conn.commit()


def get_user(email: str) -> Optional[Dict]:
    email = normalise_email(email)
    with db_connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        return dict(row) if row else None


def list_users() -> List[Dict]:
    with db_connect() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY email").fetchall()
        return [dict(r) for r in rows]


def delete_user(email: str) -> None:
    email = normalise_email(email)
    with db_connect() as conn:
        conn.execute("DELETE FROM users WHERE email=?", (email,))
        conn.commit()


def verify_user(email: str, password: str) -> Optional[Dict]:
    """Return the user record when the password matches, else None."""
    user = get_user(email)
    if not user or not verify_password(password, user["password_hash"]):
        return None
    with db_connect() as conn:
        conn.execute(
            "UPDATE users SET last_login_at=? WHERE email=?", (_now(), user["email"])
        )
        conn.commit()
    return user


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


# --------------------------------------------------------------------------- #
# nftables: per-MAC traffic accounting (current session only)
#
# Rules are volatile like the rest: nft rules do not survive a reload, so they
# are reinstalled whenever a device is authorized and cleared when revoked.
# --------------------------------------------------------------------------- #
def _acct_rules() -> List[Tuple[str, str, int, int, int]]:
    """Return [(mac, direction, handle, packets, bytes), ...]."""
    res = _run(["nft", "-j", "list", "chain", NFT_FAMILY, NFT_TABLE, ACCT_CHAIN])
    if res.returncode != 0:
        return []
    try:
        data = json.loads(res.stdout or "{}")
    except json.JSONDecodeError:
        return []
    out: List[Tuple[str, str, int, int, int]] = []
    for obj in data.get("nftables", []):
        rule = obj.get("rule")
        if not rule:
            continue
        comment = rule.get("comment") or ""
        if not comment.startswith("acct|"):
            continue
        # MACs contain colons, so the fields are pipe-separated.
        _, mac, direction = comment.split("|", 2)
        counters = rule.get("counter") or {}
        out.append((
            mac.lower(),
            direction,
            int(rule.get("handle", 0)),
            int(counters.get("packets", 0)),
            int(counters.get("bytes", 0)),
        ))
    return out


def clear_acct_rules(mac: Optional[str] = None) -> int:
    mac = mac.lower() if mac else None
    removed = 0
    for rule_mac, _direction, handle, _p, _b in _acct_rules():
        if mac is None or rule_mac == mac:
            if _run(["nft", "delete", "rule", NFT_FAMILY, NFT_TABLE,
                     ACCT_CHAIN, "handle", str(handle)]).returncode == 0:
                removed += 1
    return removed


def ensure_acct_rules(mac: str) -> bool:
    """Install upload+download byte counters for a MAC (idempotent)."""
    mac = (mac or "").lower().strip()
    if not valid_mac(mac):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    existing = {(m, d) for m, d, _h, _p, _b in _acct_rules() if m == mac}
    ok = True
    for direction, kind in (("saddr", "up"), ("daddr", "down")):
        if (mac, kind) in existing:
            continue
        res = _run([
            "nft", "add", "rule", NFT_FAMILY, NFT_TABLE, ACCT_CHAIN,
            "ether", direction, mac,
            "counter",
            "comment", f'"acct|{mac}|{kind}"',
        ])
        ok = ok and res.returncode == 0
    return ok


def read_acct(mac: str) -> Dict[str, int]:
    """Bytes/packets used by a MAC in the current session."""
    mac = (mac or "").lower().strip()
    up_bytes = down_bytes = up_pkts = down_pkts = 0
    for rule_mac, direction, _h, packets, nbytes in _acct_rules():
        if rule_mac != mac:
            continue
        if direction == "up":
            up_bytes, up_pkts = nbytes, packets
        elif direction == "down":
            down_bytes, down_pkts = nbytes, packets
    return {
        "up_bytes": up_bytes,
        "down_bytes": down_bytes,
        "bytes": up_bytes + down_bytes,
        "up_packets": up_pkts,
        "down_packets": down_pkts,
    }


def session_remaining(mac: str) -> Optional[int]:
    """Seconds left on a MAC's authorization, or None if not authorized."""
    mac = (mac or "").lower().strip()
    res = _run(["nft", "-j", "list", "set", NFT_FAMILY, NFT_TABLE, AUTH_SET])
    if res.returncode != 0:
        return None
    try:
        data = json.loads(res.stdout or "{}")
    except json.JSONDecodeError:
        return None
    for obj in data.get("nftables", []):
        st = obj.get("set")
        if not st:
            continue
        for el in st.get("elem") or []:
            if not isinstance(el, dict):
                continue
            val = el.get("elem")
            if isinstance(val, dict):
                if str(val.get("val", "")).lower() == mac and "expires" in val:
                    return int(val["expires"])
    return None


def session_summary(mac: str) -> Dict[str, object]:
    """Everything the UI needs about a device's current session.

    Returns zeros/inactive when the MAC is not currently authorized.
    """
    mac = (mac or "").lower().strip()
    remaining = session_remaining(mac)
    acct = read_acct(mac)
    active = remaining is not None
    connected = max(0, SESSION_SECONDS - remaining) if active and remaining is not None else 0
    return {
        "mac": mac,
        "active": active,
        "connected_seconds": connected,
        "remaining_seconds": remaining or 0,
        "connected_human": fmt_duration(connected),
        "remaining_human": fmt_duration(remaining or 0),
        "bytes": acct["bytes"],
        "up_bytes": acct["up_bytes"],
        "down_bytes": acct["down_bytes"],
        "bytes_human": fmt_bytes(acct["bytes"]),
        "up_human": fmt_bytes(acct["up_bytes"]),
        "down_human": fmt_bytes(acct["down_bytes"]),
    }


def fmt_bytes(n: int) -> str:
    step = 1000.0
    value = float(n)
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if value < step or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= step
    return f"{value:.1f} TB"


def fmt_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


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
    if res.returncode == 0:
        # Start a fresh per-session byte counter for this device.
        clear_acct_rules(mac)
        ensure_acct_rules(mac)
    return res.returncode == 0


def deauthorize_mac(mac: str) -> bool:
    mac = (mac or "").lower().strip()
    if not valid_mac(mac):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    res = _run(["nft", "delete", "element", NFT_FAMILY, NFT_TABLE, AUTH_SET, f"{{ {mac} }}"])
    # Session over: drop its counters so the next sign-in starts from zero.
    clear_acct_rules(mac)
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
AUTH_LOG_MAX_BYTES = 5 * 1024 * 1024


def _rotate_log(path: Path, max_bytes: int = AUTH_LOG_MAX_BYTES) -> None:
    """Keep the auth log bounded so a busy portal cannot fill the disk."""
    try:
        if path.exists() and path.stat().st_size > max_bytes:
            path.replace(path.with_suffix(path.suffix + ".1"))
    except OSError:
        pass


def log_auth_event(ip: str, mac: str, username: str, name: str, method: str) -> None:
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    entry = (
        f"{ts} | method={method} | ip={ip} | mac={mac} | user={username} | name={name}\n"
    )
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        _rotate_log(LOG_PATH)
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(entry)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Presentation — shared design language
#
# Ported from CasperOng/open-day-attendance-science so both projects share one
# visual signature: paper/ink palette, green brand, white rounded cards,
# uppercase letter-spaced labels, pill badges, Avenir, and the developer
# signature in the footer.
#   paper #f6f7f9   ink #172033   mint #e7f6ee   fog #e6e9ef
#   brand #89d0af   brand-ink #1f7a4e (their token is named "coral")   amber #d99a26
# --------------------------------------------------------------------------- #
SIGNATURE_PATH = (
    "M 223 160 L 73 100 L 133 100 L 598 40 L 178 40 "
    "L 238 40 L 538 40 L 403 160 L 313 100"
)

DESIGN_CSS = """
:root{
  --paper:#f6f7f9; --ink:#172033; --line:#e2e6ec; --mint:#e7f6ee;
  --brand:#89d0af; --brand-ink:#1f7a4e; --brand-ink-hover:#185e3b;
  --amber:#d99a26; --fog:#e6e9ef;
  --font-ui:"Avenir Next",Avenir,"Segoe UI",system-ui,sans-serif;
  --font-mono:"SF Mono","Cascadia Code",ui-monospace,monospace;
  --shadow-lift:0 16px 40px rgba(23,32,51,.08);
  --shadow-panel:0 1px 3px rgba(23,32,51,.06),0 8px 24px rgba(23,32,51,.04);
}
*{box-sizing:border-box}
html{background:var(--paper)}
body{margin:0;background:var(--paper);color:var(--ink);
  font-family:var(--font-ui);letter-spacing:-.01em;-webkit-font-smoothing:antialiased}
h1,h2,h3{margin:0;letter-spacing:-.035em}
p{margin:0}
code,kbd,pre,.mono{font-family:var(--font-mono);letter-spacing:0}
a{color:inherit;text-decoration:none}
:focus-visible{outline:3px solid rgba(31,122,78,.35);outline-offset:3px}
::selection{background:#d6ebde;color:#132238}
@media (prefers-reduced-motion:no-preference){
  a,button{transition:color .15s ease,background-color .15s ease,border-color .15s ease,box-shadow .15s ease}
}
.wrap{max-width:1080px;margin:0 auto;padding:2.5rem 1.25rem}

/* ---- card ---- */
.card{background:#fff;border:1px solid rgba(23,32,51,.1);border-radius:16px;
  padding:1.25rem;box-shadow:var(--shadow-panel)}

/* ---- buttons ---- */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:.5rem;
  min-height:44px;padding:.625rem 1rem;border-radius:12px;border:0;
  font:inherit;font-size:.875rem;font-weight:600;letter-spacing:-.01em;
  cursor:pointer;white-space:nowrap;text-align:center}
.btn:active{transform:translateY(1px)}
.btn[disabled]{opacity:.45;cursor:not-allowed}
.btn-primary{background:var(--brand-ink);color:#fff}
.btn-primary:hover{background:var(--brand-ink-hover)}
.btn-secondary{background:#fff;color:var(--ink);border:1px solid rgba(23,32,51,.1);
  box-shadow:0 1px 2px rgba(23,32,51,.05)}
.btn-secondary:hover{border-color:rgba(23,32,51,.2);background:var(--paper)}
.btn-ghost{background:transparent;color:rgba(23,32,51,.6)}
.btn-ghost:hover{background:rgba(23,32,51,.05);color:var(--ink)}
.btn-danger{background:#dc2626;color:#fff}
.btn-danger:hover{background:#b91c1c}
.btn-sm{min-height:36px;padding:.4rem .7rem;font-size:.8rem;border-radius:10px}
.btn-block{width:100%}

/* ---- form controls ---- */
.input{min-height:44px;width:100%;border-radius:12px;border:1px solid rgba(23,32,51,.15);
  background:#fff;padding:.625rem .875rem;font:inherit;font-size:.875rem;
  color:var(--ink);outline:0}
.input::placeholder{color:rgba(23,32,51,.35)}
.input:focus{border-color:var(--brand-ink);box-shadow:0 0 0 4px rgba(31,122,78,.1)}
.label{display:block;margin-bottom:.5rem;font-size:.75rem;font-weight:700;
  text-transform:uppercase;letter-spacing:.12em;color:rgba(23,32,51,.55)}

/* ---- badges ---- */
.badge{display:inline-flex;align-items:center;border-radius:9999px;
  padding:.25rem .625rem;font-size:.75rem;font-weight:700;letter-spacing:.02em}
.badge-default{background:rgba(23,32,51,.05);color:rgba(23,32,51,.6)}
.badge-green{background:#d1fae5;color:#065f46}
.badge-orange{background:#fef3c7;color:#78350f}

/* ---- alerts ---- */
.alert{border-radius:12px;padding:.75rem;font-size:.875rem;font-weight:500}
.alert-error{border:1px solid #fecaca;background:#fef2f2;color:#b91c1c}
.alert-ok{border:1px solid #a7f3d0;background:#ecfdf5;color:#065f46}

/* ---- tables ---- */
table{width:100%;border-collapse:collapse;font-size:.875rem}
th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;
  color:rgba(23,32,51,.55);padding:.6rem .5rem;border-bottom:1px solid var(--line);
  font-weight:700}
td{padding:.7rem .5rem;border-bottom:1px solid rgba(226,230,236,.8);vertical-align:middle}
tbody tr{transition:background-color .15s ease}
tbody tr:hover{background:rgba(137,208,175,.08)}
tbody tr:last-child td{border-bottom:0}

/* ---- developer signature ---- */
.credit{display:flex;justify-content:center;padding:.5rem 1.25rem 2rem}
.credit a{display:inline-flex;flex-direction:column;align-items:center;gap:.75rem;
  max-width:100%;padding:.5rem;border-radius:8px;text-align:center;
  font-size:.75rem;color:rgba(23,32,51,.7)}
.credit a:hover{color:var(--ink)}
.credit svg{width:12rem;height:auto;color:var(--ink);opacity:.6}
.credit a:hover svg{opacity:.8}
.credit-compact svg{width:7rem}
.credit span.stack{display:flex;flex-direction:column;gap:.25rem}
.credit a:hover .credit-line{text-decoration:underline;text-underline-offset:4px}

/* ---- captive portal auth layout ---- */
.auth{display:flex;flex-direction:column;min-height:100dvh;background:var(--paper)}
@media (min-width:1024px){.auth{flex-direction:row}}
.auth-aside{position:relative;display:none;overflow:hidden;background:var(--ink);color:#fff}
@media (min-width:1024px){
  .auth-aside{display:flex;flex-direction:column;justify-content:center;
    width:46%;padding:4rem 3rem}
}
.auth-aside .glow{position:absolute;border-radius:9999px;filter:blur(64px);pointer-events:none}
.auth-aside .glow-1{width:24rem;height:24rem;background:rgba(31,122,78,.3);left:-6rem;top:-6rem}
.auth-aside .glow-2{width:24rem;height:24rem;background:rgba(137,208,175,.18);right:-4rem;bottom:-8rem}
.auth-aside-inner{position:relative}
.crest{display:grid;place-items:center;width:5rem;height:5rem;border-radius:24px;
  background:#fff;color:var(--brand-ink);font-weight:800;font-size:1.25rem;
  letter-spacing:-.02em;box-shadow:var(--shadow-lift);overflow:hidden}
.crest img{width:78%;height:78%;object-fit:contain;display:block}
.crest-sm img{width:74%;height:74%;object-fit:contain;display:block}
.zh{font-size:.85em;opacity:.7;letter-spacing:0}
.auth-aside h1{margin-top:2rem;font-size:2.5rem;line-height:1.05;font-weight:700;color:#fff}
.auth-aside .sub{margin-top:1rem;max-width:24rem;color:rgba(255,255,255,.6);
  font-size:1rem;line-height:1.6}
.auth-aside .accent{margin-top:.5rem;color:var(--brand);font-size:.875rem;
  font-weight:500;letter-spacing:0}
.auth-main{display:flex;flex:1;flex-direction:column;min-width:0}
.auth-main>main{display:grid;flex:1;place-items:center;padding:2.5rem 1.25rem}
@media (min-width:1024px){.auth-main>main{padding:2.5rem 3rem}}
.auth-brand-mobile{display:flex;flex-direction:column;align-items:center;gap:.5rem;
  text-align:center;margin-bottom:2rem}
@media (min-width:1024px){.auth-brand-mobile{display:none}}
.auth-brand-mobile .row{display:flex;align-items:center;gap:.75rem}
.auth-brand-mobile .crest-sm{display:grid;place-items:center;width:3rem;height:3rem;
  border-radius:18px;background:var(--ink);color:var(--brand);font-weight:800;font-size:.9rem}
.auth-brand-mobile h1{font-size:1.25rem;font-weight:700}
.auth-brand-mobile .event{font-size:.75rem;font-weight:500;color:rgba(23,32,51,.55)}
.auth-card{width:100%;max-width:28rem;padding:1.5rem}
@media (min-width:640px){.auth-card{padding:2rem}}
.auth-card h2{font-size:1.5rem;font-weight:700}

/* ---- portal detail panel ---- */
.detail-panel{margin:1.25rem 0;border:1px solid rgba(23,32,51,.1);
  background:var(--paper);border-radius:12px;padding:.4rem .9rem}
.detail-row{display:flex;justify-content:space-between;align-items:center;gap:1rem;
  padding:.55rem 0;font-size:.875rem}
.detail-row+.detail-row{border-top:1px solid rgba(23,32,51,.07)}
.detail-label{color:rgba(23,32,51,.55)}
.detail-value{font-family:var(--font-mono);font-weight:600;font-size:.8rem}

/* ---- divider + notes ---- */
.divider{display:flex;align-items:center;gap:.75rem;margin:1.35rem 0 1rem;
  color:rgba(23,32,51,.45);font-size:.7rem;font-weight:700;text-transform:uppercase;
  letter-spacing:.12em}
.divider::before,.divider::after{content:"";flex:1;border-bottom:1px solid rgba(23,32,51,.1)}
.note{margin-top:.6rem;text-align:center;font-size:.75rem;color:rgba(23,32,51,.45)}
.note code{color:rgba(23,32,51,.65)}

/* ---- success state ---- */
.done{display:flex;flex-direction:column;align-items:center;text-align:center}
.done-icon{display:grid;place-items:center;width:3.5rem;height:3.5rem;border-radius:9999px;
  background:var(--mint);color:var(--brand-ink);font-size:1.5rem;font-weight:700;
  margin-bottom:1.25rem}
.done h2{font-size:1.5rem;font-weight:700}
.done .lede{margin-top:.5rem;color:rgba(23,32,51,.6);font-size:.9rem;line-height:1.6}

/* ---- microsoft mark ---- */
.ms-mark{display:grid;grid-template-columns:1fr 1fr;grid-template-rows:1fr 1fr;
  gap:2px;width:16px;height:16px;flex-shrink:0}
.ms-mark i{display:block}
.ms-chip{display:grid;place-items:center;width:22px;height:22px;border-radius:5px;
  background:#fff;flex-shrink:0}
"""


def esc(value: object) -> str:
    import html as _html

    return _html.escape(str(value if value is not None else ""))


def signature_svg() -> str:
    """The developer signature mark (inline, inherits currentColor)."""
    return (
        '<svg viewBox="65 32 541 136" xmlns="http://www.w3.org/2000/svg" '
        'aria-hidden="true" focusable="false">'
        f'<path d="{SIGNATURE_PATH}" stroke="currentColor" stroke-width="3" '
        'fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
        "</svg>"
    )


def microsoft_mark() -> str:
    return (
        '<span class="ms-mark" aria-hidden="true">'
        '<i style="background:#f25022"></i><i style="background:#7fba00"></i>'
        '<i style="background:#00a4ef"></i><i style="background:#ffb900"></i>'
        "</span>"
    )


def credit_html(compact: bool = False) -> str:
    """Developer signature footer, matching the open-day-attendance reference."""
    cls = "credit credit-compact" if compact else "credit"
    return f"""<footer class="{cls}">
  <a href="https://casperong.is-a.dev/" target="_blank" rel="noopener noreferrer">
    {signature_svg()}
    <span class="stack">
      <span class="credit-line">Developed by Casper Ong</span>
      <span>With the help of opencode</span>
    </span>
  </a>
</footer>"""


TIMER_JS = """
(function () {
  function fmt(t) {
    t = Math.max(0, Math.floor(t));
    var h = Math.floor(t / 3600), m = Math.floor((t % 3600) / 60), s = t % 60;
    if (h) return h + "h " + m + "m";
    if (m) return m + "m " + s + "s";
    return s + "s";
  }
  function tick() {
    document.querySelectorAll("[data-countup]").forEach(function (el) {
      var v = parseInt(el.getAttribute("data-countup"), 10) + 1;
      el.setAttribute("data-countup", v);
      el.textContent = fmt(v);
    });
    document.querySelectorAll("[data-countdown]").forEach(function (el) {
      var v = parseInt(el.getAttribute("data-countdown"), 10) - 1;
      el.setAttribute("data-countdown", v);
      el.textContent = fmt(v);
    });
  }
  setInterval(tick, 1000);
})();
"""


def timer_script() -> str:
    """Inline script that ticks [data-countup] / [data-countdown] elements."""
    return f"<script>{TIMER_JS}</script>"


def page_shell(title: str, body: str, *, credit: bool = True,
               compact_credit: bool = False, wrap: bool = True,
               extra_css: str = "") -> str:
    inner = f'<div class="wrap">{body}</div>' if wrap else body
    footer = credit_html(compact=compact_credit) if credit else ""
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(title)}</title>
<style>{DESIGN_CSS}{extra_css}</style>
</head><body>{inner}{footer}</body></html>"""
