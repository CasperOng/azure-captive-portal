#!/usr/bin/env bash
# Consistent, permission-tight backup of portal.db (accounts, devices, profiles).
# Uses SQLite's online backup API so it is safe while the apps are running.
set -euo pipefail

DB="${PORTAL_DB:-/opt/captive-portal/portal.db}"
DEST="${BACKUP_DIR:-/var/backups/captive-portal}"
KEEP="${BACKUP_KEEP:-14}"

mkdir -p "$DEST"
chmod 700 "$DEST"

/opt/captive-portal/venv/bin/python - "$DB" "$DEST" "$KEEP" <<'PY'
import datetime
import os
import sqlite3
import sys

db, dest, keep = sys.argv[1], sys.argv[2], int(sys.argv[3])
stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
target = os.path.join(dest, f"portal-{stamp}.db")

src = sqlite3.connect(db)
dst = sqlite3.connect(target)
with dst:
    src.backup(dst)
dst.close()
src.close()
os.chmod(target, 0o600)

backups = sorted(
    (f for f in os.listdir(dest) if f.startswith("portal-") and f.endswith(".db")),
    reverse=True,
)
for stale in backups[keep:]:
    os.remove(os.path.join(dest, stale))

print(f"backed up to {target} ({len(backups[:keep])} kept)")
PY
