"""SQLite storage for devices and events."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    mac TEXT NOT NULL UNIQUE,
    ip TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL DEFAULT 'camera',
    link TEXT NOT NULL DEFAULT 'wifi',          -- wifi | wired
    status TEXT NOT NULL DEFAULT 'normal',      -- normal | attacked
    last_risk REAL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,          -- block | alert | release
    target_ip TEXT NOT NULL,     -- attacker IP, or its MAC when no IP is known; the camera for alerts
    target_mac TEXT,             -- attacker MAC (LAN attackers)
    victim_ip TEXT,              -- the camera that was attacked
    device_id INTEGER REFERENCES devices(id),
    source TEXT,                 -- suricata | isolation_forest | binding_check | admin | user
    reason TEXT,
    risk REAL,
    evidence TEXT,               -- JSON
    released_at REAL
);
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    display_name TEXT,
    role TEXT NOT NULL DEFAULT 'user',  -- admin (the research team) | user (camera owner)
    pw_hash TEXT NOT NULL        -- pbkdf2_sha256$iterations$salt$hash
);
"""
ROLES = ("admin", "user")

# columns added after the first version; older databases get them on connect
MIGRATIONS = {
    "devices": [("link", "TEXT NOT NULL DEFAULT 'wifi'")],
    "events": [("victim_ip", "TEXT")],
    "users": [("role", "TEXT NOT NULL DEFAULT 'admin'")],  # accounts made before roles were the team's
}


def connect(path: str | Path) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # readers do not block the writer
    conn.executescript(SCHEMA)
    for table, cols in MIGRATIONS.items():
        have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in cols:
            if name not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
    conn.commit()
    return conn


class ThreadConn:
    """One SQLite connection per thread, used like a connection.

    The dashboard serves many requests at once (camera streams, phone frames,
    status checks), and one shared sqlite3 connection is not safe for that."""

    def __init__(self, path: str | Path):
        self.path = path
        self._local = threading.local()
        self._get()  # create the file and tables now

    def _get(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = self._local.conn = connect(self.path)
        return c

    def __getattr__(self, name):
        return getattr(self._get(), name)


def upsert_device(conn, name, mac, ip, kind="camera", link="wifi") -> int:
    conn.execute(
        """INSERT INTO devices (name, mac, ip, kind, link) VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(mac) DO UPDATE SET name=excluded.name, ip=excluded.ip, kind=excluded.kind,
             link=excluded.link""",
        (name, mac.lower(), ip, kind, link),
    )
    conn.commit()
    return conn.execute("SELECT id FROM devices WHERE mac=?", (mac.lower(),)).fetchone()["id"]


def list_devices(conn):
    return conn.execute("SELECT * FROM devices ORDER BY id").fetchall()


def device_by_ip(conn, ip):
    return conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()


def record_event(conn, kind, target_ip, reason, source, risk=None, evidence=None, target_mac=None, ts=None,
                 victim_ip=None) -> int:
    """target_ip is the attacker (IP, or MAC when no IP is known); victim_ip is the camera."""
    dev = device_by_ip(conn, victim_ip or target_ip)
    cur = conn.execute(
        """INSERT INTO events (ts, kind, target_ip, target_mac, victim_ip, device_id, source, reason, risk, evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (ts or time.time(), kind, target_ip, target_mac, victim_ip, dev["id"] if dev else None, source, reason, risk,
         json.dumps(evidence or {}, default=str)),
    )
    if dev and kind in ("block", "alert"):
        conn.execute("UPDATE devices SET status='attacked', last_risk=COALESCE(?, last_risk) WHERE id=?",
                     (risk, dev["id"]))
    conn.commit()
    return cur.lastrowid


def list_events(conn, limit=50):
    return conn.execute(
        """SELECT e.*, d.name AS device_name FROM events e LEFT JOIN devices d ON d.id = e.device_id
           ORDER BY e.ts DESC LIMIT ?""", (limit,)).fetchall()


def get_event(conn, event_id):
    return conn.execute(
        "SELECT e.*, d.name AS device_name FROM events e LEFT JOIN devices d ON d.id = e.device_id WHERE e.id=?",
        (event_id,)).fetchone()


def active_responses(conn):
    """Blocks and alerts that have not been released or dismissed yet."""
    return conn.execute(
        """SELECT e.*, d.name AS device_name FROM events e LEFT JOIN devices d ON d.id = e.device_id
           WHERE e.kind IN ('block', 'alert') AND e.released_at IS NULL ORDER BY e.ts DESC""").fetchall()


def mark_released(conn, target) -> int:
    now = time.time()
    victims = [r["victim_ip"] for r in conn.execute(
        "SELECT victim_ip FROM events WHERE target_ip=? AND kind IN ('block','alert') AND released_at IS NULL",
        (target,))]
    cur = conn.execute(
        "UPDATE events SET released_at=? WHERE target_ip=? AND kind IN ('block','alert') AND released_at IS NULL",
        (now, target))
    for v in set(filter(None, victims)):
        left = conn.execute("SELECT 1 FROM events WHERE victim_ip=? AND kind IN ('block','alert') "
                            "AND released_at IS NULL", (v,)).fetchone()
        if not left:
            conn.execute("UPDATE devices SET status='normal' WHERE ip=?", (v,))
    conn.commit()
    return cur.rowcount


# --- dashboard accounts ---------------------------------------------------
PBKDF2_ITERATIONS = 200_000


def hash_password(password: str, salt: str | None = None, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations).hex()
    return f"pbkdf2_sha256${iterations}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt, _digest = stored.split("$")
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(password, salt, int(iterations)), stored)


def set_user(conn, username: str, password: str, display_name: str | None = None, role: str | None = None) -> None:
    """Create an account, or change its password (and name/role when given)."""
    if role is not None and role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    username = username.lower()
    row = conn.execute("SELECT display_name, role FROM users WHERE username=?", (username,)).fetchone()
    name = display_name or (row["display_name"] if row else username)
    role = role or (row["role"] if row else "user")
    conn.execute(
        """INSERT INTO users (username, display_name, role, pw_hash) VALUES (?, ?, ?, ?)
           ON CONFLICT(username) DO UPDATE SET display_name=excluded.display_name, role=excluded.role,
             pw_hash=excluded.pw_hash""",
        (username, name, role, hash_password(password)))
    conn.commit()


def get_role(conn, username: str) -> str | None:
    row = conn.execute("SELECT role FROM users WHERE username=?", (username.lower(),)).fetchone()
    return row["role"] if row else None


def delete_user(conn, username: str) -> int:
    cur = conn.execute("DELETE FROM users WHERE username=?", (username.lower(),))
    conn.commit()
    return cur.rowcount


def list_users(conn):
    return conn.execute("SELECT username, display_name, role FROM users ORDER BY role, username").fetchall()


def check_user(conn, username: str, password: str) -> bool:
    row = conn.execute("SELECT pw_hash FROM users WHERE username=?", (username.lower(),)).fetchone()
    return bool(row) and verify_password(password, row["pw_hash"])
