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
    kind TEXT NOT NULL DEFAULT 'esp32',
    relay_channel INTEGER,
    relay_cutoff_enabled INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'normal',      -- normal | quarantined
    last_risk REAL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,          -- quarantine | block | release | info
    target_ip TEXT NOT NULL,
    target_mac TEXT,
    device_id INTEGER REFERENCES devices(id),
    source TEXT,                 -- suricata | isolation_forest | owner
    reason TEXT,
    risk REAL,
    evidence TEXT,               -- JSON
    released_at REAL
);
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    display_name TEXT,
    pw_hash TEXT NOT NULL        -- pbkdf2_sha256$iterations$salt$hash
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # readers do not block the writer
    conn.executescript(SCHEMA)
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


def upsert_device(conn, name, mac, ip, kind="esp32", relay_channel=None, relay_cutoff_enabled=False) -> int:
    conn.execute(
        """INSERT INTO devices (name, mac, ip, kind, relay_channel, relay_cutoff_enabled)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(mac) DO UPDATE SET name=excluded.name, ip=excluded.ip, kind=excluded.kind,
             relay_channel=excluded.relay_channel, relay_cutoff_enabled=excluded.relay_cutoff_enabled""",
        (name, mac.lower(), ip, kind, relay_channel, int(relay_cutoff_enabled)),
    )
    conn.commit()
    return conn.execute("SELECT id FROM devices WHERE mac=?", (mac.lower(),)).fetchone()["id"]


def list_devices(conn):
    return conn.execute("SELECT * FROM devices ORDER BY id").fetchall()


def device_by_ip(conn, ip):
    return conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()


def record_event(conn, kind, target_ip, reason, source, risk=None, evidence=None, target_mac=None, ts=None) -> int:
    dev = device_by_ip(conn, target_ip)
    cur = conn.execute(
        """INSERT INTO events (ts, kind, target_ip, target_mac, device_id, source, reason, risk, evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (ts or time.time(), kind, target_ip, target_mac, dev["id"] if dev else None, source, reason, risk,
         json.dumps(evidence or {}, default=str)),
    )
    if dev and kind == "quarantine":
        conn.execute("UPDATE devices SET status='quarantined', last_risk=? WHERE id=?", (risk, dev["id"]))
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
    """Quarantines and blocks that have not been released yet."""
    return conn.execute(
        """SELECT e.*, d.name AS device_name FROM events e LEFT JOIN devices d ON d.id = e.device_id
           WHERE e.kind IN ('quarantine', 'block') AND e.released_at IS NULL ORDER BY e.ts DESC""").fetchall()


def mark_released(conn, target_ip) -> int:
    now = time.time()
    cur = conn.execute(
        "UPDATE events SET released_at=? WHERE target_ip=? AND kind IN ('quarantine','block') AND released_at IS NULL",
        (now, target_ip))
    conn.execute("UPDATE devices SET status='normal' WHERE ip=?", (target_ip,))
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


def set_user(conn, username: str, password: str, display_name: str | None = None) -> None:
    conn.execute(
        """INSERT INTO users (username, display_name, pw_hash) VALUES (?, ?, ?)
           ON CONFLICT(username) DO UPDATE SET display_name=excluded.display_name, pw_hash=excluded.pw_hash""",
        (username.lower(), display_name or username, hash_password(password)))
    conn.commit()


def delete_user(conn, username: str) -> int:
    cur = conn.execute("DELETE FROM users WHERE username=?", (username.lower(),))
    conn.commit()
    return cur.rowcount


def list_users(conn):
    return conn.execute("SELECT username, display_name FROM users ORDER BY username").fetchall()


def check_user(conn, username: str, password: str) -> bool:
    row = conn.execute("SELECT pw_hash FROM users WHERE username=?", (username.lower(),)).fetchone()
    return bool(row) and verify_password(password, row["pw_hash"])
