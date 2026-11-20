"""SQLite storage for devices and events."""
from __future__ import annotations

import json
import sqlite3
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
"""


def connect(path: str | Path) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


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
