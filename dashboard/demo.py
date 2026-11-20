"""Set up a demo dashboard for presentations (simulated data, dry run).

    python -m dashboard.demo            # build data/demo.db, make accounts, start on http://localhost:8000
    python -m dashboard.demo --reset    # rebuild the demo data (keeps the accounts)

The demo shows one hacked ESP32 node in quarantine and one blocked outside
attacker, so the panel can watch a Release from start to finish. Accounts
for the members are created once and saved in data/demo_accounts.txt
(data/ is gitignored, so the passwords never reach the repo).
"""
from __future__ import annotations

import argparse
import contextlib
import io
import os
import time
from pathlib import Path

from . import db
from .users import generate_password

DEMO_DB = Path("data/demo.db")
ACCOUNTS_FILE = Path("data/demo_accounts.txt")
MEMBERS = [("narz", "Narz Alcaide"), ("rod", "Rod Dela Cruz"), ("christian", "Christian Famador")]


def build_data(path: Path) -> None:
    """Fresh devices and events from the simulator, then trimmed to one clear story."""
    from gateway import simulate

    conn = db.connect(path)
    conn.executescript("DELETE FROM events; DELETE FROM devices;")
    conn.commit()
    with contextlib.redirect_stdout(io.StringIO()):
        simulate.main(["--db", str(path)])
    conn = db.connect(path)
    now = time.time()
    # Keep: Node 1 quarantined (T6 hacked scan) and the Suricata block of the outside attacker.
    keep = conn.execute(
        """SELECT id FROM events WHERE (kind='quarantine' AND target_ip='192.168.50.11')
           OR (kind='block' AND source='suricata')""").fetchall()
    keep_ids = {r["id"] for r in keep}
    for r in conn.execute("SELECT id, kind, target_ip FROM events").fetchall():
        if r["id"] not in keep_ids:
            conn.execute("UPDATE events SET released_at=? WHERE id=?", (now - 300, r["id"]))
    # Spread the times out so the log reads like a real afternoon.
    rows = conn.execute("SELECT id FROM events ORDER BY id").fetchall()
    for i, r in enumerate(rows):
        conn.execute("UPDATE events SET ts=? WHERE id=?", (now - 60 * (len(rows) - i) * 7, r["id"]))
    conn.execute("UPDATE devices SET status='normal' WHERE ip <> '192.168.50.11'")
    for ip, risk in [("192.168.50.12", 18.4), ("192.168.50.13", 21.7), ("192.168.50.20", 12.9)]:
        conn.execute("UPDATE devices SET last_risk=? WHERE ip=?", (risk, ip))
    conn.commit()


def ensure_accounts(path: Path) -> None:
    conn = db.connect(path)
    if db.list_users(conn) and ACCOUNTS_FILE.exists():
        return
    lines = ["TANOD demo dashboard accounts (http://localhost:8000). Do not commit this file.", ""]
    for user, name in MEMBERS:
        pw = generate_password()
        db.set_user(conn, user, pw, name)
        lines.append(f"{user:10s} {pw}")
    ACCOUNTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    ACCOUNTS_FILE.write_text("\n".join(lines) + "\n")
    os.chmod(ACCOUNTS_FILE, 0o600)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reset", action="store_true", help="rebuild the demo data, then exit")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)))
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args(argv)

    build_data(DEMO_DB)
    ensure_accounts(DEMO_DB)
    print(f"Demo data ready in {DEMO_DB}. Accounts are in {ACCOUNTS_FILE.resolve()}")
    if args.reset:
        return
    os.environ["TANOD_DB"] = str(DEMO_DB)
    os.environ["TANOD_DRY_RUN"] = "1"
    import uvicorn
    print(f"Open http://localhost:{args.port}  (Ctrl+C to stop)")
    uvicorn.run("dashboard.app:app", host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
