"""Set up a demo dashboard for presentations (simulated data, dry run).

    python -m dashboard.demo            # build data/demo.db, make accounts, start on http://localhost:8000
    python -m dashboard.demo --reset    # rebuild the demo data (keeps the accounts)
    python -m dashboard.demo --cameras 4   # demo with 4 cameras (kept until changed)
    python -m dashboard.demo --lan      # also HTTPS on the Wi-Fi: open https://<mac-ip>:8443/cam
                                        # on a phone to use it as the camera

While the demo runs, from a second terminal:
    python -m dashboard.demo --attack leak   # camera starts sending video to an unknown server
                                             # -> camera quarantined, live feed cut, Telegram alert
    python -m dashboard.demo --attack leak --camera 2   # same, on camera 2
    python -m dashboard.demo --attack scan   # outside laptop port-scans the camera
                                             # -> attacker blocked, feed keeps running

The camera panel uses TANOD_CAMERA_URL (an MJPEG stream from a phone camera
app) if it is set in .env; otherwise it uses a camera on the laptop, which
can be an iPhone through Continuity Camera. "leak" is an exhibit scenario, not
one of the six thesis tests: in the thesis the camera is only an attack target.

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


def extra_cameras(n: int):
    """Cameras 2..n for the demo (the thesis setup has one camera)."""
    from gateway.registry import Device
    return [Device(f"IP Camera {i}", f"aa:bb:cc:00:01:{i:02x}", f"192.168.50.{19 + i}", "camera")
            for i in range(2, n + 1)]


def demo_cameras_registry(n: int):
    from gateway.registry import Registry, demo_registry
    reg = demo_registry()
    return Registry(list(reg.devices.values()) + extra_cameras(n))


def build_data(path: Path, cameras: int = 1) -> None:
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
    conn.execute("DELETE FROM devices WHERE kind='camera' AND ip <> '192.168.50.20'")
    for d in extra_cameras(cameras):
        db.upsert_device(conn, d.name, d.mac, d.ip, d.kind)
    if cameras > 1:
        conn.execute("UPDATE devices SET name='IP Camera 1' WHERE ip='192.168.50.20'")
    conn.execute("UPDATE devices SET status='normal' WHERE ip <> '192.168.50.11'")
    for ip, risk in [("192.168.50.12", 18.4), ("192.168.50.13", 21.7), ("192.168.50.20", 12.9)]:
        conn.execute("UPDATE devices SET last_risk=? WHERE ip=?", (risk, ip))
    conn.commit()


ATTACKS = {
    "leak": "Camera sends a copy of its video to an unknown server",
    "scan": "Outside laptop port-scans the camera",
}


def run_attack(path: Path, which: str, camera: int = 1) -> None:
    """Run one camera scenario through the real models and decision logic, then record it now."""
    import random

    from alerts import telegram
    from gateway import simulate as S
    from gateway.decision import DecisionEngine, SuricataAlert
    from gateway.enforce import Enforcer

    rng = random.Random()
    conn = db.connect(path)
    n = max(conn.execute("SELECT COUNT(*) FROM devices WHERE kind='camera'").fetchone()[0], 1)
    if not 1 <= camera <= n:
        print(f"There {'is' if n == 1 else 'are'} {n} camera{'s' if n > 1 else ''} in the demo. "
              f"Start it with --cameras {camera} to have camera {camera}.")
        return
    reg = demo_cameras_registry(n)
    cam = [d.ip for d in reg.devices.values() if d.kind == "camera"][camera - 1]
    if which == "leak" and any(e["target_ip"] == cam for e in db.active_responses(db.connect(path))):
        print(f"Camera {camera} is already cut off, so TANOD has nothing new to do (and sends no new alert).")
        print("Release it on the dashboard first, or run: python -m dashboard.demo --reset")
        return
    print(f"Scenario: {ATTACKS[which]} (simulated traffic, dry run)")
    print(f"Target: {db.device_by_ip(conn, cam)['name']} ({cam})")
    bank, baselines = S.train_bank(reg, random.Random(7))
    t0 = 100_000.0
    attack = S.camera_leak(rng, cam, t0 + 10) if which == "leak" else S.t3_port_scan(rng, cam, t0 + 10)
    actions = S.run_scenario(which, attack, reg, bank, baselines, rng, t0, DecisionEngine(reg))
    if not actions and which == "leak":
        # The Isolation Forest can saturate (see the open design points); the local Suricata
        # rule for camera video sent to an unapproved address catches it about 5 s in.
        first = next(p for p in attack if p.src == cam)
        alert = SuricataAlert(t0 + 15, 1, cam, first.dst,
                              "TANOD local: camera video sent to an unapproved address", 9000010)
        actions = S.run_scenario(which, attack, reg, bank, baselines, rng, t0, DecisionEngine(reg), [alert])
    if not actions:
        print("TANOD took no action this time. Run it again.")
        return
    enforcer = Enforcer(dry_run=True)
    for act in actions:
        dev = db.device_by_ip(conn, act.target)
        new = (act.evidence or {}).get("new_destinations") or []
        if act.kind == "quarantine" and new:
            act.reason += f"; it started sending data to a new address ({', '.join(map(str, new[:2]))})"
        enforcer.quarantine(reg.get(act.target)) if act.kind == "quarantine" else enforcer.block(act.target)
        db.record_event(conn, act.kind, act.target, act.reason, act.source, act.risk, act.evidence,
                        target_mac=dev["mac"] if dev else None)
        name = dev["name"] if dev else "Unregistered client"
        print(f"  {act.kind} {name} ({act.target}) via {act.source}" + (f", risk {act.risk}" if act.risk is not None else "") + ", "
              f"{max(act.ts - t0 - 10, 0):.0f} s after the attack started")
        print("  " + telegram.notify(act.kind, name, act.target, act.reason, act.risk))


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


def lan_ip() -> str:
    """This Mac's address on the Wi-Fi (no packet is sent)."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def make_cert(ip: str) -> tuple[str, str]:
    """Self-signed certificate for this Mac's Wi-Fi address (phones only allow the camera on HTTPS)."""
    import subprocess
    d = Path("data/certs")
    d.mkdir(parents=True, exist_ok=True)
    key, crt, tag = d / "demo.key", d / "demo.crt", d / "ip.txt"
    if not (crt.exists() and tag.exists() and tag.read_text() == ip):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365",
                        "-keyout", str(key), "-out", str(crt), "-subj", "/CN=TANOD demo",
                        "-addext", f"subjectAltName=IP:{ip},DNS:localhost"],
                       check=True, capture_output=True)
        os.chmod(key, 0o600)
        tag.write_text(ip)
    return str(key), str(crt)


def serve(port: int, host: str, lan: bool, lan_port: int) -> None:
    import asyncio
    import socket

    import uvicorn
    for h, p in [(host, port)] + ([("0.0.0.0", lan_port)] if lan else []):
        with socket.socket() as sk:
            if sk.connect_ex(("127.0.0.1", p)) == 0:
                raise SystemExit(f"Port {p} is already in use, most likely by another demo that is still running. "
                                 f"Stop it with Ctrl+C in its terminal (or: kill $(lsof -tiTCP:{p} -sTCP:LISTEN)), "
                                 "then run this again.")
    configs = [uvicorn.Config("dashboard.app:app", host=host, port=port, log_level="warning")]
    if lan:
        os.environ["TANOD_PHONE_CAMERA"] = "1"  # every camera is a phone; never fall back to the laptop camera
        ip = lan_ip()
        key, crt = make_cert(ip)
        configs.append(uvicorn.Config("dashboard.app:app", host="0.0.0.0", port=lan_port, log_level="warning",
                                      ssl_keyfile=key, ssl_certfile=crt))
        print(f"Phone camera: on each phone (same Wi-Fi), open  https://{ip}:{lan_port}/cam  and pick a camera")
        print("  The phone will warn that the certificate is not trusted; tap Show Details > visit this website.")
        print(f"  Other devices can open the dashboard at https://{ip}:{lan_port}")

    async def run():
        await asyncio.gather(*(uvicorn.Server(c).serve() for c in configs))

    asyncio.run(run())


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reset", action="store_true", help="rebuild the demo data, then exit")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--lan", action="store_true",
                    help="also serve HTTPS on the Wi-Fi so a phone can be the camera (open /cam on it)")
    ap.add_argument("--lan-port", type=int, default=8443)
    ap.add_argument("--cameras", type=int, default=None, help="how many cameras the demo has (1 to 9)")
    ap.add_argument("--camera", type=int, default=1, help="which camera --attack targets (1 = the first)")
    ap.add_argument("--attack", choices=sorted(ATTACKS), help="run a camera scenario against the running demo")
    args = ap.parse_args(argv)

    from alerts import telegram
    telegram.load_env()
    if args.attack:
        run_attack(DEMO_DB, args.attack, args.camera)
        return

    if args.cameras is None:  # keep what the demo had
        args.cameras = max(db.connect(DEMO_DB).execute(
            "SELECT COUNT(*) FROM devices WHERE kind='camera'").fetchone()[0], 1)
    if not 1 <= args.cameras <= 9:
        raise SystemExit("--cameras must be 1 to 9")
    build_data(DEMO_DB, args.cameras)
    ensure_accounts(DEMO_DB)
    print(f"Demo data ready in {DEMO_DB}. Accounts are in {ACCOUNTS_FILE.resolve()}")
    if args.reset:
        return
    os.environ["TANOD_DB"] = str(DEMO_DB)
    os.environ["TANOD_DRY_RUN"] = "1"
    print("Camera: " + (os.environ["TANOD_CAMERA_URL"] if os.environ.get("TANOD_CAMERA_URL")
                        else "phone page (--lan) or a camera on this laptop"))
    print("Telegram: " + ("on" if telegram.configured() else "off (fill in .env to turn it on)"))
    print(f"Dashboard on this Mac: http://localhost:{args.port}  (Ctrl+C to stop)")
    serve(args.port, args.host, args.lan, args.lan_port)


if __name__ == "__main__":
    main()
