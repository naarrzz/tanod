"""Set up a demo dashboard for presentations (simulated data, dry run).

    python -m dashboard.demo            # build data/demo.db, make accounts, start on http://localhost:8000
    python -m dashboard.demo --reset    # rebuild the demo data (keeps the accounts)
    python -m dashboard.demo --cameras 3   # demo with 3 cameras (kept until changed)
    python -m dashboard.demo --lan      # also HTTPS on the Wi-Fi: open https://<mac-ip>:8443/cam
                                        # on a phone to use it as the camera

Three views for the defense: the admin dashboard (a team account), the user
dashboard (the owner account, in a private window) and the attacker (this
terminal). While the demo runs, from a second terminal:

    python -m dashboard.demo --attack scan          # A1, see --help for the list
    python -m dashboard.demo --attack rejoin        # the blocked attacker changes its IP and tries again
    python -m dashboard.demo --attack leak --camera 2

Each attack runs through the real rules, models and decision logic on
simulated traffic, prints what Suricata alone, the Isolation Forest and the
binding check caught, records what TANOD did, and sends the Telegram alert.
The camera is never cut off: TANOD blocks the attacker.

Accounts are created once and saved in data/demo_accounts.txt (data/ is
gitignored, so the passwords never reach the repo).
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
MEMBERS = [("narz", "Narz Alcaide", "admin"), ("rod", "Rod Dela Cruz", "admin"),
           ("christian", "Christian Famador", "admin"), ("owner", "Camera owner", "user")]


def extra_cameras(n: int):
    """Cameras 3..n for the demo (the thesis setup has one Wi-Fi camera and the wired CCTV)."""
    from gateway.registry import Device
    return [Device(f"IP Camera {i}", f"aa:bb:cc:00:01:{i:02x}", f"192.168.50.{19 + i}", "camera", "wifi")
            for i in range(3, n + 1)]


def demo_cameras_registry(n: int):
    from gateway.registry import Registry, demo_registry
    reg = demo_registry()
    devs = list(reg.devices.values())[:max(n, 1)] + extra_cameras(n)
    return Registry(devs, str(reg.lan), reg.gateway_ip, reg.gateway_mac, reg.viewers)


def build_data(path: Path, cameras: int = 1) -> None:
    """Fresh cameras plus one earlier, already-unblocked attack so the log is not empty."""
    from gateway import simulate

    conn = db.connect(path)
    conn.executescript("DELETE FROM events; DELETE FROM devices;")
    conn.commit()
    with contextlib.redirect_stdout(io.StringIO()):
        simulate.main(["--db", str(path)])
    conn = db.connect(path)
    now = time.time()
    rows = conn.execute("SELECT id FROM events ORDER BY id").fetchall()
    keep = rows[:1]  # the A1 port scan block, shown as handled earlier today
    conn.execute(f"DELETE FROM events WHERE id NOT IN ({','.join(str(r['id']) for r in keep) or 0})")
    for r in keep:
        conn.execute("UPDATE events SET ts=?, released_at=? WHERE id=?", (now - 3 * 3600, now - 3 * 3600 + 600, r["id"]))
        conn.execute("INSERT INTO events (ts, kind, target_ip, target_mac, victim_ip, source, reason) "
                     "SELECT ?, 'release', target_ip, target_mac, victim_ip, 'user', 'Unblocked by owner' "
                     "FROM events WHERE id=?", (now - 3 * 3600 + 600, r["id"]))
    reg = demo_cameras_registry(cameras)
    conn.execute(f"DELETE FROM devices WHERE ip NOT IN ({','.join(repr(ip) for ip in reg.devices)})")
    for d in reg.devices.values():
        db.upsert_device(conn, d.name, d.mac, d.ip, d.kind, d.link)
    conn.execute("UPDATE devices SET status='normal'")
    for ip, risk in [("192.168.50.20", 12.9), ("192.168.50.21", 14.2)]:
        conn.execute("UPDATE devices SET last_risk=? WHERE ip=?", (risk, ip))
    conn.commit()


def _attacks():
    from gateway.simulate import ATTACKS
    return {**ATTACKS, "rejoin": ("A1b", "Blocked attacker changes its IP and scans again", "C")}


ATTACKS = _attacks()


def run_attack(path: Path, which: str, camera: int = 1, say=print) -> bool:
    """Run one attack through the real rules, models and decision logic, then record it now.
    Returns True when TANOD blocked or alerted. Messages go to say() (print, or the dashboard)."""
    import random

    from alerts import telegram
    from gateway import simulate as S
    from gateway.enforce import Enforcer

    conn = db.connect(path)
    n = max(conn.execute("SELECT COUNT(*) FROM devices WHERE kind='camera'").fetchone()[0], 1)
    if not 1 <= camera <= n:
        say(f"There {'is' if n == 1 else 'are'} {n} camera{'s' if n > 1 else ''} in the demo. "
            f"Start it with --cameras {camera} to have camera {camera}.")
        return False
    reg = demo_cameras_registry(n)
    cam = list(reg.devices)[camera - 1]
    code, name, cia = ATTACKS[which]
    say(f"{code} {name}  [CIA: {cia}]  (simulated traffic, dry run)")
    say(f"Target: {reg.get(cam).name} ({cam})")

    active = db.active_responses(conn)
    blocked_macs = {e["target_mac"] for e in active if e["kind"] == "block" and e["target_mac"]}
    if which == "rejoin":
        if S.ATTACKER_MAC not in blocked_macs:
            say("The attacker is not blocked yet. Run --attack scan first.")
            return False
        say(f"Attacker {S.ATTACKER_MAC} drops {S.ATTACKER} and takes {S.ATTACKER_NEW_IP}, then scans again.")
        say(f"  Every packet from MAC {S.ATTACKER_MAC} is already dropped (nftables ether saddr, hostapd deny list),")
        say("  so the new IP gets nothing through. TANOD adds the new IP to the block list too.")
        ip_mac = next(e for e in active if e["target_mac"] == S.ATTACKER_MAC)
        db.record_event(conn, "block", S.ATTACKER_NEW_IP, f"Blocked MAC {S.ATTACKER_MAC} came back as {S.ATTACKER_NEW_IP}",
                        "binding_check", None, {"previous_ip": ip_mac["target_ip"], "mac": S.ATTACKER_MAC},
                        target_mac=S.ATTACKER_MAC, victim_ip=cam)
        Enforcer(dry_run=True).block(S.ATTACKER_NEW_IP, S.ATTACKER_MAC)
        return True
    if which in ("scan", "brute", "flood", "arp", "view") and S.ATTACKER_MAC in blocked_macs:
        say(f"The attacker ({S.ATTACKER_MAC}) is already blocked, so its packets never reach the camera.")
        say("Unblock it on the dashboard first, or reset the demo.")
        return False

    rng = random.Random()
    bank, baselines = S.train_bank(reg, random.Random(7))
    t0 = 100_000.0
    res = S.run_scenario(S.build_scenario(which, rng, reg, cam, t0 + 10), reg, bank, baselines, rng, t0)
    say(f"  Suricata only (Setup A):  {S.fmt(res.first(res.suricata))}")
    say(f"  Isolation Forest:         {S.fmt(res.first(res.if_actions))}")
    say(f"  IP-MAC binding check:     {S.fmt(res.first(res.binding_actions))}")
    if not res.actions:
        say("  TANOD (Setup B): nothing detected. This attack is a known gap (see the paper's limitations).")
        return False
    enforcer = Enforcer(dry_run=True)
    for act in res.actions:
        if act.kind == "block":
            enforcer.block(act.target, act.mac)
        db.record_event(conn, act.kind, act.key, act.reason, act.source, act.risk, act.evidence,
                        target_mac=act.mac, victim_ip=act.victim)
        who = act.key + (f" (MAC {act.mac})" if act.mac and act.target else "")
        say(f"  TANOD: {'block ' + who if act.kind == 'block' else 'alert, no attacker to block'} via {act.source}"
            + (f", risk {act.risk}" if act.risk is not None else "")
            + f", {max(act.ts - res.attack_start, 0):.0f} s after the attack started")
    # one Telegram message per attack, even when several addresses were blocked
    first = res.actions[0]
    blocks = [a for a in res.actions if a.kind == "block"]
    reason = first.reason + (f" ({len(blocks)} addresses blocked)" if len(blocks) > 1 else "")
    camera_name = reg.get(first.victim).name if reg.get(first.victim) else first.victim
    say("  " + telegram.notify(first.kind, camera_name, first.key, reason, first.risk))
    if blocks:
        say("  Only the attacker was blocked; the camera stays on the network.")
    return True


def ensure_accounts(path: Path) -> None:
    """Create the demo accounts that are missing. Existing passwords are never changed."""
    conn = db.connect(path)
    have = {u["username"] for u in db.list_users(conn)}
    lines = ACCOUNTS_FILE.read_text().splitlines() if ACCOUNTS_FILE.exists() else [
        "TANOD demo dashboard accounts (http://localhost:8000). Do not commit this file.",
        "admin = research team, user = camera owner (open it in a private window).", ""]
    added = False
    for user, name, role in MEMBERS:
        if user in have:
            if db.get_role(conn, user) != role:
                conn.execute("UPDATE users SET role=? WHERE username=?", (role, user))
                conn.commit()
            continue
        pw = generate_password()
        db.set_user(conn, user, pw, name, role)
        lines.append(f"{user:10s} {role:6s} {pw}")
        added = True
    if added or not ACCOUNTS_FILE.exists():
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


def serve(port: int, host: str, lan: bool, lan_port: int, buttons: bool = False) -> None:
    import asyncio
    import socket

    import uvicorn
    if buttons:
        os.environ["TANOD_DEMO"] = "1"  # shows the Demo controls (attack picker, Reset, QR code)
    for h, p in [(host, port)] + ([("0.0.0.0", lan_port)] if lan else []):
        with socket.socket() as sk:
            if sk.connect_ex(("127.0.0.1", p)) == 0:
                raise SystemExit(f"Port {p} is already in use, most likely by another demo that is still running. "
                                 f"Stop it with Ctrl+C in its terminal (or: kill $(lsof -tiTCP:{p} -sTCP:LISTEN)), "
                                 "then run this again.")
    configs = [uvicorn.Config("dashboard.app:app", host=host, port=port, log_level="warning")]
    # Every camera is a phone (or TANOD_CAMERA_URL); the demo never uses this computer's own camera.
    os.environ["TANOD_PHONE_CAMERA"] = "1"
    if lan:
        ip = lan_ip()
        key, crt = make_cert(ip)
        os.environ["TANOD_LAN_URL"] = f"https://{ip}:{lan_port}"
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
    ap.add_argument("--buttons", action="store_true",
                    help="show Demo controls on the dashboard (attack picker, Reset, QR code for the phone)")
    ap.add_argument("--cameras", type=int, default=None, help="how many cameras the demo has (1 to 9)")
    ap.add_argument("--camera", type=int, default=1, help="which camera --attack targets (1 = the first)")
    ap.add_argument("--attack", choices=list(ATTACKS),
                    help="run an attack against the running demo: " + ", ".join(f"{k} ({v[0]})" for k, v in ATTACKS.items()))
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
                        else "phones on the /cam page (start with --lan); this laptop's camera is not used"))
    print("Telegram: " + ("on" if telegram.configured() else "off (fill in .env to turn it on)"))
    print(f"Dashboard on this Mac: http://localhost:{args.port}  (Ctrl+C to stop)")
    serve(args.port, args.host, args.lan, args.lan_port, args.buttons)


if __name__ == "__main__":
    main()
