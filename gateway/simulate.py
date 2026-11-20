"""Laptop simulation of the whole pipeline with synthetic packet metadata.

No packets are sent anywhere: this only generates header records in memory,
trains the per-device models, replays the Table 6 scenarios through the
decision logic, and writes the results to the dashboard database.

    python -m gateway.simulate                 # writes data/tanod.db
    python -m gateway.simulate --send-alerts   # also posts to the local mock endpoint
"""
from __future__ import annotations

import argparse
import logging
import random

import numpy as np

from .decision import Action, DecisionEngine, SuricataAlert
from .enforce import Enforcer
from .features import Packet, extract_windows, learn_baseline_destinations
from .model import ModelBank
from .registry import Registry, demo_registry

SERVER = "10.10.0.5"  # simulated internet server laptop
VIEWER = "10.10.0.7"  # monitoring laptop that views the camera
GATEWAY = "192.168.50.1"
ATTACKER = "192.168.50.99"  # unregistered client with a leaked passphrase
UNKNOWN_SERVER = "10.10.0.66"
C2_SERVER = "10.10.0.99"
LEAK_SERVER = "10.10.0.77"  # exhibit scenario: where a hijacked camera would send its video


# ---- normal traffic ------------------------------------------------------
def node_normal(rng: random.Random, ip: str, t0: float, t1: float) -> list[Packet]:
    out, t = [], t0 + rng.random()
    sport = rng.randint(40000, 60000)
    while t < t1:
        out.append(Packet(t, ip, SERVER, rng.randint(120, 220), "tcp", sport, 1883, ack=True))
        out.append(Packet(t + 0.02, SERVER, ip, 60, "tcp", 1883, sport, ack=True))
        if rng.random() < 0.03:
            out.append(Packet(t + 0.1, ip, GATEWAY, 70, "udp", rng.randint(1024, 65000), 53))
            out.append(Packet(t + 0.12, GATEWAY, ip, 110, "udp", 53, rng.randint(1024, 65000)))
        t += rng.uniform(0.6, 1.6)
    return out


def camera_normal(rng: random.Random, ip: str, t0: float, t1: float, pps: int = 20) -> list[Packet]:
    out, t = [], t0
    while t < t1:
        out.append(Packet(t, ip, VIEWER, rng.randint(1000, 1400), "udp", 5004, 5004))
        if rng.random() < 0.1:
            out.append(Packet(t + 0.01, VIEWER, ip, 80, "udp", 5005, 5005))
        t += rng.expovariate(pps)
    return out


def normal_traffic(rng: random.Random, reg: Registry, t0: float, t1: float) -> list[Packet]:
    pk: list[Packet] = []
    for d in reg.devices.values():
        pk += camera_normal(rng, d.ip, t0, t1) if d.kind == "camera" else node_normal(rng, d.ip, t0, t1)
    return pk


# ---- Table 6 scenarios ---------------------------------------------------
def t3_port_scan(rng, target, t0, dur=6.0):
    out = []
    for i, port in enumerate(range(1, 1001)):
        t = t0 + dur * i / 1000
        sp = rng.randint(30000, 60000)
        out.append(Packet(t, ATTACKER, target, 60, "tcp", sp, port, syn=True))
        out.append(Packet(t + 0.001, target, ATTACKER, 54, "tcp", port, sp, rst=True, ack=True))
    return out


def t4_password_guess(rng, target, t0, dur=10.0):
    out, t = [], t0
    while t < t0 + dur:
        sp = rng.randint(30000, 60000)
        out += [Packet(t, ATTACKER, target, 60, "tcp", sp, 80, syn=True),
                Packet(t + .005, target, ATTACKER, 60, "tcp", 80, sp, syn=True, ack=True),
                Packet(t + .01, ATTACKER, target, 300, "tcp", sp, 80, ack=True),
                Packet(t + .02, target, ATTACKER, 200, "tcp", 80, sp, ack=True)]
        t += 0.1
    return out


def t5_flood(rng, target, t0, dur=6.0):
    n = int(dur * 2000)
    return [Packet(t0 + dur * i / n, ATTACKER, target, 1400, "udp", rng.randint(1024, 65000), 9) for i in range(n)]


def t6_hacked_scan(rng, node, others, t0, dur=8.0):
    out = []
    targets = [(o, p) for o in others for p in range(20, 120)]
    for i, (o, p) in enumerate(targets):
        t = t0 + dur * i / len(targets)
        sp = rng.randint(30000, 60000)
        out += [Packet(t, node, o, 60, "tcp", sp, p, syn=True),
                Packet(t + .002, o, node, 54, "tcp", p, sp, rst=True, ack=True)]
    return out


def t7_upload(rng, node, t0, dur=8.0):
    sp = rng.randint(30000, 60000)
    out = [Packet(t0, node, UNKNOWN_SERVER, 60, "tcp", sp, 8080, syn=True),
           Packet(t0 + .01, UNKNOWN_SERVER, node, 60, "tcp", 8080, sp, syn=True, ack=True)]
    n = int(dur * 150)
    for i in range(n):
        t = t0 + 0.02 + dur * i / n
        out.append(Packet(t, node, UNKNOWN_SERVER, 1400, "tcp", sp, 8080, ack=True))
        if i % 4 == 0:
            out.append(Packet(t + .005, UNKNOWN_SERVER, node, 60, "tcp", 8080, sp, ack=True))
    return out


def t8_beacon(rng, node, t0, dur=12.0):
    out, t = [], t0
    while t < t0 + dur:
        sp = rng.randint(30000, 60000)
        out += [Packet(t, node, C2_SERVER, 60, "tcp", sp, 4444, syn=True),
                Packet(t + .01, C2_SERVER, node, 60, "tcp", 4444, sp, syn=True, ack=True),
                Packet(t + .02, node, C2_SERVER, 90, "tcp", sp, 4444, ack=True)]
        t += 1.0
    return out


def camera_leak(rng, cam, t0, dur=10.0):
    """Exhibit scenario (not one of the six thesis tests): the camera starts
    sending a second copy of its video to an unknown server."""
    out, t = [], t0
    sp = rng.randint(30000, 60000)
    out += [Packet(t0, cam, LEAK_SERVER, 60, "tcp", sp, 8554, syn=True),
            Packet(t0 + .01, LEAK_SERVER, cam, 60, "tcp", 8554, sp, syn=True, ack=True)]
    while t < t0 + dur:
        out.append(Packet(t, cam, LEAK_SERVER, rng.randint(1200, 1400), "tcp", sp, 8554, ack=True))
        if rng.random() < 0.2:
            out.append(Packet(t + .005, LEAK_SERVER, cam, 60, "tcp", 8554, sp, ack=True))
        t += rng.expovariate(120)
    return out


# ---- pipeline ------------------------------------------------------------
def train_bank(reg: Registry, rng: random.Random, train_s: float = 1800, calib_s: float = 720):
    devices = list(reg.devices)
    train_pk = normal_traffic(rng, reg, 0, train_s)
    calib_pk = normal_traffic(rng, reg, train_s, train_s + calib_s)
    baselines = {d: learn_baseline_destinations(train_pk, d) for d in devices}
    bank = ModelBank()
    tw = extract_windows(train_pk, devices, baselines)
    cw = extract_windows(calib_pk, devices, baselines)
    for d in devices:
        bank.train(d, np.array([w.features for w in tw if w.device == d]),
                   np.array([w.features for w in cw if w.device == d]))
    return bank, baselines


def run_scenario(name, attack_pk, reg, bank, baselines, rng, t0, engine: DecisionEngine,
                 suricata: list[SuricataAlert] | None = None, lead_s=10.0, tail_s=20.0):
    pk = normal_traffic(rng, reg, t0, t0 + lead_s + tail_s) + attack_pk
    pk.sort(key=lambda p: p.ts)
    actions: list[Action] = []
    for a in suricata or []:
        act = engine.on_suricata_alert(a)
        if act:
            actions.append(act)
    for w in extract_windows(pk, list(reg.devices), baselines):
        s = bank.score(w.device, w.features)
        act = engine.on_window(w, s.flagged, s.risk)
        if act:
            act.risk = s.risk
            actions.append(act)
    return actions


def scenarios(reg: Registry, rng: random.Random, t0: float):
    ips = list(reg.devices)
    nodes = [d.ip for d in reg.devices.values() if d.kind == "esp32"]
    cam = next(d.ip for d in reg.devices.values() if d.kind == "camera")
    a = t0 + 10
    return [
        ("T3 Port scan on camera", t3_port_scan(rng, cam, a), None),
        ("T4 Password guessing on node 1", t4_password_guess(rng, nodes[0], a),
         [SuricataAlert(a + 3, 1, ATTACKER, nodes[0], "TANOD local: repeated HTTP login failures", 9000001)]),
        ("T5 Flood on node 2", t5_flood(rng, nodes[1], a), None),
        ("T6 Hacked node 1 scans others", t6_hacked_scan(rng, nodes[0], [i for i in ips if i != nodes[0]], a), None),
        ("T7 Node 2 uploads dummy file", t7_upload(rng, nodes[1], a), None),
        ("T8 Node 3 beacons once per second", t8_beacon(rng, nodes[2], a), None),
    ]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="data/tanod.db")
    ap.add_argument("--send-alerts", action="store_true", help="post alerts to TANOD_ALERT_ENDPOINT (local mock)")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.WARNING)

    from alerts import telegram
    from dashboard import db

    rng = random.Random(args.seed)
    reg = demo_registry()
    conn = db.connect(args.db)
    for d in reg.devices.values():
        db.upsert_device(conn, d.name, d.mac, d.ip, d.kind, d.relay_channel, d.relay_cutoff_enabled)

    print("Training per-device models on synthetic baseline traffic...")
    bank, baselines = train_bank(reg, rng)
    for d, m in bank.models.items():
        print(f"  {reg.get(d).name:14s} threshold s = {m.threshold:.4f} (risk {100 * m.threshold:.1f})")

    enforcer = Enforcer(dry_run=True)
    t0 = 100_000.0
    for name, attack, sur in scenarios(reg, rng, t0):
        engine = DecisionEngine(reg)
        actions = run_scenario(name, attack, reg, bank, baselines, rng, t0, engine, sur)
        print(f"\n{name}")
        if not actions:
            print("  no action")
        for act in actions:
            dev = reg.get(act.target)
            if act.kind == "quarantine":
                enforcer.quarantine(dev)
            else:
                enforcer.block(act.target)
            ttb = act.ts - (t0 + 10)
            print(f"  -> {act.kind} {dev.name if dev else act.target} via {act.source}"
                  f" (risk {act.risk}, ~{max(ttb, 0):.0f}s after attack start): {act.reason}")
            db.record_event(conn, act.kind, act.target, act.reason, act.source, act.risk, act.evidence,
                            target_mac=dev.mac if dev else None)
            if args.send_alerts:
                text = telegram.build_message(act.kind, dev.name if dev else "Unknown device", act.target,
                                              act.reason, act.risk)
                try:
                    telegram.send(telegram.build_payload(text))
                except OSError as e:
                    print(f"  (alert not sent: {e})")
    print(f"\nWrote events to {args.db}. Start the dashboard to review and release.")


if __name__ == "__main__":
    main()
