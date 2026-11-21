"""Laptop simulation of the whole pipeline with synthetic packet metadata.

No packets are sent anywhere: this only generates header records in memory,
trains the per-camera models, replays the attack list through the three
detectors and the decision logic, and writes the results to the dashboard DB.

    python -m gateway.simulate                 # attack table + data/tanod.db
    python -m gateway.simulate --send-alerts   # also posts to the local mock endpoint

For every attack it prints what each detector caught, so the value of the
Isolation Forest over Suricata alone is visible:
    Suricata  = Setup A (Suricata with TANOD's local rules, see rules.py)
    IF        = per-camera Isolation Forest
    Binding   = IP-MAC binding check for spoofing (spoof.py)
"""
from __future__ import annotations

import argparse
import logging
import random
from dataclasses import dataclass, field

import numpy as np

from . import rules
from .decision import Action, DecisionEngine, SuricataAlert
from .enforce import Enforcer
from .features import (WINDOW_SECONDS, Packet, device_window_features, extract_windows,
                       learn_baseline_destinations, window_start)
from .model import ModelBank
from .registry import Registry, demo_registry
from .spoof import BindingCheck, Observation

VIEWER = "10.10.0.7"  # owner's viewing PC / NVR (approved viewer)
GATEWAY = "192.168.50.1"
ATTACKER = "192.168.50.99"  # LAN client with a leaked Wi-Fi passphrase
ATTACKER_MAC = "de:ad:be:ef:00:99"
ATTACKER_NEW_IP = "192.168.50.98"  # where the attacker moves after changing its IP
CLONE_IP = "192.168.50.97"  # second attacker that copies a camera's MAC
OUTSIDE_ATTACKER = "10.10.0.66"
C2_SERVER = "10.10.0.99"


# ---- normal traffic ------------------------------------------------------
def camera_normal(rng: random.Random, ip: str, t0: float, t1: float, pps: int = 20) -> list[Packet]:
    """Video to the approved viewer, its small replies, and an occasional DNS/NTP check."""
    out, t = [], t0
    while t < t1:
        out.append(Packet(t, ip, VIEWER, rng.randint(1000, 1400), "udp", 5004, 5004))
        if rng.random() < 0.1:
            out.append(Packet(t + 0.01, VIEWER, ip, 80, "udp", 5005, 5005))
        if rng.random() < 0.002:
            out.append(Packet(t + 0.02, ip, GATEWAY, 70, "udp", rng.randint(1024, 65000), 53))
            out.append(Packet(t + 0.03, GATEWAY, ip, 110, "udp", 53, rng.randint(1024, 65000)))
        t += rng.expovariate(pps)
    return out


def normal_traffic(rng: random.Random, reg: Registry, t0: float, t1: float,
                   silent: tuple[str, float, float] | None = None) -> list[Packet]:
    pk: list[Packet] = []
    for d in reg.devices.values():
        cam = camera_normal(rng, d.ip, t0, t1)
        if silent and d.ip == silent[0]:  # the camera is knocked off the network for a while
            cam = [p for p in cam if not silent[1] <= p.ts < silent[2]]
        pk += cam
    return pk


# ---- attacks on a camera (Section 3.7 attack list) ----------------------
def a1_port_scan(rng, cam, t0, src=ATTACKER, dur=6.0):
    out = []
    for i, port in enumerate(range(1, 1001)):
        t = t0 + dur * i / 1000
        sp = rng.randint(30000, 60000)
        out.append(Packet(t, src, cam, 60, "tcp", sp, port, syn=True))
        out.append(Packet(t + 0.001, cam, src, 54, "tcp", port, sp, rst=True, ack=True))
    return out


def a2_password_guess(rng, cam, t0, src=ATTACKER, dur=10.0):
    out, t = [], t0
    while t < t0 + dur:
        sp = rng.randint(30000, 60000)
        out += [Packet(t, src, cam, 60, "tcp", sp, 80, syn=True),
                Packet(t + .005, cam, src, 60, "tcp", 80, sp, syn=True, ack=True),
                Packet(t + .01, src, cam, 300, "tcp", sp, 80, ack=True),
                Packet(t + .02, cam, src, 200, "tcp", 80, sp, ack=True)]
        t += 0.1
    return out


def a3_flood(rng, cam, t0, src=ATTACKER, dur=6.0):
    n = int(dur * 2000)
    return [Packet(t0 + dur * i / n, src, cam, 1400, "udp", rng.randint(1024, 65000), 9) for i in range(n)]


def a4_arp_spoof(rng, cam, t0, dur=10.0):
    """Attacker tells the camera "I am the gateway" once a second (first step of a MITM).
    The video still flows (now through the attacker), so the packets look normal."""
    obs = [Observation(t0 + i, GATEWAY, ATTACKER_MAC, "arp") for i in range(int(dur))]
    return [], obs


def a5_mac_clone(rng, cam, t0, reg: Registry, dur=10.0):
    """Attacker copies the camera's MAC, gets another IP and sends a fake video stream to the viewer."""
    cam_mac = reg.get(cam).mac
    obs = [Observation(t0, CLONE_IP, cam_mac, "dhcp")]
    pk, t = [], t0 + 0.5
    while t < t0 + dur:
        pk.append(Packet(t, CLONE_IP, VIEWER, rng.randint(1000, 1400), "udp", 5004, 5004))
        t += rng.expovariate(20)
    return pk, obs


def a6_unauthorized_view(rng, cam, t0, src=ATTACKER, dur=10.0):
    """A client that is not an approved viewer opens the camera's RTSP stream and watches it."""
    sp = rng.randint(30000, 60000)
    out = [Packet(t0, src, cam, 60, "tcp", sp, 554, syn=True),
           Packet(t0 + .005, cam, src, 60, "tcp", 554, sp, syn=True, ack=True),
           Packet(t0 + .01, src, cam, 200, "tcp", sp, 554, ack=True)]
    t = t0 + .05
    while t < t0 + dur:
        out.append(Packet(t, cam, src, rng.randint(1000, 1400), "tcp", 554, sp, ack=True))
        if rng.random() < 0.1:
            out.append(Packet(t + .005, src, cam, 60, "tcp", sp, 554, ack=True))
        t += rng.expovariate(20)
    return out


def a7_exfiltration(rng, cam, t0, dur=10.0):
    """Hijacked camera tries several unknown servers (some refuse) and sends copies of its video
    to the ones that answer."""
    out, t = [], t0
    servers = [f"10.10.0.{i}" for i in range(70, 76)]
    ports = [554, 8554, 443, 8080]
    live: list[tuple[str, int, int]] = []
    next_try = t0
    while t < t0 + dur:
        if t >= next_try:
            dst, dport, sp = rng.choice(servers), rng.choice(ports), rng.randint(30000, 60000)
            out.append(Packet(t, cam, dst, 60, "tcp", sp, dport, syn=True))
            if rng.random() < 0.35:
                out.append(Packet(t + .01, dst, cam, 54, "tcp", dport, sp, rst=True, ack=True))
            else:
                out.append(Packet(t + .01, dst, cam, 60, "tcp", dport, sp, syn=True, ack=True))
                live = (live + [(dst, dport, sp)])[-3:]
            next_try = t + rng.uniform(0.15, 0.35)
        if live:
            dst, dport, sp = rng.choice(live)
            out.append(Packet(t, cam, dst, rng.randint(1200, 1400), "tcp", sp, dport, ack=True))
            if rng.random() < 0.2:
                out.append(Packet(t + .005, dst, cam, 60, "tcp", dport, sp, ack=True))
        t += rng.expovariate(120)
    return out


def a8_beacon(rng, cam, t0, dur=12.0):
    """Hijacked camera checks in with a command server once a second."""
    out, t = [], t0
    while t < t0 + dur:
        sp = rng.randint(30000, 60000)
        out += [Packet(t, cam, C2_SERVER, 60, "tcp", sp, 4444, syn=True),
                Packet(t + .01, C2_SERVER, cam, 60, "tcp", 4444, sp, syn=True, ack=True),
                Packet(t + .02, cam, C2_SERVER, 90, "tcp", sp, 4444, ack=True)]
        t += 1.0
    return out


# A9 Wi-Fi deauthentication: forged management frames knock the camera off the
# Wi-Fi. No IP packet is involved; the only trace is the camera going silent.

ATTACKS = {
    "scan": ("A1", "Port scan of the camera", "C"),
    "brute": ("A2", "Password guessing on the camera login", "C"),
    "flood": ("A3", "UDP flood on the camera (denial of service)", "A"),
    "arp": ("A4", "ARP spoofing: attacker pretends to be the gateway", "C, I"),
    "clone": ("A5", "MAC cloning: attacker copies the camera's MAC", "C, I, A"),
    "view": ("A6", "Unauthorized viewing of the live stream", "C"),
    "leak": ("A7", "Hijacked camera sends its video to unknown servers", "C"),
    "beacon": ("A8", "Hijacked camera checks in with a command server", "C"),
    "deauth": ("A9", "Wi-Fi deauthentication knocks the camera offline", "A"),
}


@dataclass
class Scenario:
    key: str
    camera: str
    packets: list[Packet] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    silent: tuple[str, float, float] | None = None

    @property
    def label(self) -> str:
        code, name, _ = ATTACKS[self.key]
        return f"{code} {name}"


def build_scenario(key: str, rng: random.Random, reg: Registry, cam: str, start: float) -> Scenario:
    s = Scenario(key, cam)
    if key == "scan":
        s.packets = a1_port_scan(rng, cam, start)
    elif key == "brute":
        s.packets = a2_password_guess(rng, cam, start)
    elif key == "flood":
        s.packets = a3_flood(rng, cam, start)
    elif key == "arp":
        s.packets, s.observations = a4_arp_spoof(rng, cam, start)
    elif key == "clone":
        s.packets, s.observations = a5_mac_clone(rng, cam, start, reg)
    elif key == "view":
        s.packets = a6_unauthorized_view(rng, cam, start)
    elif key == "leak":
        s.packets = a7_exfiltration(rng, cam, start)
    elif key == "beacon":
        s.packets = a8_beacon(rng, cam, start)
    elif key == "deauth":
        s.silent = (cam, start, start + 15.0)
    else:
        raise KeyError(key)
    return s


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


@dataclass
class Result:
    scenario: Scenario
    attack_start: float
    suricata: list[SuricataAlert]
    if_actions: list[Action]  # what the Isolation Forest path decided
    binding_actions: list[Action]
    actions: list[Action]  # what TANOD (Setup B) actually did, in time order

    def first(self, items) -> float | None:
        return min((x.ts - self.attack_start for x in items), default=None)


def run_scenario(sc: Scenario, reg: Registry, bank: ModelBank, baselines, rng: random.Random, t0: float,
                 lead_s: float = 10.0, tail_s: float = 20.0, setup: str = "B") -> Result:
    """Setup A = Suricata only. Setup B = Suricata + Isolation Forest + binding check (TANOD)."""
    pk = normal_traffic(rng, reg, t0, t0 + lead_s + tail_s, sc.silent) + sc.packets
    pk.sort(key=lambda p: p.ts)
    attack_start = t0 + lead_s
    alerts = rules.evaluate(pk, reg)

    reg = _copy(reg)  # each run learns bindings on its own copy
    # each detector on its own, to report what it catches
    if_only = DecisionEngine(reg)
    if_actions = [a for w in extract_windows(pk, list(reg.devices), baselines)
                  for a in if_only.on_window(w, *_score(bank, w))]
    bind_engine, check = DecisionEngine(_copy(reg)), BindingCheck(_copy(reg))
    binding_actions = [a for o in sc.observations if (f := check.check(o)) for a in bind_engine.on_spoof(f)]

    # TANOD itself: all inputs in time order through one engine. Once an address is
    # blocked, its packets stop reaching the camera, as they would behind nftables.
    treg = _copy(reg)
    engine, check = DecisionEngine(treg), BindingCheck(treg)
    devices = list(treg.devices)
    buckets: dict[float, list[Packet]] = {}
    for p in pk:
        buckets.setdefault(window_start(p.ts), []).append(p)
    events: list[tuple[float, int, object]] = [(a.ts, 0, a) for a in alerts]
    if setup == "B":
        events += [(o.ts, 1, o) for o in sc.observations]
        events += [(ws + WINDOW_SECONDS, 2, ws) for ws in sorted(buckets)]
    actions: list[Action] = []
    blocked_at: dict[str, float] = {}

    def dropped(p: Packet) -> bool:
        return any(a in blocked_at and p.ts >= blocked_at[a] for a in (p.src, p.dst))

    for ts, kind, item in sorted(events, key=lambda e: (e[0], e[1])):
        if kind == 0:
            if item.src in blocked_at and item.ts >= blocked_at[item.src]:
                continue  # Suricata no longer sees a blocked source
            new = engine.on_suricata_alert(item)
        elif kind == 1:
            f = check.check(item)
            new = engine.on_spoof(f) if f else []
        else:
            seen = [p for p in buckets[item] if not dropped(p)]
            new = []
            for d in devices:
                w = device_window_features(d, seen, baselines.get(d), start=item)
                new += engine.on_window(w, *_score(bank, w))
        for a in new:
            ips = {a.target} if a.target else set()
            if a.kind == "block" and a.mac:
                ips |= {ip for ip, m in treg.bindings.items() if m == a.mac and not treg.is_protected(ip)}
            for ip in ips if a.kind == "block" else ():
                blocked_at.setdefault(ip, a.ts)
        actions += new
    return Result(sc, attack_start, alerts, if_actions, binding_actions, actions)


def _score(bank: ModelBank, w):
    s = bank.score(w.device, w.features)
    return s.flagged, s.risk


def _copy(reg: Registry) -> Registry:
    r = Registry(list(reg.devices.values()), str(reg.lan), reg.gateway_ip, reg.gateway_mac, reg.viewers)
    r.bindings[ATTACKER] = ATTACKER_MAC  # the attacker's DHCP lease
    return r


def fmt(t: float | None) -> str:
    return "missed" if t is None else f"yes, {max(t, 0):.0f} s"


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
        db.upsert_device(conn, d.name, d.mac, d.ip, d.kind, d.link)

    print("Training per-camera models on synthetic baseline traffic...")
    bank, baselines = train_bank(reg, rng)
    for d, m in bank.models.items():
        print(f"  {reg.get(d).name:14s} threshold s = {m.threshold:.4f} (risk {100 * m.threshold:.1f})")

    cam = "192.168.50.20"
    enforcer = Enforcer(dry_run=True)
    t0 = 100_000.0
    print(f"\n{'Attack':58s} {'CIA':8s} {'Suricata':10s} {'IF':10s} {'Binding':10s} TANOD did")
    for key in ATTACKS:
        res = run_scenario(build_scenario(key, rng, reg, cam, t0 + 10), reg, bank, baselines, rng, t0)
        did = "; ".join(f"{a.kind} {a.key}" + (f" (MAC {a.mac})" if a.mac and a.target else "") for a in res.actions[:2]) or "nothing"
        print(f"{res.scenario.label:58s} {ATTACKS[key][2]:8s} {fmt(res.first(res.suricata)):10s} "
              f"{fmt(res.first(res.if_actions)):10s} {fmt(res.first(res.binding_actions)):10s} {did}")
        for act in res.actions:
            if act.kind == "block":
                enforcer.block(act.target, act.mac)
            db.record_event(conn, act.kind, act.key, act.reason, act.source, act.risk, act.evidence,
                            target_mac=act.mac, victim_ip=act.victim)
            if args.send_alerts:
                try:
                    telegram.send(telegram.build_payload(
                        telegram.build_message(act.kind, reg.get(act.victim).name, act.key, act.reason, act.risk)))
                except OSError as e:
                    print(f"  (alert not sent: {e})")
    print(f"\nWrote events to {args.db}. Start the dashboard to review and unblock.")


if __name__ == "__main__":
    main()
