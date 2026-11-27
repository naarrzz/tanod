"""Run TANOD on real traffic (the Pi 5, or a Linux VM in the Kali test lab).

This is what turns the prototype from a simulation into a working gateway. It
reads real packets from an interface (or a pcap) and Suricata's alerts, runs
the same detection and decision logic as gateway/simulate.py, and blocks the
attacker with real nftables and hostapd commands.

    # safe, prints what it would do (no root needed):
    python -m gateway.run --pcap capture.pcap
    sudo TANOD_DRY_RUN=0 python -m gateway.run --iface wlan0 --eve /var/log/suricata/eve.json

Attacker response (same as the simulation and the paper):
  - a camera is attacked        -> block the attacker, by MAC on the LAN, by IP outside;
  - a camera looks hijacked      -> block the address it talks to; the camera stays online;
  - no attacker can be named      -> alert only (e.g. the camera was deauthenticated).

Models: with --models DIR it loads per-camera Isolation Forests trained from a
real baseline (gateway/train... on the Pi). Without it, it trains throwaway
models on synthetic baseline traffic so the pipeline runs end to end -- the
thresholds are then placeholders, not thesis results, and it says so.
"""
from __future__ import annotations

import argparse
import logging
import os
import threading
import time
from pathlib import Path

from .capture import Frame, frames_from_pcap, sniff_live
from .decision import Action, DecisionEngine, SuricataAlert
from .enforce import Enforcer
from .features import WINDOW_SECONDS, Packet, device_window_features, window_start
from .model import ModelBank
from .registry import Registry, registry_from_env
from .spoof import BindingCheck, Observation
from .suricata import parse_eve_line

log = logging.getLogger("tanod.run")


class GatewayPipeline:
    """One decision engine fed by three detectors: Suricata, the Isolation Forest
    and the IP-MAC binding check. Every block it decides is applied to the firewall
    and written to the dashboard database."""

    def __init__(self, registry: Registry, bank: ModelBank, enforcer: Enforcer,
                 conn=None, baselines: dict | None = None, on_action=None):
        self.reg = registry
        self.bank = bank
        self.enforcer = enforcer
        self.conn = conn
        self.baselines = baselines or {}
        self.engine = DecisionEngine(registry)
        self.check = BindingCheck(registry)
        self.on_action = on_action
        self._lock = threading.Lock()

    def _apply(self, actions: list[Action]) -> list[Action]:
        for a in actions:
            if a.kind == "block":
                try:
                    self.enforcer.block(a.target, a.mac)
                except Exception as e:  # a bad address must not crash the gateway
                    log.error("could not block %s/%s: %s", a.target, a.mac, e)
            if self.conn is not None:
                from dashboard import db
                db.record_event(self.conn, a.kind, a.key, a.reason, a.source, a.risk, a.evidence,
                                target_mac=a.mac, victim_ip=a.victim)
            log.info("%s %s (%s): %s", a.kind, a.key, a.source, a.reason)
            if self.on_action:
                self.on_action(a)
        return actions

    def on_alert(self, alert: SuricataAlert) -> list[Action]:
        with self._lock:
            return self._apply(self.engine.on_suricata_alert(alert))

    def on_observation(self, obs: Observation) -> list[Action]:
        with self._lock:
            finding = self.check.check(obs)
            return self._apply(self.engine.on_spoof(finding)) if finding else []

    def on_slice(self, packets: list[Packet], start: float) -> list[Action]:
        """Score one 2-second window for every camera. A camera with no packets
        gets a zero window, so a camera knocked offline (deauth) is noticed."""
        with self._lock:
            out: list[Action] = []
            for cam in self.reg.devices:
                w = device_window_features(cam, packets, self.baselines.get(cam), start=start)
                score = self.bank.score(cam, w.features)
                if score is None:
                    continue
                out += self.engine.on_window(w, score.flagged, score.risk)
            return self._apply(out)

    # ---- offline: a whole pcap at once ---------------------------------
    def process_frames(self, frames: list[Frame]) -> list[Action]:
        frames = sorted(frames, key=lambda f: f.ts)
        actions: list[Action] = []
        buckets: dict[float, list[Packet]] = {}
        for f in frames:
            if f.src_ip and f.src_mac:
                self.reg.observe(f.src_ip, f.src_mac)
            if f.observation:
                actions += self.on_observation(f.observation)
            if f.packet:
                buckets.setdefault(window_start(f.packet.ts), []).append(f.packet)
        for start in sorted(buckets):
            actions += self.on_slice(buckets[start], start)
        return actions


# ---- building the pipeline ------------------------------------------------
def load_bank(reg: Registry, models_dir: str | None) -> tuple[ModelBank, dict]:
    if models_dir and Path(models_dir).exists():
        log.info("loading trained models from %s", models_dir)
        return ModelBank.load(models_dir), {}
    log.warning("no --models given: training throwaway models on synthetic baseline. "
                "Thresholds are placeholders, not real results.")
    import random

    from . import simulate
    return simulate.train_bank(reg, random.Random(7))


def make_pipeline(models_dir: str | None = None, db_path: str | None = None, dry_run: bool | None = None,
                  iface: str = "wlan0", on_action=None) -> GatewayPipeline:
    reg = registry_from_env()
    bank, baselines = load_bank(reg, models_dir)
    if dry_run is None:
        dry_run = os.environ.get("TANOD_DRY_RUN", "1") != "0"
    enforcer = Enforcer(dry_run=dry_run, wlan=iface)
    conn = None
    if db_path:
        from dashboard import db
        conn = db.connect(db_path)
        for d in reg.devices.values():
            db.upsert_device(conn, d.name, d.mac, d.ip, d.kind, d.link)
    if not dry_run:
        enforcer.setup()
    return GatewayPipeline(reg, bank, enforcer, conn, baselines, on_action)


# ---- live loop ------------------------------------------------------------
def tail_eve(path: str, on_alert, stop) -> None:
    """Follow Suricata's eve.json and hand priority-1 alerts to the pipeline."""
    while not stop() and not Path(path).exists():
        time.sleep(0.5)
    with open(path) as fh:
        fh.seek(0, 2)  # start at the end; only new alerts matter
        while not stop():
            line = fh.readline()
            if not line:
                time.sleep(0.2)
                continue
            alert = parse_eve_line(line)
            if alert:
                on_alert(alert)


def run_live(pipe: GatewayPipeline, iface: str, eve_path: str | None) -> None:
    """Sniff the interface, flush a window every WINDOW_SECONDS, and tail Suricata."""
    stop_flag = threading.Event()
    buffer: list[Packet] = []
    buf_lock = threading.Lock()

    def on_frame(f: Frame) -> None:
        if f.src_ip and f.src_mac:
            pipe.reg.observe(f.src_ip, f.src_mac)
        if f.observation:
            pipe.on_observation(f.observation)
        if f.packet:
            with buf_lock:
                buffer.append(f.packet)

    def flusher() -> None:
        while not stop_flag.is_set():
            time.sleep(WINDOW_SECONDS)
            with buf_lock:
                slice_, buffer[:] = buffer[:], []
            start = window_start(slice_[0].ts if slice_ else time.time())
            pipe.on_slice(slice_, start)

    threads = [threading.Thread(target=flusher, daemon=True)]
    if eve_path:
        threads.append(threading.Thread(target=tail_eve, args=(eve_path, pipe.on_alert, stop_flag.is_set), daemon=True))
    for t in threads:
        t.start()
    log.info("TANOD watching %s (%s). Ctrl+C to stop.", iface, "live block" if not pipe.enforcer.dry_run else "dry run")
    try:
        sniff_live(iface, on_frame, stop_flag.is_set)
    except KeyboardInterrupt:
        pass
    finally:
        stop_flag.set()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="network interface to watch live (needs root), e.g. wlan0 or eth0")
    src.add_argument("--pcap", help="a saved capture to replay instead of sniffing live")
    ap.add_argument("--eve", help="Suricata eve.json to follow for rule alerts")
    ap.add_argument("--models", help="folder of trained per-camera models (joblib)")
    ap.add_argument("--db", default="data/tanod.db", help="dashboard database to write events to")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")

    pipe = make_pipeline(args.models, args.db, iface=args.iface or "wlan0")
    if args.pcap:
        actions = pipe.process_frames(list(frames_from_pcap(args.pcap)))
        print(f"{len(actions)} action(s) from {args.pcap}. See the dashboard.")
        return
    run_live(pipe, args.iface, args.eve)


if __name__ == "__main__":
    main()
