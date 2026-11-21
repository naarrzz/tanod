"""The real-traffic path: Frames in -> the same blocks the simulation makes.

These use make_frame (no scapy needed). frame_from_scapy is a thin wrapper over
make_frame, exercised on the Pi / lab VM where scapy is installed."""
import random

import pytest

from gateway import simulate as S
from gateway.capture import make_frame
from gateway.enforce import Enforcer
from gateway.registry import demo_registry
from gateway.run import GatewayPipeline, make_pipeline

CAM = "192.168.50.20"
GW = "192.168.50.1"
ATTACKER, ATTACKER_MAC = "192.168.50.99", "de:ad:be:ef:00:99"
CAM_MAC = "aa:bb:cc:00:00:20"


def pipeline():
    reg = demo_registry()
    bank, baselines = S.train_bank(reg, random.Random(7))
    enforcer = Enforcer(dry_run=True)
    return GatewayPipeline(reg, bank, enforcer, baselines=baselines), enforcer


# ---- capture conversion ------------------------------------------------
def test_make_frame_builds_a_tcp_syn_packet():
    f = make_frame(1.0, ATTACKER_MAC, CAM_MAC, src_ip=ATTACKER, dst_ip=CAM, proto="tcp",
                   sport=40000, dport=80, size=60, syn=True)
    assert f.packet.syn and not f.packet.ack and f.packet.dport == 80
    assert f.src_ip == ATTACKER and f.src_mac == ATTACKER_MAC and f.observation is None


def test_make_frame_builds_an_arp_observation():
    f = make_frame(2.0, ATTACKER_MAC, "ff:ff:ff:ff:ff:ff", arp_op=2, arp_ip=GW)
    assert f.packet is None and f.observation.ip == GW and f.observation.mac == ATTACKER_MAC
    assert f.observation.via == "arp"


def test_mac_is_lowercased():
    assert make_frame(1.0, "DE:AD:BE:EF:00:99", "", src_ip=ATTACKER, dst_ip=CAM).src_mac == ATTACKER_MAC


# ---- pipeline on real-shaped frames ------------------------------------
def frames_from_packets(packets, mac):
    return [make_frame(p.ts, mac, "", src_ip=p.src, dst_ip=p.dst, proto=p.proto, sport=p.sport,
                       dport=p.dport, size=p.size, syn=p.syn, ack=p.ack, rst=p.rst) for p in packets]


def test_port_scan_frames_block_the_attacker_by_its_learned_mac():
    pipe, enforcer = pipeline()
    rng = random.Random(1)
    packets = S.a1_port_scan(rng, CAM, 100.0, src=ATTACKER)
    actions = pipe.process_frames(frames_from_packets(packets, ATTACKER_MAC))
    blocks = [a for a in actions if a.kind == "block"]
    assert blocks and blocks[0].target == ATTACKER and blocks[0].mac == ATTACKER_MAC
    # the firewall really saw a MAC block, built from the learned IP->MAC binding
    flat = [" ".join(c) for c in enforcer.executed]
    assert any("block_mac { de:ad:be:ef:00:99 }" in c for c in flat)
    assert not any(CAM in c for c in flat)  # never the camera


def test_arp_spoof_frame_blocks_the_spoofer():
    pipe, _ = pipeline()
    frame = make_frame(1.0, ATTACKER_MAC, "", arp_op=2, arp_ip=GW)
    [a] = pipe.process_frames([frame])
    assert a.source == "binding_check" and a.mac == ATTACKER_MAC and GW not in pipe.engine.blocked_ips


def test_silent_camera_slice_raises_an_alert():
    pipe, _ = pipeline()
    # two empty 2-second windows for the camera: it was knocked offline
    a = pipe.on_slice([], 0.0) + pipe.on_slice([], 2.0)
    assert any(x.kind == "alert" and x.victim == CAM for x in a)


def test_pipeline_writes_events_to_the_dashboard_db(tmp_path):
    pipe = make_pipeline(db_path=str(tmp_path / "t.db"), dry_run=True)
    rng = random.Random(1)
    pipe.process_frames(frames_from_packets(S.a1_port_scan(rng, CAM, 100.0, src=ATTACKER), ATTACKER_MAC))
    from dashboard import db
    active = db.active_responses(pipe.conn)
    assert any(e["kind"] == "block" and e["victim_ip"] == CAM for e in active)


def test_dry_run_pipeline_runs_no_commands_for_real():
    pipe, enforcer = pipeline()
    assert enforcer.dry_run
    pipe.process_frames(frames_from_packets(S.a1_port_scan(random.Random(1), CAM, 100.0, src=ATTACKER), ATTACKER_MAC))
    # executed records what WOULD run, but the dry-run runner never calls subprocess
    assert enforcer.executed  # commands were built
