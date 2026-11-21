"""The attack table the defense will show: what Suricata alone catches vs TANOD."""
import random

import pytest

from gateway import simulate as S
from gateway.registry import demo_registry

CAM = "192.168.50.20"


@pytest.fixture(scope="module")
def trained():
    reg = demo_registry()
    bank, baselines = S.train_bank(reg, random.Random(7))
    return reg, bank, baselines


def run(trained, key, seed=1):
    reg, bank, baselines = trained
    rng = random.Random(seed)
    return S.run_scenario(S.build_scenario(key, rng, reg, CAM, 100_010.0), reg, bank, baselines, rng, 100_000.0)


@pytest.mark.parametrize("key", ["scan", "brute", "flood", "view"])
def test_suricata_catches_and_tanod_blocks_the_lan_attacker_by_mac(trained, key):
    res = run(trained, key)
    assert res.suricata
    blocks = [a for a in res.actions if a.kind == "block"]
    assert blocks and blocks[0].target == S.ATTACKER and blocks[0].mac == S.ATTACKER_MAC
    assert all(a.target != CAM for a in res.actions if a.kind == "block")


@pytest.mark.parametrize("key", ["leak", "deauth"])
def test_only_the_isolation_forest_catches(trained, key):
    res = run(trained, key)
    assert not res.suricata and res.if_actions and res.actions
    assert res.first(res.actions) <= 10  # the paper's time-to-block target


@pytest.mark.parametrize("key", ["arp", "clone"])
def test_only_the_binding_check_catches_spoofing(trained, key):
    res = run(trained, key)
    assert not res.suricata and not res.if_actions and res.binding_actions
    [a] = res.actions
    if key == "arp":
        assert a.mac == S.ATTACKER_MAC
    else:
        assert a.target == S.CLONE_IP and a.mac is None


def test_setup_a_misses_what_the_forest_catches(trained):
    reg, bank, baselines = trained
    rng = random.Random(1)
    res = S.run_scenario(S.build_scenario("leak", rng, reg, CAM, 100_010.0), reg, bank, baselines, rng, 100_000.0,
                         setup="A")
    assert res.actions == []


def test_blocked_attacker_traffic_stops_reaching_the_camera(trained):
    res = run(trained, "scan")
    assert [a.kind for a in res.actions] == ["block"]  # no follow-up alert once it is blocked
