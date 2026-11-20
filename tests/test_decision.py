from collections import Counter

from gateway.decision import DecisionEngine, SuricataAlert
from gateway.features import Window
from gateway.registry import demo_registry

NODE1, NODE2, CAM = "192.168.50.11", "192.168.50.12", "192.168.50.20"
ATTACKER = "192.168.50.99"  # LAN client, not registered
OUTSIDE = "10.10.0.5"


def win(dev, start=0.0, incoming=None, attempts_in=None, attempts_out=0):
    return Window(device=dev, start=start, features=[0.0] * 10, incoming_by_src=Counter(incoming or {}),
                  attempts_in_by_src=Counter(attempts_in or {}), attempts_out=attempts_out)


def engine():
    return DecisionEngine(demo_registry())


# ---- Suricata ---------------------------------------------------------
def test_priority1_alert_from_unregistered_client_blocks_client():
    e = engine()
    a = e.on_suricata_alert(SuricataAlert(1.0, 1, ATTACKER, CAM, "scan"))
    assert a.kind == "block" and a.target == ATTACKER and a.source == "suricata"
    assert CAM not in e.quarantined


def test_priority1_alert_from_protected_device_quarantines_it():
    a = engine().on_suricata_alert(SuricataAlert(1.0, 1, NODE1, OUTSIDE, "malware beacon"))
    assert a.kind == "quarantine" and a.target == NODE1


def test_priority1_alert_from_outside_quarantines_target():
    a = engine().on_suricata_alert(SuricataAlert(1.0, 1, OUTSIDE, NODE2, "exploit"))
    assert a.kind == "quarantine" and a.target == NODE2


def test_lower_priority_alert_does_nothing():
    assert engine().on_suricata_alert(SuricataAlert(1.0, 2, ATTACKER, CAM, "info")) is None


def test_duplicate_block_is_not_repeated():
    e = engine()
    assert e.on_suricata_alert(SuricataAlert(1.0, 1, ATTACKER, CAM, "x"))
    assert e.on_suricata_alert(SuricataAlert(2.0, 1, ATTACKER, NODE1, "x")) is None


# ---- Isolation Forest windows -------------------------------------------
def test_one_flagged_window_is_not_enough():
    e = engine()
    assert e.on_window(win(NODE1, 0), True, 80) is None
    assert NODE1 not in e.quarantined


def test_two_consecutive_flagged_windows_quarantine():
    e = engine()
    assert e.on_window(win(NODE1, 0), True, 80) is None
    a = e.on_window(win(NODE1, 2), True, 82)
    assert a.kind == "quarantine" and a.target == NODE1 and a.source == "isolation_forest"
    assert a.ts == 4.0  # decided when the second window closes


def test_non_consecutive_flags_reset_the_streak():
    e = engine()
    e.on_window(win(NODE1, 0), True, 80)
    e.on_window(win(NODE1, 2), False, 40)
    assert e.on_window(win(NODE1, 4), True, 80) is None


def test_streaks_are_per_device():
    e = engine()
    e.on_window(win(NODE1, 0), True, 80)
    assert e.on_window(win(NODE2, 0), True, 80) is None
    assert e.on_window(win(NODE1, 2), True, 80).target == NODE1


def test_flagged_window_mostly_from_unregistered_client_blocks_client():
    e = engine()
    a = e.on_window(win(CAM, 0, incoming={ATTACKER: 900, OUTSIDE: 10}), True, 75)
    assert a.kind == "block" and a.target == ATTACKER
    assert CAM not in e.quarantined
    # the camera's streak was not advanced by the attack
    assert e.on_window(win(CAM, 2), True, 75) is None


def test_unregistered_client_without_majority_does_not_block():
    e = engine()
    a = e.on_window(win(CAM, 0, incoming={ATTACKER: 40, OUTSIDE: 60}), True, 75)
    assert a is None and ATTACKER not in e.blocked


def test_victim_of_protected_device_scan_is_not_quarantined():
    e = engine()
    for t in (0, 2, 4):
        assert e.on_window(win(NODE2, t, incoming={NODE1: 80}, attempts_in={NODE1: 75}), True, 75) is None
    assert NODE2 not in e.quarantined


def test_scanning_device_is_still_quarantined():
    e = engine()
    # the scanner receives RST replies from victims but made the attempts itself
    w = lambda t: win(NODE1, t, incoming={NODE2: 75, CAM: 75}, attempts_out=150)
    e.on_window(w(0), True, 76)
    assert e.on_window(w(2), True, 76).target == NODE1


def test_quarantined_device_is_ignored_until_released():
    e = engine()
    e.on_window(win(NODE1, 0), True, 80)
    e.on_window(win(NODE1, 2), True, 80)
    assert e.on_window(win(NODE1, 4), True, 80) is None
    e.release(NODE1)
    assert e.on_window(win(NODE1, 6), True, 80) is None
    assert e.on_window(win(NODE1, 8), True, 80).kind == "quarantine"
