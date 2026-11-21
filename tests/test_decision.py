from collections import Counter

from gateway.decision import DecisionEngine, SuricataAlert
from gateway.features import Window
from gateway.registry import demo_registry
from gateway.spoof import BindingCheck, Observation

CAM, CCTV = "192.168.50.20", "192.168.50.21"
CAM_MAC = "aa:bb:cc:00:00:20"
GW = "192.168.50.1"
ATTACKER, ATTACKER_MAC = "192.168.50.99", "de:ad:be:ef:00:99"
OUTSIDE = "10.10.0.66"
VIEWER = "10.10.0.7"


def win(dev, start=0.0, incoming=None, attempts_in=None, attempts_out=0, new=None, sent=10.0):
    f = [0.0] * 10
    f[2] = sent
    return Window(device=dev, start=start, features=f, incoming_by_src=Counter(incoming or {}),
                  attempts_in_by_src=Counter(attempts_in or {}), attempts_out=attempts_out,
                  new_dst_list=list(new or []))


def registry():
    reg = demo_registry()
    reg.observe(ATTACKER, ATTACKER_MAC)  # the attacker's DHCP lease
    return reg


def engine():
    return DecisionEngine(registry())


# ---- Suricata ---------------------------------------------------------
def test_alert_on_camera_blocks_the_attacker_by_mac_not_the_camera():
    e = engine()
    [a] = e.on_suricata_alert(SuricataAlert(1.0, 1, ATTACKER, CAM, "scan"))
    assert a.kind == "block" and a.target == ATTACKER and a.mac == ATTACKER_MAC and a.victim == CAM
    assert CAM not in e.blocked_ips and CAM_MAC not in e.blocked_macs


def test_outside_attacker_is_blocked_by_ip_only():
    [a] = engine().on_suricata_alert(SuricataAlert(1.0, 1, OUTSIDE, CCTV, "exploit"))
    assert a.target == OUTSIDE and a.mac is None and a.victim == CCTV


def test_camera_sending_attack_traffic_blocks_the_other_end():
    e = engine()
    [a] = e.on_suricata_alert(SuricataAlert(1.0, 1, CAM, OUTSIDE, "malware beacon"))
    assert a.kind == "block" and a.target == OUTSIDE and "hijacked" in a.reason
    assert CAM in e.suspect and CAM not in e.blocked_ips


def test_lower_priority_alert_does_nothing():
    assert engine().on_suricata_alert(SuricataAlert(1.0, 2, ATTACKER, CAM, "info")) == []


def test_duplicate_block_is_not_repeated():
    e = engine()
    assert e.on_suricata_alert(SuricataAlert(1.0, 1, ATTACKER, CAM, "x"))
    assert e.on_suricata_alert(SuricataAlert(2.0, 1, ATTACKER, CCTV, "x")) == []


def test_attacker_that_changes_ip_is_still_known_by_mac():
    e = engine()
    e.on_suricata_alert(SuricataAlert(1.0, 1, ATTACKER, CAM, "scan"))
    e.registry.observe("192.168.50.98", ATTACKER_MAC)
    assert e.is_blocked(mac=e.registry.mac_of("192.168.50.98"))
    # a new alert from the new IP adds that IP to the block, the MAC was already there
    [a] = e.on_suricata_alert(SuricataAlert(5.0, 1, "192.168.50.98", CAM, "scan"))
    assert a.target == "192.168.50.98" and a.mac == ATTACKER_MAC


# ---- Isolation Forest windows -------------------------------------------
def test_one_flagged_window_is_not_enough():
    e = engine()
    assert e.on_window(win(CAM, 0, incoming={OUTSIDE: 900}), True, 80) == []


def test_two_flagged_windows_block_the_main_source():
    e = engine()
    e.on_window(win(CAM, 0, incoming={OUTSIDE: 900}), True, 80)
    [a] = e.on_window(win(CAM, 2, incoming={OUTSIDE: 900}), True, 82)
    assert a.kind == "block" and a.target == OUTSIDE and a.source == "isolation_forest"
    assert a.ts == 4.0  # decided when the second window closes


def test_unregistered_lan_client_is_blocked_after_one_window():
    e = engine()
    [a] = e.on_window(win(CAM, 0, incoming={ATTACKER: 900, VIEWER: 10}), True, 75)
    assert a.target == ATTACKER and a.mac == ATTACKER_MAC
    assert e.on_window(win(CAM, 2, incoming={VIEWER: 10}), True, 75) == []  # streak was reset


def test_viewer_and_gateway_are_never_named_as_attacker():
    e = engine()
    e.on_window(win(CAM, 0, incoming={VIEWER: 900, GW: 50}), True, 80)
    [a] = e.on_window(win(CAM, 2, incoming={VIEWER: 900, GW: 50}), True, 80)
    assert a.kind == "alert" and VIEWER not in e.blocked_ips and GW not in e.blocked_ips


def test_non_consecutive_flags_reset_the_streak():
    e = engine()
    e.on_window(win(CAM, 0, incoming={OUTSIDE: 900}), True, 80)
    e.on_window(win(CAM, 2), False, 40)
    assert e.on_window(win(CAM, 4, incoming={OUTSIDE: 900}), True, 80) == []


def test_hijacked_camera_gets_its_new_destinations_blocked():
    e = engine()
    srv = ["10.10.0.70", "10.10.0.71"]
    e.on_window(win(CAM, 0, new=srv, attempts_out=5), True, 70)
    acts = e.on_window(win(CAM, 2, new=srv, attempts_out=5), True, 70)
    assert {a.target for a in acts} == set(srv) and all(a.victim == CAM for a in acts)
    assert CAM in e.suspect and CAM not in e.blocked_ips
    # once suspect, a further new destination is blocked right away
    [a] = e.on_window(win(CAM, 4, new=["10.10.0.72"]), True, 70)
    assert a.target == "10.10.0.72"


def test_replies_from_a_server_the_camera_called_are_not_an_inbound_attack():
    e = engine()
    w = lambda t: win(CAM, t, incoming={"10.10.0.70": 300}, new=["10.10.0.70"], attempts_out=3)
    e.on_window(w(0), True, 70)
    [a] = e.on_window(w(2), True, 70)
    assert "hijacked" in a.reason


def test_silent_camera_raises_one_alert_without_blocking():
    e = engine()
    e.on_window(win(CAM, 0, sent=0), True, 73)
    [a] = e.on_window(win(CAM, 2, sent=0), True, 73)
    assert a.kind == "alert" and "stopped sending video" in a.reason and not e.blocked_ips
    e.on_window(win(CAM, 4, sent=0), True, 73)
    assert e.on_window(win(CAM, 6, sent=0), True, 73) == []  # no repeat while it lasts


def test_never_blocks_a_camera_or_the_gateway():
    e = engine()
    assert e.on_suricata_alert(SuricataAlert(1.0, 1, CCTV, CAM, "odd")) == []
    assert not e.blocked_ips and not e.blocked_macs


def test_release_lets_the_attacker_be_blocked_again():
    e = engine()
    e.on_suricata_alert(SuricataAlert(1.0, 1, ATTACKER, CAM, "x"))
    e.release(ATTACKER, ATTACKER_MAC)
    assert e.on_suricata_alert(SuricataAlert(9.0, 1, ATTACKER, CAM, "x"))


# ---- spoofing (binding check) -----------------------------------------
def test_arp_spoof_of_the_gateway_blocks_the_spoofer_mac():
    reg = registry()
    e, check = DecisionEngine(reg), BindingCheck(reg)
    f = check.check(Observation(1.0, GW, ATTACKER_MAC, "arp"))
    assert f.kind == "ip_spoof" and f.victim_ip == GW
    [a] = e.on_spoof(f)
    assert a.mac == ATTACKER_MAC and a.target == ATTACKER and a.source == "binding_check"
    assert GW not in e.blocked_ips
    assert check.check(Observation(2.0, GW, ATTACKER_MAC, "arp")) is None  # reported once


def test_ip_spoof_of_a_camera_blocks_the_mac_never_the_camera_ip():
    reg = registry()
    e, check = DecisionEngine(reg), BindingCheck(reg)
    [a] = e.on_spoof(check.check(Observation(1.0, CAM, "11:22:33:44:55:66", "arp")))
    assert a.mac == "11:22:33:44:55:66" and a.target is None and a.key == "11:22:33:44:55:66"
    assert CAM not in e.blocked_ips


def test_cloned_camera_mac_blocks_the_impostor_ip_only():
    reg = registry()
    e, check = DecisionEngine(reg), BindingCheck(reg)
    f = check.check(Observation(1.0, "192.168.50.97", CAM_MAC, "dhcp"))
    assert f.kind == "mac_clone" and f.victim_ip == CAM
    [a] = e.on_spoof(f)
    assert a.target == "192.168.50.97" and a.mac is None
    assert CAM_MAC not in e.blocked_macs  # the real camera keeps working


def test_normal_bindings_are_learned_quietly():
    reg = registry()
    check = BindingCheck(reg)
    assert check.check(Observation(1.0, "192.168.50.40", "aa:aa:aa:aa:aa:aa")) is None
    assert check.check(Observation(1.0, CAM, CAM_MAC)) is None
    assert reg.mac_of("192.168.50.40") == "aa:aa:aa:aa:aa:aa"
    assert reg.mac_of(OUTSIDE) is None  # outside the LAN only the IP can be blocked
