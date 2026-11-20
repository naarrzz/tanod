import json

import pytest

from alerts import telegram
from gateway.enforce import Enforcer, MockRelay, block_commands, quarantine_commands, release_commands
from gateway.registry import Device
from gateway.suricata import parse_eve_line

DEV = Device("ESP32 Node 1", "AA:BB:CC:00:00:01", "192.168.50.11", relay_channel=1)


def test_quarantine_commands_use_mac_and_ip_sets():
    cmds = quarantine_commands(DEV.ip, DEV.mac)
    flat = [" ".join(c) for c in cmds]
    assert "nft add element inet tanod quarantine_mac { aa:bb:cc:00:00:01 }" in flat
    assert "nft add element inet tanod quarantine_ip { 192.168.50.11 }" in flat


def test_bad_addresses_are_rejected():
    with pytest.raises(ValueError):
        quarantine_commands("192.168.50.11; rm -rf /", DEV.mac)
    with pytest.raises(ValueError):
        block_commands("1.2.3.4", "not-a-mac")


def test_release_deletes_from_the_right_sets():
    flat = [" ".join(c) for c in release_commands("192.168.50.99", kind="block")]
    assert flat == ["nft delete element inet tanod block_ip { 192.168.50.99 }"]


def test_dry_run_by_default_runs_nothing():
    ran = []
    e = Enforcer(runner=ran.append)
    e.quarantine(DEV)
    assert e.dry_run and ran == [] and e.executed


def test_relay_cutoff_off_by_default():
    relay = MockRelay()
    Enforcer(relay=relay).quarantine(Device(**{**DEV.__dict__, "relay_cutoff_enabled": True}))
    assert relay.history == []  # enforcer-level switch is off
    Enforcer(relay=relay, relay_enabled=True).quarantine(DEV)
    assert relay.history == []  # device-level switch is off


def test_relay_cut_and_restore_when_enabled():
    relay = MockRelay()
    dev = Device(**{**DEV.__dict__, "relay_cutoff_enabled": True})
    e = Enforcer(relay=relay, relay_enabled=True)
    e.quarantine(dev)
    assert relay.state(1) == "cut"
    e.release(dev.ip, dev.mac, relay_channel=1)
    assert relay.state(1) == "on"


def test_alert_message_is_plain_language_and_telegram_shaped():
    text = telegram.build_message("quarantine", "IP Camera", "192.168.50.20",
                                  "Unusual behavior in 2 windows in a row", 81.2, ts=0)
    assert "IP Camera was cut off" in text and "Release" in text and "81 out of 100" in text
    p = telegram.build_payload(text, chat_id="123")
    assert set(p) >= {"chat_id", "text"} and p["chat_id"] == "123"


def test_default_endpoint_is_local():
    assert telegram.DEFAULT_ENDPOINT.startswith("http://127.0.0.1")


def test_parse_suricata_eve_alert():
    line = json.dumps({"timestamp": "2026-11-19T10:00:00.000000+0800", "event_type": "alert",
                       "src_ip": "192.168.50.99", "dest_ip": "192.168.50.20",
                       "alert": {"severity": 1, "signature": "ET SCAN", "signature_id": 2001}})
    a = parse_eve_line(line)
    assert a.priority == 1 and a.src == "192.168.50.99" and a.sid == 2001
    assert parse_eve_line(json.dumps({"event_type": "flow"})) is None


def test_notify_skips_without_bot(monkeypatch):
    from alerts import telegram
    monkeypatch.delenv("TANOD_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TANOD_CHAT_ID", raising=False)
    assert not telegram.configured()
    assert "skipped" in telegram.notify("quarantine", "IP Camera", "192.168.50.20", "test")


def test_release_message_and_env_file(tmp_path, monkeypatch):
    from alerts import telegram
    msg = telegram.build_message("release", "IP Camera", "192.168.50.20", "Released by narz")
    assert msg.startswith("TANOD: IP Camera (192.168.50.20) was reconnected")
    monkeypatch.setenv("TANOD_CHAT_ID", "0")
    monkeypatch.delenv("TANOD_CHAT_ID")  # restored after the test
    (tmp_path / ".env").write_text("# comment\nTANOD_CHAT_ID='12345'\n")
    telegram.load_env(str(tmp_path / ".env"))
    import os
    assert os.environ["TANOD_CHAT_ID"] == "12345"
