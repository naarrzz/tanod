import json
import subprocess

import pytest

from alerts import telegram
from gateway.enforce import Enforcer, block_commands, release_commands, setup_commands
from gateway.suricata import parse_eve_line

MAC = "DE:AD:BE:EF:00:99"
IP = "192.168.50.99"


def flat(cmds):
    return [" ".join(c) for c in cmds]


def test_lan_attacker_is_blocked_by_mac_and_kicked_off_the_wifi():
    f = flat(block_commands(IP, MAC))
    assert "nft add element inet tanod block_mac { de:ad:be:ef:00:99 }" in f
    assert "hostapd_cli -i wlan0 deny_acl ADD_MAC de:ad:be:ef:00:99" in f
    assert "hostapd_cli -i wlan0 deauthenticate de:ad:be:ef:00:99" in f
    assert "nft add element inet tanod block_ip { 192.168.50.99 }" in f


def test_outside_attacker_is_blocked_by_ip_only():
    f = flat(block_commands("10.10.0.66"))
    assert not any("block_mac" in c or "hostapd" in c for c in f)
    assert "nft add element inet tanod block_ip { 10.10.0.66 }" in f


def test_mac_only_block_has_no_ip_rule():
    f = flat(block_commands(mac=MAC))
    assert not any("block_ip" in c for c in f)


def test_setup_drops_blocked_macs_and_ips_everywhere():
    f = flat(setup_commands())
    assert any("forward ether saddr @block_mac drop" in c for c in f)
    assert any("input ether saddr @block_mac drop" in c for c in f)
    assert any("forward ip daddr @block_ip drop" in c for c in f)
    assert not any("quarantine" in c for c in f)  # the camera is never cut off


def test_bad_addresses_are_rejected():
    with pytest.raises(ValueError):
        block_commands("192.168.50.11; rm -rf /")
    with pytest.raises(ValueError):
        block_commands(mac="not-a-mac")
    with pytest.raises(ValueError):
        block_commands()


def test_release_removes_from_both_sets_and_the_deny_list():
    f = flat(release_commands(IP, MAC))
    assert "nft delete element inet tanod block_ip { 192.168.50.99 }" in f
    assert "nft delete element inet tanod block_mac { de:ad:be:ef:00:99 }" in f
    assert "hostapd_cli -i wlan0 deny_acl DEL_MAC de:ad:be:ef:00:99" in f


def test_dry_run_by_default_runs_nothing():
    ran = []
    e = Enforcer(runner=ran.append)
    e.block(IP, MAC)
    assert ran == [] and e.executed


def test_wired_attacker_not_in_hostapd_does_not_stop_the_block():
    ran = []

    def runner(cmd):
        ran.append(cmd[0])
        if cmd[0] == "hostapd_cli":
            raise subprocess.CalledProcessError(1, cmd, stderr="FAIL")

    Enforcer(dry_run=False, runner=runner).block(IP, MAC)
    assert ran.count("nft") == 2  # MAC and IP still blocked


def test_nft_failure_is_not_hidden():
    def runner(cmd):
        raise subprocess.CalledProcessError(1, cmd)

    with pytest.raises(subprocess.CalledProcessError):
        Enforcer(dry_run=False, runner=runner).block(IP)


def test_alert_message_is_plain_language_and_telegram_shaped():
    text = telegram.build_message("block", "Wi-Fi Camera", "192.168.50.99",
                                  "Attacked Wi-Fi Camera: port scan", 81.2, ts=0)
    assert "attack on Wi-Fi Camera was blocked" in text and "kept recording" in text and "81 out of 100" in text
    p = telegram.build_payload(text, chat_id="123")
    assert set(p) >= {"chat_id", "text"} and p["chat_id"] == "123"


def test_no_attacker_alert_says_nothing_was_blocked():
    text = telegram.build_message("alert", "Wi-Fi Camera", "192.168.50.20", "Wi-Fi Camera stopped sending video")
    assert "Nothing was blocked" in text


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
    assert "skipped" in telegram.notify("block", "IP Camera", "192.168.50.99", "test")


def test_release_message_and_env_file(tmp_path, monkeypatch):
    from alerts import telegram
    msg = telegram.build_message("release", "IP Camera", "192.168.50.99", "Unblocked by narz")
    assert msg.startswith("TANOD: 192.168.50.99 was unblocked")
    monkeypatch.setenv("TANOD_CHAT_ID", "0")
    monkeypatch.delenv("TANOD_CHAT_ID")  # restored after the test
    (tmp_path / ".env").write_text("# comment\nTANOD_CHAT_ID='12345'\n")
    telegram.load_env(str(tmp_path / ".env"))
    import os
    assert os.environ["TANOD_CHAT_ID"] == "12345"
