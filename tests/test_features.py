import pytest

from gateway.features import (FEATURE_NAMES, Packet, device_window_features, extract_windows,
                              learn_baseline_destinations, window_start)

DEV = "192.168.50.11"
SRV = "10.10.0.5"


def test_ten_features_in_table4_order():
    assert len(FEATURE_NAMES) == 10
    w = device_window_features(DEV, [])
    assert len(w.features) == 10
    assert all(v == 0 for v in w.features)


def test_bytes_packets_and_mean_size():
    pk = [
        Packet(0.1, DEV, SRV, 100, dport=1883),
        Packet(0.2, DEV, SRV, 300, dport=1883),
        Packet(0.3, SRV, DEV, 200, sport=1883),
    ]
    f = device_window_features(DEV, pk).as_dict()
    assert f["bytes_sent"] == 400
    assert f["bytes_received"] == 200
    assert f["packets_sent"] == 2
    assert f["mean_packet_size"] == pytest.approx(200)


def test_unique_destinations_ports_and_new_destinations():
    pk = [
        Packet(0.1, DEV, SRV, 60, dport=1883),
        Packet(0.2, DEV, "10.10.0.99", 60, dport=4444),
        Packet(0.3, DEV, "10.10.0.99", 60, dport=4445),
    ]
    w = device_window_features(DEV, pk, baseline_dsts={SRV})
    f = w.as_dict()
    assert f["unique_dst_addrs"] == 2
    assert f["unique_dst_ports"] == 3
    assert f["new_dsts"] == 1
    assert w.new_dst_list == ["10.10.0.99"]


def test_connection_attempts_and_failed_ratio():
    pk = [
        # answered attempt
        Packet(0.1, DEV, SRV, 60, sport=5000, dport=80, syn=True),
        Packet(0.11, SRV, DEV, 60, sport=80, dport=5000, syn=True, ack=True),
        # refused attempt (RST)
        Packet(0.2, DEV, SRV, 60, sport=5001, dport=81, syn=True),
        Packet(0.21, SRV, DEV, 54, sport=81, dport=5001, rst=True, ack=True),
        # no reply
        Packet(0.3, DEV, SRV, 60, sport=5002, dport=82, syn=True),
        # incoming attempt from an attacker, no reply
        Packet(0.4, "192.168.50.99", DEV, 60, sport=6000, dport=23, syn=True),
    ]
    w = device_window_features(DEV, pk)
    f = w.as_dict()
    assert f["conn_attempts"] == 4
    assert f["failed_conn_ratio"] == pytest.approx(3 / 4)
    assert w.attempts_out == 3
    assert w.attempts_in_by_src["192.168.50.99"] == 1


def test_interpacket_variation_regular_vs_irregular():
    regular = [Packet(t * 0.5, DEV, SRV, 60) for t in range(4)]
    irregular = [Packet(t, DEV, SRV, 60) for t in (0.0, 0.1, 0.15, 1.9)]
    cv_reg = device_window_features(DEV, regular).as_dict()["ipt_variation"]
    cv_irr = device_window_features(DEV, irregular).as_dict()["ipt_variation"]
    assert cv_reg == pytest.approx(0.0)
    assert cv_irr > 0.5


def test_windows_are_two_seconds_and_fill_empty():
    assert window_start(3.9) == 2.0
    pk = [Packet(0.5, DEV, SRV, 100), Packet(6.5, DEV, SRV, 100)]
    ws = extract_windows(pk, [DEV])
    assert [w.start for w in ws] == [0.0, 2.0, 4.0, 6.0]
    assert ws[1].features == [0.0] * 10  # silent window still present


def test_incoming_sources_counted_for_attribution():
    pk = [Packet(0.1 + i / 100, "192.168.50.99", DEV, 60) for i in range(9)] + [Packet(0.5, SRV, DEV, 60)]
    w = device_window_features(DEV, pk)
    assert w.incoming_by_src.most_common(1)[0] == ("192.168.50.99", 9)


def test_learn_baseline_destinations():
    pk = [Packet(0, DEV, SRV, 1), Packet(1, DEV, "192.168.50.1", 1), Packet(2, SRV, DEV, 1)]
    assert learn_baseline_destinations(pk, DEV) == {SRV, "192.168.50.1"}
