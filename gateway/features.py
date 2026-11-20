"""Per-device traffic features over 2-second windows (Table 4).

The extractor only needs packet header metadata, so it works the same with a
live capture on the Pi (wlan0) or with synthetic packets on a laptop.

Feature vector order (FEATURE_NAMES):
 1 bytes_sent            bytes the device sent
 2 bytes_received        bytes the device received
 3 packets_sent          packets the device sent
 4 mean_packet_size      mean size of all packets to/from the device
 5 unique_dst_addrs      distinct destination IPs the device sent to
 6 unique_dst_ports      distinct destination ports the device sent to
 7 new_dsts              destination IPs the device sent to that are not in its baseline
 8 conn_attempts         TCP connection attempts (SYN without ACK) to or from the device
 9 failed_conn_ratio     share of those attempts with no SYN-ACK reply in the window
10 ipt_variation         coefficient of variation of the time between sent packets

Incoming attempts are counted too (8, 9), so a port scan or password guessing
against a device also shows up in that device's window. The decision logic then
checks who sent the traffic (see decision.py).
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable

WINDOW_SECONDS = 2.0

FEATURE_NAMES = [
    "bytes_sent",
    "bytes_received",
    "packets_sent",
    "mean_packet_size",
    "unique_dst_addrs",
    "unique_dst_ports",
    "new_dsts",
    "conn_attempts",
    "failed_conn_ratio",
    "ipt_variation",
]


@dataclass(frozen=True)
class Packet:
    """Header metadata of one packet seen at the gateway."""

    ts: float
    src: str
    dst: str
    size: int
    proto: str = "tcp"  # tcp, udp, icmp, ...
    sport: int = 0
    dport: int = 0
    syn: bool = False
    ack: bool = False
    rst: bool = False


@dataclass
class Window:
    """Features of one device in one window, plus evidence for the dashboard."""

    device: str  # device IP
    start: float
    features: list[float]
    # packets received by the device, per source IP (used to find the attacker)
    incoming_by_src: Counter = field(default_factory=Counter)
    # TCP connection attempts (SYN) the device received, per source, and sent
    attempts_in_by_src: Counter = field(default_factory=Counter)
    attempts_out: int = 0
    new_dst_list: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, float]:
        return dict(zip(FEATURE_NAMES, self.features))


def window_start(ts: float, size: float = WINDOW_SECONDS) -> float:
    return math.floor(ts / size) * size


def _cv(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    if mean <= 0:
        return 0.0
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(var) / mean


def device_window_features(
    device: str,
    packets: list[Packet],
    baseline_dsts: set[str] | None = None,
    start: float = 0.0,
) -> Window:
    """Compute the ten features for one device from the packets of one window."""
    baseline_dsts = baseline_dsts or set()
    sent = [p for p in packets if p.src == device]
    received = [p for p in packets if p.dst == device]

    bytes_sent = sum(p.size for p in sent)
    bytes_received = sum(p.size for p in received)
    all_pk = sent + received
    mean_size = (bytes_sent + bytes_received) / len(all_pk) if all_pk else 0.0

    dst_addrs = {p.dst for p in sent}
    dst_ports = {p.dport for p in sent if p.dport}
    new_dsts = sorted(dst_addrs - baseline_dsts)

    # TCP handshakes in either direction. key = (client, cport, server, sport)
    attempts: set[tuple] = set()
    answered: set[tuple] = set()
    for p in all_pk:
        if p.proto != "tcp":
            continue
        if p.syn and not p.ack:
            attempts.add((p.src, p.sport, p.dst, p.dport))
        elif p.syn and p.ack:
            answered.add((p.dst, p.dport, p.src, p.sport))
    failed = len(attempts - answered)
    failed_ratio = failed / len(attempts) if attempts else 0.0

    times = sorted(p.ts for p in sent)
    gaps = [b - a for a, b in zip(times, times[1:])]

    features = [
        float(bytes_sent),
        float(bytes_received),
        float(len(sent)),
        float(mean_size),
        float(len(dst_addrs)),
        float(len(dst_ports)),
        float(len(new_dsts)),
        float(len(attempts)),
        float(failed_ratio),
        float(_cv(gaps)),
    ]
    return Window(
        device=device,
        start=start,
        features=features,
        incoming_by_src=Counter(p.src for p in received),
        attempts_in_by_src=Counter(a[0] for a in attempts if a[2] == device),
        attempts_out=sum(1 for a in attempts if a[0] == device),
        new_dst_list=new_dsts,
    )


def extract_windows(
    packets: Iterable[Packet],
    devices: Iterable[str],
    baselines: dict[str, set[str]] | None = None,
    size: float = WINDOW_SECONDS,
    fill_empty: bool = True,
) -> list[Window]:
    """Group packets into windows and compute features for every device.

    With fill_empty, devices that were silent in a window still get an all-zero
    window, so the model also learns what "idle" looks like.
    """
    devices = list(devices)
    baselines = baselines or {}
    dev_set = set(devices)
    buckets: dict[float, list[Packet]] = defaultdict(list)
    for p in packets:
        if p.src in dev_set or p.dst in dev_set:
            buckets[window_start(p.ts, size)].append(p)
    if not buckets:
        return []

    starts = sorted(buckets)
    if fill_empty:
        n = int(round((starts[-1] - starts[0]) / size)) + 1
        starts = [starts[0] + i * size for i in range(n)]

    out: list[Window] = []
    for s in starts:
        pk = buckets.get(s, [])
        for d in devices:
            out.append(device_window_features(d, pk, baselines.get(d), start=s))
    return out


def learn_baseline_destinations(packets: Iterable[Packet], device: str) -> set[str]:
    """Destinations a device contacted during baseline collection."""
    return {p.dst for p in packets if p.src == device}
