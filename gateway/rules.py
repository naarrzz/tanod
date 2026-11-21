"""Laptop stand-in for Suricata with TANOD's local rules (suricata/tanod.rules).

On the Pi, Suricata itself reads the traffic and gateway/suricata.py reads its
eve.json. On a laptop there is no Suricata, so this module applies the same
rules with the same thresholds to the simulated packets. That keeps the
Setup A (Suricata only) results honest: an attack counts as caught by Suricata
only if one of these signatures would fire.

Suricata does not look at ARP or Wi-Fi management frames, so ARP spoofing,
MAC cloning and deauthentication are never caught here (see spoof.py).
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Iterable

from .decision import SuricataAlert
from .features import Packet
from .registry import Registry

STREAM_PORTS = {554, 8554}
LOGIN_PORTS = {80, 443, 554, 8080}


@dataclass(frozen=True)
class Rule:
    sid: int
    msg: str
    count: int  # detection_filter count (1 = every match)
    seconds: float

    def matches(self, p: Packet, reg: Registry) -> bool:
        if not reg.is_protected(p.dst):
            return False
        syn = p.proto == "tcp" and p.syn and not p.ack
        if self.sid == 9000001:
            return syn
        if self.sid == 9000002:
            return syn and p.dport in LOGIN_PORTS and not reg.is_viewer(p.src)
        if self.sid == 9000003:
            return p.proto == "udp"
        if self.sid == 9000005:
            return syn
        if self.sid == 9000004:
            return syn and p.dport in STREAM_PORTS and not reg.is_viewer(p.src)
        return False


RULES = [
    Rule(9000001, "TANOD local: port scan on a camera", 20, 5),
    Rule(9000002, "TANOD local: repeated logins to a camera", 15, 10),
    Rule(9000003, "TANOD local: UDP flood on a camera", 500, 1),
    Rule(9000005, "TANOD local: SYN flood on a camera", 500, 1),
    Rule(9000004, "TANOD local: camera stream opened by an unapproved client", 1, 1),
]


def evaluate(packets: Iterable[Packet], reg: Registry) -> list[SuricataAlert]:
    """Alerts Suricata would raise, one per (rule, source, camera): the first time each fires."""
    seen: dict[tuple, deque] = defaultdict(deque)
    fired: set[tuple] = set()
    out: list[SuricataAlert] = []
    for p in sorted(packets, key=lambda p: p.ts):
        for r in RULES:
            key = (r.sid, p.src, p.dst)
            if key in fired or not r.matches(p, reg):
                continue
            q = seen[key]
            q.append(p.ts)
            while q and p.ts - q[0] > r.seconds:
                q.popleft()
            if len(q) >= r.count:
                fired.add(key)
                out.append(SuricataAlert(p.ts, 1, p.src, p.dst, r.msg, r.sid))
    return out
