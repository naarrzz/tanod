"""IP-MAC binding check: catches spoofing that Suricata and the Isolation Forest cannot see.

TANOD is the DHCP server and the access point, so it knows which MAC belongs
to each camera (DHCP reservation) and to the gateway. On the Pi the
observations come from ARP replies (arpwatch-style capture on wlan0/eth1),
DHCP requests (dnsmasq log) and the association table (hostapd_cli all_sta).

Two kinds of spoofing are caught:

1. IP spoofing / ARP spoofing: a different MAC claims a camera's IP or the
   gateway's IP ("192.168.50.1 is-at <attacker MAC>"), the first step of a
   man-in-the-middle attack. The IP belongs to the victim, so TANOD blocks the
   claiming MAC, never the IP.
2. MAC cloning: a camera's registered MAC shows up with a different IP while
   the camera is still at its reserved IP. The MAC belongs to the victim, so
   TANOD blocks the impostor's IP only and the real camera keeps working.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .registry import Registry


@dataclass(frozen=True)
class Observation:
    ts: float
    ip: str
    mac: str
    via: Literal["arp", "dhcp", "assoc"] = "arp"


@dataclass(frozen=True)
class SpoofFinding:
    ts: float
    kind: Literal["ip_spoof", "mac_clone"]
    victim_ip: str  # the camera or gateway being impersonated
    attacker_ip: str | None
    attacker_mac: str | None
    detail: str


class BindingCheck:
    def __init__(self, registry: Registry):
        self.reg = registry
        self.reported: set[tuple] = set()

    def _expected_mac(self, ip: str) -> str | None:
        if ip == self.reg.gateway_ip:
            return self.reg.gateway_mac
        d = self.reg.get(ip)
        return d.mac if d else None

    def check(self, obs: Observation) -> SpoofFinding | None:
        mac = obs.mac.lower()
        expected = self._expected_mac(obs.ip)
        owner = self.reg.owner_of_mac(mac)
        finding = None
        if expected and mac != expected:
            # someone else claims a protected IP
            who = "the gateway" if obs.ip == self.reg.gateway_ip else self.reg.get(obs.ip).name
            attacker_ip = next((ip for ip, m in self.reg.bindings.items() if m == mac and ip != obs.ip), None)
            finding = SpoofFinding(obs.ts, "ip_spoof", obs.ip, attacker_ip, mac,
                                   f"MAC {mac} claimed to be {who} ({obs.ip}) in an {obs.via.upper()} message")
        elif owner and obs.ip != owner.ip and self.reg.is_lan(obs.ip):
            # a camera's MAC appears at another IP
            finding = SpoofFinding(obs.ts, "mac_clone", owner.ip, obs.ip, None,
                                   f"{owner.name}'s MAC {mac} appeared at {obs.ip} while the camera is at {owner.ip}")
        else:
            self.reg.observe(obs.ip, mac)
            return None
        key = (finding.kind, finding.attacker_ip, finding.attacker_mac, finding.victim_ip)
        if key in self.reported:
            return None
        self.reported.add(key)
        return finding
