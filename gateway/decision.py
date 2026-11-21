"""Detection and response logic (Section 3.6).

TANOD blocks the attacker, never the camera being attacked, so the camera keeps
recording (Availability). The attacker is blocked by MAC address when it is on
the LAN (changing its IP does not get it back in) and by IP when it is outside
the LAN (its packets arrive with the upstream router's MAC).

Rules:
1. A priority 1 Suricata alert leads directly to a response.
   - A camera is the target      -> block the source (the attacker).
   - A camera is the source      -> the camera looks hijacked: block the address it
                                     attacked or reported to; the camera stays online
                                     and the owner is told to check it.
2. Isolation Forest: a camera counts as attacked after CONSECUTIVE_WINDOWS (2)
   flagged windows in a row. TANOD then finds the attacker in the evidence:
   a. most of the traffic reaching the camera came from one address
      (not the gateway, not an approved viewer)  -> block that address;
   b. the camera itself sent data to new destinations -> block those destinations
      (hijacked camera talking to its controller);
   c. no attacker can be named (e.g. the camera went silent after a Wi-Fi
      deauthentication)                           -> alert the owner, no block.
   An unregistered LAN client sending most of the traffic is blocked after the
   first flagged window, because it should not be talking to the camera at all.
3. IP-MAC binding check (spoof.py): a MAC claiming a camera's or the gateway's IP
   is blocked by MAC; a cloned camera MAC at another IP is blocked by that IP.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .features import WINDOW_SECONDS, Window
from .model import CONSECUTIVE_WINDOWS
from .registry import Registry

ActionKind = Literal["block", "alert"]

# Share of incoming packets that one source must exceed to count as "most of the traffic".
MAJORITY_SHARE = 0.5


@dataclass
class SuricataAlert:
    ts: float
    priority: int
    src: str
    dst: str
    signature: str
    sid: int = 0


@dataclass
class Action:
    kind: ActionKind
    target: str | None  # attacker IP (None when only the MAC is known); the camera for "alert"
    reason: str
    source: str  # "suricata", "isolation_forest" or "binding_check"
    ts: float
    victim: str = ""  # the camera (or gateway) that was attacked
    mac: str | None = None  # attacker MAC, when it is on the LAN
    risk: float | None = None
    evidence: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        """What the dashboard lists and releases: the IP, or the MAC when no IP is known."""
        return self.target or self.mac or ""


class DecisionEngine:
    def __init__(self, registry: Registry, consecutive: int = CONSECUTIVE_WINDOWS):
        self.registry = registry
        self.consecutive = consecutive
        self.streak: dict[str, int] = {}
        self.blocked_ips: set[str] = set()
        self.blocked_macs: set[str] = set()
        self.alerted: set[str] = set()  # cameras with an open "no attacker found" alert
        self.suspect: set[str] = set()  # cameras that look hijacked

    # ---- helpers -------------------------------------------------------
    def is_blocked(self, ip: str | None = None, mac: str | None = None) -> bool:
        return (ip is not None and ip in self.blocked_ips) or (mac is not None and mac in self.blocked_macs)

    def _block(self, ip: str | None, victim: str, reason: str, source: str, ts: float,
               mac: str | None = None, risk=None, evidence=None, use_mac: bool = True) -> Action | None:
        reg = self.registry
        if use_mac and mac is None and ip is not None and not reg.is_protected(ip):
            mac = reg.mac_of(ip)
        if mac and reg.owner_of_mac(mac):
            mac = None  # never block a camera's own MAC
        if ip is not None and (reg.is_protected(ip) or ip == reg.gateway_ip):
            ip = None  # never block a camera's or the gateway's IP
        if ip is None and mac is None:
            return None
        if not ((ip and ip not in self.blocked_ips) or (mac and mac not in self.blocked_macs)):
            return None  # already blocked
        if ip:
            self.blocked_ips.add(ip)
        if mac:
            self.blocked_macs.add(mac)
        ev = dict(evidence or {})
        ev.update(attacker_ip=ip, attacker_mac=mac, victim=victim)
        return Action("block", ip, reason, source, ts, victim=victim, mac=mac, risk=risk, evidence=ev)

    def _name(self, ip: str) -> str:
        d = self.registry.get(ip)
        return d.name if d else ip

    def _majority_source(self, window: Window) -> tuple[str, float] | None:
        """The address that sent most of the traffic reaching the camera, ignoring
        the gateway and approved viewers."""
        reg = self.registry
        counts = {s: n for s, n in window.incoming_by_src.items()
                  if s != reg.gateway_ip and not reg.is_viewer(s)}
        total = sum(window.incoming_by_src.values())
        if not total or not counts:
            return None
        src = max(counts, key=counts.get)
        share = counts[src] / total
        # Traffic the camera asked for (replies from a server it connected to) is not an attack on it.
        inbound = window.attempts_in_by_src.get(src, 0) > 0 or src not in window.new_dst_list
        return (src, share) if share > MAJORITY_SHARE and inbound else None

    # ---- inputs --------------------------------------------------------
    def on_suricata_alert(self, alert: SuricataAlert) -> list[Action]:
        if alert.priority != 1:
            return []
        reg = self.registry
        ev = {"signature": alert.signature, "sid": alert.sid, "src": alert.src, "dst": alert.dst}
        if reg.is_protected(alert.dst):
            act = self._block(alert.src, alert.dst, f"Attacked {self._name(alert.dst)}: {alert.signature}",
                              "suricata", alert.ts, evidence=ev)
            return [act] if act else []
        if reg.is_protected(alert.src):
            self.suspect.add(alert.src)
            act = self._block(alert.dst, alert.src,
                              f"{self._name(alert.src)} sent attack traffic to {alert.dst} ({alert.signature}); "
                              "the camera may be hijacked", "suricata", alert.ts, evidence=ev)
            return [act] if act else []
        return []

    def on_window(self, window: Window, flagged: bool, risk: float) -> list[Action]:
        cam = window.device
        reg = self.registry
        if not flagged:
            self.streak[cam] = 0
            self.alerted.discard(cam)
            return []

        decided_at = window.start + WINDOW_SECONDS  # the window closes before it is scored
        ev = {"window_start": window.start, "features": window.as_dict(), "new_destinations": window.new_dst_list,
              "top_sources": window.incoming_by_src.most_common(5)}
        self.streak[cam] = self.streak.get(cam, 0) + 1
        maj = self._majority_source(window)

        # an unknown LAN client hammering the camera: no need to wait for a second window
        if maj and reg.is_unregistered_client(maj[0]) and not self.is_blocked(maj[0]):
            src, share = maj
            self.streak[cam] = 0
            act = self._block(src, cam, f"Unusual traffic to {self._name(cam)} came mostly from {src}",
                              "isolation_forest", decided_at, risk=risk, evidence={**ev, "share_from_source": round(share, 3)})
            return [act] if act else []

        # a camera already known to be hijacked: block each new destination at once
        new = [d for d in window.new_dst_list if not self.is_blocked(d) and not reg.is_protected(d)]
        if cam in self.suspect and new:
            return [a for a in (self._block(d, cam, f"{self._name(cam)} started sending data to {d}; "
                                            "the camera may be hijacked", "isolation_forest", decided_at,
                                            risk=risk, evidence=ev) for d in new) if a]

        if self.streak[cam] < self.consecutive:
            return []
        self.streak[cam] = 0

        if maj and not self.is_blocked(maj[0]):
            src, share = maj
            act = self._block(src, cam, f"Unusual traffic to {self._name(cam)} in {self.consecutive} windows "
                                        f"in a row came mostly from {src}", "isolation_forest", decided_at,
                              risk=risk, evidence={**ev, "share_from_source": round(share, 3)})
            return [act] if act else []
        if new:
            self.suspect.add(cam)
            return [a for a in (self._block(d, cam, f"{self._name(cam)} started sending data to {d}; "
                                            "the camera may be hijacked", "isolation_forest", decided_at,
                                            risk=risk, evidence=ev) for d in new) if a]
        if cam in self.alerted:
            return []
        self.alerted.add(cam)
        quiet = window.features[2] == 0  # packets_sent
        why = ("stopped sending video (possible Wi-Fi deauthentication or power loss)" if quiet
               else f"behaved unusually in {self.consecutive} windows in a row, but no attacker could be named")
        return [Action("alert", cam, f"{self._name(cam)} {why}", "isolation_forest", decided_at,
                       victim=cam, risk=risk, evidence=ev)]

    def on_spoof(self, f) -> list[Action]:
        """A finding from spoof.BindingCheck."""
        ev = {"detail": f.detail, "spoof": f.kind}
        if f.kind == "ip_spoof":
            act = self._block(f.attacker_ip if f.attacker_ip else None, f.victim_ip,
                              f"Spoofing: {f.detail}", "binding_check", f.ts, mac=f.attacker_mac, evidence=ev)
        else:
            act = self._block(f.attacker_ip, f.victim_ip, f"MAC cloning: {f.detail}", "binding_check", f.ts,
                              evidence=ev, use_mac=False)
        return [act] if act else []

    # ---- owner actions -------------------------------------------------
    def release(self, ip: str | None = None, mac: str | None = None) -> None:
        if ip:
            self.blocked_ips.discard(ip)
            self.streak[ip] = 0
            self.suspect.discard(ip)
        if mac:
            self.blocked_macs.discard(mac.lower())
