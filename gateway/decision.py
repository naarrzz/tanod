"""Detection and response logic (Figure 5, Section 3.6).

Rules:
1. A priority 1 Suricata alert leads directly to a response.
   - Source is an unregistered Wi-Fi client  -> block that client.
   - Source is a protected device             -> quarantine that device.
   - Otherwise (e.g. the simulated internet
     server attacking a device)               -> quarantine the targeted device.
2. Isolation Forest: a device is quarantined only after CONSECUTIVE_WINDOWS (2)
   flagged windows in a row.
3. If a flagged window shows that most of the traffic reaching the device came
   from one unregistered client, that client is blocked right away instead of
   quarantining the targeted device, and the device's flag streak is reset.
4. (Skeleton choice, not in the approved text; confirm with the advisers.)
   If a flagged device mostly received connection attempts (SYNs) instead of
   making them, and most of those came from another protected device, the
   window does not count toward the target's streak.
   The sender is judged by its own model, so in Test T6 only the hacked node
   is quarantined, not the devices it scanned.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .features import WINDOW_SECONDS, Window
from .model import CONSECUTIVE_WINDOWS
from .registry import Registry

ActionKind = Literal["quarantine", "block"]

# Share of incoming packets that one unregistered client must exceed to count
# as "most of the suspicious traffic".
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
    target: str  # IP of the device to quarantine or the client to block
    reason: str
    source: str  # "suricata" or "isolation_forest"
    ts: float
    risk: float | None = None
    evidence: dict = field(default_factory=dict)


class DecisionEngine:
    def __init__(self, registry: Registry, consecutive: int = CONSECUTIVE_WINDOWS):
        self.registry = registry
        self.consecutive = consecutive
        self.streak: dict[str, int] = {}
        self.quarantined: set[str] = set()
        self.blocked: set[str] = set()

    # ---- helpers -------------------------------------------------------
    def _majority_source(self, window: Window) -> tuple[str, float] | None:
        """The source of most packets reaching the device, if one source has a majority."""
        total = sum(window.incoming_by_src.values())
        if not total:
            return None
        src, count = window.incoming_by_src.most_common(1)[0]
        share = count / total
        return (src, share) if share > MAJORITY_SHARE else None

    def _targeted_by_protected_device(self, window: Window) -> bool:
        received = sum(window.attempts_in_by_src.values())
        if not received or received <= window.attempts_out:
            return False
        src, count = window.attempts_in_by_src.most_common(1)[0]
        return count / received > MAJORITY_SHARE and self.registry.is_protected(src)

    def _block(self, client: str, **kw) -> Action | None:
        if client in self.blocked:
            return None
        self.blocked.add(client)
        return Action(kind="block", target=client, **kw)

    def _quarantine(self, device: str, **kw) -> Action | None:
        if device in self.quarantined:
            return None
        self.quarantined.add(device)
        self.streak[device] = 0
        return Action(kind="quarantine", target=device, **kw)

    # ---- inputs --------------------------------------------------------
    def on_suricata_alert(self, alert: SuricataAlert) -> Action | None:
        if alert.priority != 1:
            return None
        reg = self.registry
        ev = {"signature": alert.signature, "sid": alert.sid, "src": alert.src, "dst": alert.dst}
        common = dict(source="suricata", ts=alert.ts, evidence=ev)
        if reg.is_unregistered_client(alert.src):
            return self._block(alert.src, reason=f"Unregistered client attacked {alert.dst}: {alert.signature}", **common)
        if reg.is_protected(alert.src):
            return self._quarantine(alert.src, reason=f"Device sent attack traffic: {alert.signature}", **common)
        if reg.is_protected(alert.dst):
            return self._quarantine(alert.dst, reason=f"Device targeted by known attack: {alert.signature}", **common)
        return None

    def on_window(self, window: Window, flagged: bool, risk: float) -> Action | None:
        dev = window.device
        if dev in self.quarantined:
            return None
        if not flagged:
            self.streak[dev] = 0
            return None

        decided_at = window.start + WINDOW_SECONDS  # the window closes before it is scored
        ev = {"window_start": window.start, "features": window.as_dict(), "new_destinations": window.new_dst_list,
              "top_sources": window.incoming_by_src.most_common(5)}
        maj = self._majority_source(window)
        if maj and self.registry.is_unregistered_client(maj[0]):
            client, share = maj
            self.streak[dev] = 0
            ev["share_from_client"] = round(share, 3)
            return self._block(client, reason=f"Unusual traffic to {dev} came mostly from unregistered client {client}",
                               source="isolation_forest", ts=decided_at, risk=risk, evidence=ev)
        if self._targeted_by_protected_device(window):
            # rule 4: the sending device is judged by its own model
            self.streak[dev] = 0
            return None

        self.streak[dev] = self.streak.get(dev, 0) + 1
        if self.streak[dev] >= self.consecutive:
            return self._quarantine(dev, reason=f"Unusual behavior in {self.consecutive} windows in a row",
                                    source="isolation_forest", ts=decided_at, risk=risk, evidence=ev)
        return None

    # ---- owner actions -------------------------------------------------
    def release(self, target: str) -> None:
        self.quarantined.discard(target)
        self.blocked.discard(target)
        self.streak[target] = 0
