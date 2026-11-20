"""Read Suricata alerts from eve.json (one JSON object per line)."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Iterable, Iterator

from .decision import SuricataAlert


def parse_eve_line(line: str) -> SuricataAlert | None:
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return None
    if ev.get("event_type") != "alert":
        return None
    a = ev.get("alert", {})
    ts = ev.get("timestamp")
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() if ts else 0.0
    except ValueError:
        t = 0.0
    return SuricataAlert(
        ts=t,
        priority=int(a.get("severity", 3)),  # Suricata calls the priority "severity"
        src=ev.get("src_ip", ""),
        dst=ev.get("dest_ip", ""),
        signature=a.get("signature", ""),
        sid=int(a.get("signature_id", 0)),
    )


def read_alerts(lines: Iterable[str]) -> Iterator[SuricataAlert]:
    for line in lines:
        alert = parse_eve_line(line)
        if alert:
            yield alert
