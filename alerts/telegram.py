"""Plain-language alerts in Telegram Bot API sendMessage format.

During isolated tests the alerts go to a local endpoint (alerts/mock_server.py),
never to api.telegram.org. Real Telegram delivery is checked separately on an
ordinary network with no attack simulation running (Section 3.11, T11).

Config (environment variables):
  TANOD_ALERT_ENDPOINT  base URL, default http://127.0.0.1:8081 (local mock)
  TANOD_BOT_TOKEN       bot token, default "test-token"
  TANOD_CHAT_ID         owner chat id, default "0"
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from datetime import datetime

DEFAULT_ENDPOINT = "http://127.0.0.1:8081"

# What the owner should do, in plain words, per response type.
NEXT_STEPS = {
    "quarantine": (
        "What to do: unplug the device, then reset it or ask your installer or a technician to check it. "
        "When it is safe, open the TANOD dashboard and click Release."
    ),
    "block": (
        "What to do: change the Wi-Fi password and do not share it. "
        "If you know this device, you can release it from the TANOD dashboard."
    ),
}


def build_message(action_kind: str, device_name: str, target: str, reason: str,
                  risk: float | None = None, ts: float | None = None) -> str:
    when = datetime.fromtimestamp(ts or time.time()).strftime("%Y-%m-%d %H:%M:%S")
    if action_kind == "quarantine":
        head = f"TANOD: {device_name} was cut off from the network."
    else:
        head = f"TANOD: An unknown device ({target}) was blocked from your network."
    lines = [head, f"Why: {reason}."]
    if risk is not None:
        lines.append(f"Risk score: {risk:.0f} out of 100.")
    lines.append(f"Time: {when}")
    lines.append(NEXT_STEPS.get(action_kind, ""))
    return "\n".join(l for l in lines if l)


def build_payload(text: str, chat_id: str | None = None) -> dict:
    return {
        "chat_id": chat_id or os.environ.get("TANOD_CHAT_ID", "0"),
        "text": text,
        "disable_web_page_preview": True,
    }


def send(payload: dict, endpoint: str | None = None, token: str | None = None, timeout: float = 5.0) -> dict:
    endpoint = (endpoint or os.environ.get("TANOD_ALERT_ENDPOINT", DEFAULT_ENDPOINT)).rstrip("/")
    token = token or os.environ.get("TANOD_BOT_TOKEN", "test-token")
    url = f"{endpoint}/bot{token}/sendMessage"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode() or "{}")
