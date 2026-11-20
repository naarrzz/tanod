"""Plain-language alerts in Telegram Bot API sendMessage format.

During isolated tests the alerts go to a local endpoint (alerts/mock_server.py),
never to api.telegram.org. Real Telegram delivery is checked separately on an
ordinary network with no attack simulation running (Section 3.11, T11).

Config (environment variables, or a .env file in the repo folder, never committed):
  TANOD_ALERT_ENDPOINT  base URL, default http://127.0.0.1:8081 (local mock);
                        https://api.telegram.org for the real bot
  TANOD_BOT_TOKEN       bot token, default "test-token"
  TANOD_CHAT_ID         owner chat id (or a group id), default "0"

Helpers for setting up a real bot:
    python -m alerts.telegram chats   # after messaging the bot, lists the chat ids it can see
    python -m alerts.telegram test    # sends one test alert
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
    elif action_kind == "release":
        head = f"TANOD: {device_name} ({target}) was reconnected to the network."
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


def load_env(path: str = ".env") -> None:
    """Read KEY=value lines from a .env file into os.environ (existing values win)."""
    try:
        lines = open(path).read().splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def configured() -> bool:
    """True when a real bot token and chat id are set."""
    return os.environ.get("TANOD_BOT_TOKEN", "test-token") != "test-token" and os.environ.get("TANOD_CHAT_ID", "0") != "0"


def notify(action_kind: str, device_name: str, target: str, reason: str, risk: float | None = None) -> str:
    """Send an alert if a bot is configured. Never raises; returns what happened."""
    if not configured():
        return "Telegram not set up (no .env), alert skipped"
    try:
        res = send(build_payload(build_message(action_kind, device_name, target, reason, risk)))
        if res.get("ok") is False:
            return f"Telegram refused the alert: {res.get('description', res)}"
        msg_id = (res.get("result") or {}).get("message_id")
        return "Telegram alert sent" + (f" (message {msg_id})" if msg_id else "")
    except OSError as e:
        return f"Telegram alert failed: {e}"


def _cli(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Telegram setup helpers")
    ap.add_argument("cmd", choices=["chats", "test"])
    args = ap.parse_args(argv)
    load_env()
    if args.cmd == "test":
        print(notify("quarantine", "Test device", "192.168.50.20", "This is a test alert from TANOD", 0))
        return
    token = os.environ.get("TANOD_BOT_TOKEN", "test-token")
    if token == "test-token":
        raise SystemExit("Put TANOD_BOT_TOKEN in .env first.")
    endpoint = os.environ.get("TANOD_ALERT_ENDPOINT", "https://api.telegram.org").rstrip("/")
    with urllib.request.urlopen(f"{endpoint}/bot{token}/getUpdates", timeout=10) as r:
        updates = json.loads(r.read().decode()).get("result", [])
    chats = {}
    for u in updates:
        msg = u.get("message") or u.get("my_chat_member") or {}
        chat = msg.get("chat")
        if chat:
            chats[chat["id"]] = chat.get("title") or chat.get("first_name") or chat.get("username") or ""
    if not chats:
        print("No chats yet. Send any message to the bot (or add it to your group and send a message), then run again.")
    for cid, name in chats.items():
        print(f"{cid}\t{name}")


if __name__ == "__main__":
    _cli()
