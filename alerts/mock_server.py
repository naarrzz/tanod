"""Local stand-in for the Telegram Bot API (isolated test network).

Logs each sendMessage with the time it arrived, so alert delivery time can be
measured in Test T11.

    python -m alerts.mock_server            # listens on 127.0.0.1:8081
"""
from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

LOG = Path("data/alerts_received.jsonl")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if not self.path.endswith("/sendMessage"):
            self.send_response(404)
            self.end_headers()
            return
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0)
        received = time.time()
        try:
            msg = json.loads(body or b"{}")
        except json.JSONDecodeError:
            msg = {"raw": body.decode(errors="replace")}
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with LOG.open("a") as f:
            f.write(json.dumps({"received_at": received, "message": msg}) + "\n")
        print(f"[{time.strftime('%H:%M:%S')}] alert to chat {msg.get('chat_id')}:\n{msg.get('text')}\n")
        out = json.dumps({"ok": True, "result": {"message_id": int(received * 1000), "date": int(received),
                                                 "text": msg.get("text", "")}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):
        pass


def main(host: str = "127.0.0.1", port: int = 8081):
    print(f"Mock Telegram endpoint on http://{host}:{port}  (log: {LOG})")
    HTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
