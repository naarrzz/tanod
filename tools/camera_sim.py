#!/usr/bin/env python3
"""A stand-in IP camera for the Kali test lab (no real camera needed).

Run this on the "camera" VM. It does two things so the attacks have a real
target and TANOD has a normal baseline to compare against:

  1. Streams steady "video": UDP packets to the approved viewer at a fixed rate,
     the same shape as a real RTP camera feed. This is the normal traffic the
     Isolation Forest learns, so an attack stands out.
  2. Listens on the usual camera ports (80 web, 554 RTSP, 8080) so nmap sees
     open ports and hydra / ffplay / cameradar have something to connect to.

    sudo python3 tools/camera_sim.py --viewer 192.168.50.5
    sudo python3 tools/camera_sim.py --viewer 192.168.50.5 --ports 80,554,8080 --pps 20

Ports below 1024 need root. Nothing here is an attack; it only makes a target.
Stop with Ctrl+C.
"""
from __future__ import annotations

import argparse
import os
import random
import socket
import threading
import time

RUNNING = threading.Event()


def stream_video(viewer: str, port: int, pps: int) -> None:
    """Send UDP 'video' to the viewer at ~pps packets per second (like RTP)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", port))  # fixed source port, like a camera's RTP port
    except OSError:
        pass  # if the port is busy, still send from an ephemeral one
    rng = random.Random()
    sent = 0
    while RUNNING.is_set():
        payload = bytes(rng.getrandbits(8) for _ in range(rng.randint(1000, 1400)))
        try:
            sock.sendto(payload, (viewer, port))
        except OSError:
            pass
        sent += 1
        if sent % (pps * 10) == 0:
            print(f"  streamed {sent} video packets to {viewer}:{port}")
        time.sleep(1.0 / max(pps, 1))
    sock.close()


def serve_port(port: int, banner: bytes) -> None:
    """Accept TCP connections on a camera port and answer with a short banner."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
    except PermissionError:
        print(f"  port {port} needs root (run with sudo), skipping")
        return
    except OSError as e:
        print(f"  port {port}: {e}, skipping")
        return
    srv.listen(16)
    srv.settimeout(0.5)
    print(f"  listening on tcp/{port}")
    while RUNNING.is_set():
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            conn.settimeout(1.0)
            conn.sendall(banner)
            conn.recv(1024)  # let the client send its request (login attempt, etc.)
        except OSError:
            pass
        finally:
            conn.close()
    srv.close()


BANNERS = {
    80: b"HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"IPCamera\"\r\n\r\n",
    8080: b"HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"IPCamera\"\r\n\r\n",
    554: b"RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"IPCamera\"\r\n\r\n",
}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--viewer", required=True, help="IP of the approved viewer the camera streams to")
    ap.add_argument("--port", type=int, default=5004, help="UDP video port (default 5004, like RTP)")
    ap.add_argument("--pps", type=int, default=20, help="video packets per second (default 20)")
    ap.add_argument("--ports", default="80,554,8080", help="TCP camera ports to open (comma-separated)")
    args = ap.parse_args(argv)

    if os.geteuid() != 0 and any(int(p) < 1024 for p in args.ports.split(",") if p.strip()):
        print("note: ports below 1024 need root; run with sudo for 80/554.")

    RUNNING.set()
    threads = [threading.Thread(target=stream_video, args=(args.viewer, args.port, args.pps), daemon=True)]
    for p in [int(x) for x in args.ports.split(",") if x.strip()]:
        banner = BANNERS.get(p, b"IPCamera\r\n")
        threads.append(threading.Thread(target=serve_port, args=(p, banner), daemon=True))
    print(f"Camera stand-in: streaming to {args.viewer}:{args.port} at {args.pps} pps, "
          f"ports {args.ports} open. Ctrl+C to stop.")
    for t in threads:
        t.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopping.")
        RUNNING.clear()
        time.sleep(0.6)


if __name__ == "__main__":
    main()
