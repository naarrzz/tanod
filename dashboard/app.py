"""TANOD owner dashboard.

    TANOD_DASHBOARD_PASSWORD=... uvicorn dashboard.app:app --port 8000

Every page asks for a username and password (HTTP Basic). Accounts live in the
users table (add them with python -m dashboard.users add <name>). If no account
exists yet, the single built-in user "owner" with TANOD_DASHBOARD_PASSWORD works.
Release asks for the same user's password again and an explicit confirmation,
because it reconnects a device (and restores its power if the relay was cut).

Env:
  TANOD_DB                 SQLite path, default data/tanod.db
  TANOD_DASHBOARD_PASSWORD dashboard password (dev default "tanod-dev", change it)
  TANOD_DRY_RUN            "1" (default) logs nft commands only; "0" runs them (Pi, root)
  TANOD_CAMERA_URL         optional MJPEG stream of the camera, shown on the dashboard and
                           cut off while the camera is quarantined
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from alerts import telegram
from gateway.enforce import Enforcer

from . import db

log = logging.getLogger("tanod.dashboard")
DEV_PASSWORD = "tanod-dev"
HERE = Path(__file__).parent

security = HTTPBasic(realm="TANOD")
templates = Jinja2Templates(directory=str(HERE / "templates"))
templates.env.filters["ts"] = lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S") if t else ""
templates.env.filters["pretty"] = lambda s: json.dumps(json.loads(s or "{}"), indent=2)


def _password() -> str:
    pw = os.environ.get("TANOD_DASHBOARD_PASSWORD")
    if not pw:
        log.warning("TANOD_DASHBOARD_PASSWORD not set, using the dev password. Set it before testing.")
        return DEV_PASSWORD
    return pw


def check_password(given: str) -> bool:
    return hmac.compare_digest(given.encode(), _password().encode())


def authenticate(conn, username: str, password: str) -> bool:
    """Named accounts if any exist, otherwise the built-in "owner" + env password."""
    if db.list_users(conn):
        return db.check_user(conn, username, password)
    ok_user = secrets.compare_digest(username.encode(), b"owner")
    return ok_user and check_password(password)


def require_owner(request: Request, creds: HTTPBasicCredentials = Depends(security)) -> str:
    if not authenticate(request.app.state.conn, creds.username, creds.password):
        raise HTTPException(401, "Wrong username or password",
                            headers={"WWW-Authenticate": 'Basic realm="TANOD"'})
    return creds.username.lower()


PHONE_FRESH_S = 4.0  # a phone camera counts as live while it sent a frame this recently


def list_cameras(conn):
    return conn.execute("SELECT * FROM devices WHERE kind='camera' ORDER BY id").fetchall()


def camera_state(conn, cam, phone_ts: float = 0.0, first: bool = True) -> dict:
    """Where one camera's video comes from, whether it is live, and whether TANOD has it cut off.

    Sources: "url" (TANOD_CAMERA_URL, first camera only), "phone" (a phone sends frames to
    /camera/frame; forced for every camera when TANOD_PHONE_CAMERA=1, as in demo --lan) or
    "laptop" (a camera on the computer showing the dashboard, first camera only)."""
    active = db.active_responses(conn)
    ev = next((e for e in active if e["target_ip"] == cam["ip"]), None)
    if first and os.environ.get("TANOD_CAMERA_URL"):
        source = "url"
    elif os.environ.get("TANOD_PHONE_CAMERA") == "1" or phone_ts or not first:
        source = "phone"
    else:
        source = "laptop"
    return {"present": True, "name": cam["name"], "ip": cam["ip"], "isolated": ev is not None,
            "since": datetime.fromtimestamp(ev["ts"]).strftime("%H:%M:%S") if ev else None,
            "reason": ev["reason"] if ev else None, "risk": ev["risk"] if ev else None,
            "active": len(active), "source": source,
            "live": source != "phone" or time.time() - phone_ts < PHONE_FRESH_S}


def create_app(db_path: str | None = None, enforcer: Enforcer | None = None) -> FastAPI:
    app = FastAPI(title="TANOD Dashboard")
    app.state.conn = db.connect(db_path or os.environ.get("TANOD_DB", "data/tanod.db"))
    app.state.enforcer = enforcer or Enforcer(dry_run=os.environ.get("TANOD_DRY_RUN", "1") != "0")
    app.state.frames = {}  # camera ip -> (latest JPEG from its phone page, time received)
    app.state.frame_cond = threading.Condition()

    def cams_state(request) -> list[dict]:
        conn, frames = request.app.state.conn, request.app.state.frames
        return [camera_state(conn, c, frames.get(c["ip"], (None, 0.0))[1], i == 0)
                for i, c in enumerate(list_cameras(conn))]

    def one_cam(request, ip: str | None) -> dict:
        cams = cams_state(request)
        if not cams:
            raise HTTPException(404, "No camera is registered")
        if ip is None:
            return cams[0]
        for c in cams:
            if c["ip"] == ip:
                return c
        raise HTTPException(404, "No such camera")

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request, user: str = Depends(require_owner)):
        conn = request.app.state.conn
        return templates.TemplateResponse(request, "index.html", {
            "devices": db.list_devices(conn),
            "active": db.active_responses(conn),
            "events": db.list_events(conn, 30),
            "dry_run": request.app.state.enforcer.dry_run,
            "user": user,
            "cameras": cams_state(request),
        })

    @app.get("/camera/status")
    def camera_status(request: Request, _=Depends(require_owner)):
        cams = cams_state(request)
        return JSONResponse({"cameras": cams, "active": len(db.active_responses(request.app.state.conn))})

    @app.get("/cam", response_class=HTMLResponse)
    def phone_camera_page(request: Request, ip: str | None = None, user: str = Depends(require_owner)):
        """Open this on a phone to use it as one of the cameras."""
        cams = cams_state(request)
        cam = one_cam(request, ip) if (ip or len(cams) == 1) else None
        return templates.TemplateResponse(request, "cam.html", {"camera": cam, "cameras": cams, "user": user})

    @app.post("/camera/frame")
    async def camera_frame(request: Request, ip: str | None = None, _=Depends(require_owner)):
        """One JPEG frame from a phone. Refused while that camera is quarantined,
        the same way the gateway firewall would drop the camera's traffic."""
        st = one_cam(request, ip)
        if st["isolated"]:
            return JSONResponse({"isolated": True, "reason": st["reason"], "since": st["since"]}, status_code=503)
        body = await request.body()
        if not body.startswith(b"\xff\xd8") or len(body) > 2_000_000:
            raise HTTPException(400, "Send one JPEG image")
        with request.app.state.frame_cond:
            request.app.state.frames[st["ip"]] = (body, time.time())
            request.app.state.frame_cond.notify_all()
        return JSONResponse({"isolated": False})

    @app.get("/camera/stream")
    def camera_stream(request: Request, ip: str | None = None, _=Depends(require_owner)):
        """One camera's feed as MJPEG, from TANOD_CAMERA_URL or from its phone page.
        It stops the moment the camera is quarantined."""
        st = one_cam(request, ip)
        if st["isolated"]:
            raise HTTPException(503, "Camera is isolated by TANOD")
        conn, state, cam_ip = request.app.state.conn, request.app.state, st["ip"]

        def isolated() -> bool:
            return any(e["target_ip"] == cam_ip for e in db.active_responses(conn))

        if st["source"] == "url":
            try:
                upstream = urllib.request.urlopen(os.environ["TANOD_CAMERA_URL"], timeout=5)
            except OSError as e:
                raise HTTPException(502, f"Camera not reachable: {e}")

            def relay():
                checked = 0.0
                try:
                    while True:
                        if time.time() - checked > 0.5:
                            checked = time.time()
                            if isolated():
                                break
                        chunk = upstream.read(16384)
                        if not chunk:
                            break
                        yield chunk
                finally:
                    upstream.close()

            ctype = upstream.headers.get("Content-Type", "multipart/x-mixed-replace")
            return StreamingResponse(relay(), media_type=ctype, headers={"Cache-Control": "no-store"})

        if st["source"] != "phone" or not st["live"]:
            raise HTTPException(404, "No video from this camera yet. Open /cam on the phone.")

        def frames():
            last = None
            while True:
                with state.frame_cond:
                    state.frame_cond.wait(timeout=1.0)
                    frame, ts = state.frames.get(cam_ip, (None, 0.0))
                if isolated() or time.time() - ts > PHONE_FRESH_S:
                    break
                if frame is None or frame is last:
                    continue
                last = frame
                yield (b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: " + str(len(frame)).encode()
                       + b"\r\n\r\n" + frame + b"\r\n")

        return StreamingResponse(frames(), media_type="multipart/x-mixed-replace; boundary=frame",
                                 headers={"Cache-Control": "no-store"})

    @app.get("/events/{event_id}", response_class=HTMLResponse)
    def event_detail(event_id: int, request: Request, _=Depends(require_owner)):
        ev = db.get_event(request.app.state.conn, event_id)
        if not ev:
            raise HTTPException(404, "No such event")
        return templates.TemplateResponse(request, "event.html", {"e": ev})

    def _active_for(conn, target: str):
        rows = [r for r in db.active_responses(conn) if r["target_ip"] == target]
        if not rows:
            raise HTTPException(404, "Nothing to release for this address")
        return rows[0]

    @app.get("/release/{target}", response_class=HTMLResponse)
    def release_form(target: str, request: Request, _=Depends(require_owner)):
        conn = request.app.state.conn
        ev = _active_for(conn, target)
        dev = db.device_by_ip(conn, target)
        return templates.TemplateResponse(request, "release.html", {"e": ev, "dev": dev, "error": None})

    @app.post("/release/{target}", response_class=HTMLResponse)
    def release(target: str, request: Request, password: str = Form(""), confirm: str = Form(""),
                user: str = Depends(require_owner)):
        conn = request.app.state.conn
        ev = _active_for(conn, target)
        dev = db.device_by_ip(conn, target)
        error = None
        if not authenticate(conn, user, password):
            error = "Wrong password."
        elif confirm != "yes":
            error = "Please tick the box to confirm."
        if error:
            return templates.TemplateResponse(request, "release.html", {"e": ev, "dev": dev, "error": error},
                                              status_code=400)
        request.app.state.enforcer.release(
            target, mac=(dev["mac"] if dev else ev["target_mac"]), kind=ev["kind"],
            relay_channel=(dev["relay_channel"] if dev else None))
        db.mark_released(conn, target)
        db.record_event(conn, "release", target, f"Released by {user}", "owner",
                        target_mac=(dev["mac"] if dev else ev["target_mac"]))
        log.info(telegram.notify("release", dev["name"] if dev else "Unregistered client", target,
                                 f"Released by {user} from the dashboard"))
        return RedirectResponse("/", status_code=303)

    def _pw_page(request, user, error=None, done=False, status=200):
        named = bool(db.list_users(request.app.state.conn))
        return templates.TemplateResponse(request, "password.html", {
            "user": user, "error": error, "done": done, "named": named}, status_code=status)

    @app.get("/password", response_class=HTMLResponse)
    def password_form(request: Request, user: str = Depends(require_owner)):
        return _pw_page(request, user)

    @app.post("/password", response_class=HTMLResponse)
    def change_password(request: Request, current: str = Form(""), new: str = Form(""), again: str = Form(""),
                        user: str = Depends(require_owner)):
        conn = request.app.state.conn
        error = None
        if not db.list_users(conn):
            error = "The built-in owner password comes from TANOD_DASHBOARD_PASSWORD. Add named accounts first."
        elif not authenticate(conn, user, current):
            error = "Current password is wrong."
        elif len(new) < 8:
            error = "Use at least 8 characters."
        elif new != again:
            error = "The new passwords do not match."
        elif new == current:
            error = "The new password is the same as the current one."
        if error:
            return _pw_page(request, user, error=error, status=400)
        name = next((u["display_name"] for u in db.list_users(conn) if u["username"] == user), user)
        db.set_user(conn, user, new, name)
        return _pw_page(request, user, done=True)

    return app


app = create_app()
