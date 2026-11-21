"""TANOD owner dashboard.

    TANOD_DASHBOARD_PASSWORD=... uvicorn dashboard.app:app --port 8000

Every page asks for a username and password (HTTP Basic). Two roles:
  admin  the research team: installs TANOD, creates and removes accounts, sees device details
  user   the camera owner: watches the cameras, reads alerts and evidence, unblocks
Accounts are created only by an admin (on /accounts, or python -m dashboard.users add);
there is no public sign-up, because the dashboard controls the owner's network.
If no account exists yet, the built-in "admin" login with TANOD_DASHBOARD_PASSWORD works.
Unblock asks for the same user's password again and an explicit confirmation,
because it lets the attacker back on the network.

Env:
  TANOD_DB                 SQLite path, default data/tanod.db
  TANOD_DASHBOARD_PASSWORD dashboard password (dev default "tanod-dev", change it)
  TANOD_DRY_RUN            "1" (default) logs nft commands only; "0" runs them (Pi, root)
  TANOD_CAMERA_URL         optional MJPEG stream of the first camera, shown on the dashboard
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
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from starlette.requests import ClientDisconnect

from alerts import telegram
from gateway.enforce import Enforcer


from . import db
from .demo import ATTACKS

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


def authenticate(conn, username: str, password: str) -> str | None:
    """The user's role if the login is right, else None. Named accounts if any exist,
    otherwise the built-in "admin" + env password."""
    if db.list_users(conn):
        return db.get_role(conn, username) if db.check_user(conn, username, password) else None
    ok_user = secrets.compare_digest(username.encode(), b"admin")
    return "admin" if ok_user and check_password(password) else None


@dataclass
class User:
    name: str
    role: str

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def __str__(self) -> str:
        return self.name


def require_login(request: Request, creds: HTTPBasicCredentials = Depends(security)) -> User:
    role = authenticate(request.app.state.conn, creds.username, creds.password)
    if not role:
        raise HTTPException(401, "Wrong username or password",
                            headers={"WWW-Authenticate": 'Basic realm="TANOD"'})
    return User(creds.username.lower(), role)


def require_admin(user: User = Depends(require_login)) -> User:
    if not user.is_admin:
        raise HTTPException(403, "Only an admin can do this")
    return user


PHONE_FRESH_S = 4.0  # a phone camera counts as live while it sent a frame this recently


def list_cameras(conn):
    return conn.execute("SELECT * FROM devices WHERE kind='camera' ORDER BY id").fetchall()


def camera_state(conn, cam, phone_ts: float = 0.0, first: bool = True) -> dict:
    """Where one camera's video comes from, whether it is live, and the attack TANOD last stopped.

    TANOD never cuts the camera off: it blocks the attacker, so the video keeps running
    ("isolated" stays False; it is kept for the phone page).
    Sources: "url" (TANOD_CAMERA_URL, first camera only), "phone" (a phone sends frames to
    /camera/frame; forced for every camera when TANOD_PHONE_CAMERA=1, as in demo --lan) or
    "laptop" (a camera on the computer showing the dashboard, first camera only)."""
    active = db.active_responses(conn)
    ev = next((e for e in active if e["victim_ip"] == cam["ip"]), None)
    if first and os.environ.get("TANOD_CAMERA_URL"):
        source = "url"
    elif os.environ.get("TANOD_PHONE_CAMERA") == "1" or phone_ts or not first:
        source = "phone"
    else:
        source = "laptop"
    attack = None
    if ev:
        attack = {"kind": ev["kind"], "attacker": ev["target_ip"], "mac": ev["target_mac"],
                  "since": datetime.fromtimestamp(ev["ts"]).strftime("%H:%M:%S"),
                  "reason": ev["reason"], "risk": ev["risk"], "source": ev["source"]}
    return {"present": True, "name": cam["name"], "ip": cam["ip"], "link": cam["link"], "isolated": False,
            "attack": attack, "active": len(active), "source": source,
            "live": source != "phone" or time.time() - phone_ts < PHONE_FRESH_S}


def create_app(db_path: str | None = None, enforcer: Enforcer | None = None) -> FastAPI:
    app = FastAPI(title="TANOD Dashboard")
    app.state.conn = db.ThreadConn(db_path or os.environ.get("TANOD_DB", "data/tanod.db"))
    app.state.enforcer = enforcer or Enforcer(dry_run=os.environ.get("TANOD_DRY_RUN", "1") != "0")
    app.state.frames = {}  # camera ip -> (latest JPEG from its phone page, time received)
    app.state.frame_owner = {}  # camera ip -> (id of the phone sending it, time of its last frame)
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
    def home(request: Request, user: User = Depends(require_login)):
        conn = request.app.state.conn
        return templates.TemplateResponse(request, "index.html", {
            "devices": db.list_devices(conn),
            "active": db.active_responses(conn),
            "events": db.list_events(conn, 30),
            "dry_run": request.app.state.enforcer.dry_run,
            "user": user,
            "cameras": cams_state(request),
            "demo": os.environ.get("TANOD_DEMO") == "1",
            "lan_url": os.environ.get("TANOD_LAN_URL"),
            "attacks": ATTACKS,
        })

    @app.get("/camera/status")
    def camera_status(request: Request, _=Depends(require_login)):
        cams = cams_state(request)
        return JSONResponse({"cameras": cams, "active": len(db.active_responses(request.app.state.conn))})

    @app.get("/cam", response_class=HTMLResponse)
    def phone_camera_page(request: Request, ip: str | None = None, user: User = Depends(require_login)):
        """Open this on a phone to use it as one of the cameras."""
        cams = cams_state(request)
        cam = one_cam(request, ip) if (ip or len(cams) == 1) else None
        return templates.TemplateResponse(request, "cam.html", {"camera": cam, "cameras": cams, "user": user})

    @app.post("/camera/frame")
    async def camera_frame(request: Request, ip: str | None = None, phone: str = "",
                           _=Depends(require_login)):
        """One JPEG frame from a phone acting as the camera."""
        st = one_cam(request, ip)
        try:
            body = await request.body()
        except ClientDisconnect:  # the phone gave up on this frame (weak Wi-Fi); the next one follows
            return JSONResponse({"isolated": False}, status_code=499)
        if not body.startswith(b"\xff\xd8") or len(body) > 2_000_000:
            raise HTTPException(400, "Send one JPEG image")
        owners = request.app.state.frame_owner  # camera ip -> (phone id, last frame time)
        with request.app.state.frame_cond:
            other, last = owners.get(st["ip"], ("", 0.0))
            if phone and other and other != phone and time.time() - last < PHONE_FRESH_S:
                # Another phone is already this camera; two phones on one camera made the feed flip.
                return JSONResponse({"isolated": False, "busy": True, "camera": st["name"]}, status_code=409)
            owners[st["ip"]] = (phone, time.time())
            request.app.state.frames[st["ip"]] = (body, time.time())
            request.app.state.frame_cond.notify_all()
        return JSONResponse({"isolated": False})

    @app.get("/camera/stream")
    def camera_stream(request: Request, ip: str | None = None, _=Depends(require_login)):
        """One camera's feed as MJPEG, from TANOD_CAMERA_URL or from its phone page.
        It keeps running during an attack: TANOD blocks the attacker, not the camera."""
        st = one_cam(request, ip)
        state, cam_ip = request.app.state, st["ip"]

        if st["source"] == "url":
            try:
                upstream = urllib.request.urlopen(os.environ["TANOD_CAMERA_URL"], timeout=5)
            except OSError as e:
                raise HTTPException(502, f"Camera not reachable: {e}")

            def relay():
                try:
                    while True:
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
                if time.time() - ts > PHONE_FRESH_S:
                    break
                if frame is None or frame is last:
                    continue
                last = frame
                yield (b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: " + str(len(frame)).encode()
                       + b"\r\n\r\n" + frame + b"\r\n")

        return StreamingResponse(frames(), media_type="multipart/x-mixed-replace; boundary=frame",
                                 headers={"Cache-Control": "no-store"})

    # ---- demo controls (only with TANOD_DEMO=1, set by python -m dashboard.demo) ----
    def demo_on():
        if os.environ.get("TANOD_DEMO") != "1":
            raise HTTPException(404, "Demo controls are off")

    @app.post("/demo/attack")
    def demo_attack(request: Request, kind: str = Form("scan"), camera: int = Form(1),
                    _=Depends(require_login)):
        demo_on()
        from . import demo
        if kind not in demo.ATTACKS:
            raise HTTPException(400, "Unknown scenario")
        lines: list[str] = []
        acted = demo.run_attack(Path(app.state.conn.path), kind, camera, say=lines.append)
        return JSONResponse({"acted": acted, "lines": [l.strip() for l in lines]})

    @app.post("/demo/reset")
    def demo_reset(request: Request, _=Depends(require_login)):
        demo_on()
        from . import demo
        n = len(list_cameras(request.app.state.conn)) or 1
        demo.build_data(Path(app.state.conn.path), n)
        return JSONResponse({"ok": True})

    @app.get("/demo/qr.svg")
    def demo_qr(request: Request, _=Depends(require_login)):
        demo_on()
        url = os.environ.get("TANOD_LAN_URL")
        if not url:
            raise HTTPException(404, "Start the demo with --lan")
        import io

        import qrcode
        import qrcode.image.svg
        buf = io.BytesIO()
        qrcode.make(url + "/cam", image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2).save(buf)
        return HTMLResponse(buf.getvalue(), media_type="image/svg+xml")

    @app.get("/events/{event_id}", response_class=HTMLResponse)
    def event_detail(event_id: int, request: Request, user: User = Depends(require_login)):
        ev = db.get_event(request.app.state.conn, event_id)
        if not ev:
            raise HTTPException(404, "No such event")
        return templates.TemplateResponse(request, "event.html", {"e": ev, "user": user})

    def _active_for(conn, target: str):
        rows = [r for r in db.active_responses(conn) if r["target_ip"] == target]
        if not rows:
            raise HTTPException(404, "Nothing to unblock for this address")
        return rows[0]

    @app.get("/release/{target}", response_class=HTMLResponse)
    def release_form(target: str, request: Request, user: User = Depends(require_login)):
        ev = _active_for(request.app.state.conn, target)
        return templates.TemplateResponse(request, "release.html", {"e": ev, "error": None, "user": user})

    @app.post("/release/{target}", response_class=HTMLResponse)
    def release(target: str, request: Request, password: str = Form(""), confirm: str = Form(""),
                user: User = Depends(require_login)):
        """Unblock an attacker (or dismiss an alert that had no attacker to block)."""
        conn = request.app.state.conn
        ev = _active_for(conn, target)
        error = None
        if not authenticate(conn, user.name, password):
            error = "Wrong password."
        elif confirm != "yes":
            error = "Please tick the box to confirm."
        if error:
            return templates.TemplateResponse(request, "release.html", {"e": ev, "error": error, "user": user},
                                              status_code=400)
        if ev["kind"] == "block":
            ip = target if target != ev["target_mac"] else None
            request.app.state.enforcer.release(ip=ip, mac=ev["target_mac"])
        db.mark_released(conn, target)
        what = "Unblocked" if ev["kind"] == "block" else "Dismissed"
        db.record_event(conn, "release", target, f"{what} by {user.name}", user.role,
                        target_mac=ev["target_mac"], victim_ip=ev["victim_ip"])
        log.info(telegram.notify("release", ev["target_mac"] or target, target, f"{what} by {user.name} on the dashboard"))
        return RedirectResponse("/", status_code=303)

    # ---- accounts (admin only) ------------------------------------------
    def _accounts_page(request, user, error=None, created=None, status=200):
        return templates.TemplateResponse(request, "accounts.html", {
            "user": user, "users": db.list_users(request.app.state.conn), "error": error, "created": created},
            status_code=status)

    @app.get("/accounts", response_class=HTMLResponse)
    def accounts(request: Request, user: User = Depends(require_admin)):
        return _accounts_page(request, user)

    @app.post("/accounts", response_class=HTMLResponse)
    def add_account(request: Request, username: str = Form(""), name: str = Form(""), role: str = Form("user"),
                    user: User = Depends(require_admin)):
        from .users import generate_password
        conn = request.app.state.conn
        username = username.strip().lower()
        if not username.isascii() or not username.replace("-", "").replace("_", "").isalnum() or len(username) > 32:
            return _accounts_page(request, user, "Use letters, numbers, - or _ for the username.", status=400)
        if role not in db.ROLES:
            return _accounts_page(request, user, "Pick admin or user.", status=400)
        if db.get_role(conn, username):
            return _accounts_page(request, user, f"{username} already exists.", status=400)
        if not db.list_users(conn) and role != "admin":
            return _accounts_page(request, user, "Make an admin account first, or you will lock yourself out.",
                                  status=400)
        pw = generate_password()
        db.set_user(conn, username, pw, name.strip() or username, role)
        return _accounts_page(request, user, created={"username": username, "password": pw, "role": role})

    @app.post("/accounts/{username}/remove", response_class=HTMLResponse)
    def remove_account(username: str, request: Request, user: User = Depends(require_admin)):
        conn = request.app.state.conn
        if username.lower() == user.name:
            return _accounts_page(request, user, "You cannot remove your own account.", status=400)
        admins = [u for u in db.list_users(conn) if u["role"] == "admin"]
        if db.get_role(conn, username) == "admin" and len(admins) <= 1:
            return _accounts_page(request, user, "Keep at least one admin.", status=400)
        db.delete_user(conn, username)
        return RedirectResponse("/accounts", status_code=303)

    def _pw_page(request, user, error=None, done=False, status=200):
        named = bool(db.list_users(request.app.state.conn))
        return templates.TemplateResponse(request, "password.html", {
            "user": user, "error": error, "done": done, "named": named}, status_code=status)

    @app.get("/password", response_class=HTMLResponse)
    def password_form(request: Request, user: User = Depends(require_login)):
        return _pw_page(request, user)

    @app.post("/password", response_class=HTMLResponse)
    def change_password(request: Request, current: str = Form(""), new: str = Form(""), again: str = Form(""),
                        user: User = Depends(require_login)):
        conn = request.app.state.conn
        error = None
        if not db.list_users(conn):
            error = "The built-in admin password comes from TANOD_DASHBOARD_PASSWORD. Add named accounts first."
        elif not authenticate(conn, user.name, current):
            error = "Current password is wrong."
        elif len(new) < 8:
            error = "Use at least 8 characters."
        elif new != again:
            error = "The new passwords do not match."
        elif new == current:
            error = "The new password is the same as the current one."
        if error:
            return _pw_page(request, user, error=error, status=400)
        db.set_user(conn, user.name, new)
        return _pw_page(request, user, done=True)

    return app


app = create_app()
