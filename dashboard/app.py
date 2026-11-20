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
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

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


def create_app(db_path: str | None = None, enforcer: Enforcer | None = None) -> FastAPI:
    app = FastAPI(title="TANOD Dashboard")
    app.state.conn = db.connect(db_path or os.environ.get("TANOD_DB", "data/tanod.db"))
    app.state.enforcer = enforcer or Enforcer(dry_run=os.environ.get("TANOD_DRY_RUN", "1") != "0")

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request, user: str = Depends(require_owner)):
        conn = request.app.state.conn
        return templates.TemplateResponse(request, "index.html", {
            "devices": db.list_devices(conn),
            "active": db.active_responses(conn),
            "events": db.list_events(conn, 30),
            "dry_run": request.app.state.enforcer.dry_run,
            "user": user,
        })

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
        return RedirectResponse("/", status_code=303)

    return app


app = create_app()
