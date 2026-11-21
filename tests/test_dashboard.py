import pytest
from fastapi.testclient import TestClient

from dashboard import db
from dashboard.app import create_app
from gateway.enforce import Enforcer

PW = "test-pass"
ADMIN = ("admin", PW)  # built-in login while no accounts exist
CAM = "192.168.50.20"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("TANOD_DASHBOARD_PASSWORD", PW)
    monkeypatch.delenv("TANOD_BOT_TOKEN", raising=False)
    app = create_app(str(tmp_path / "t.db"), Enforcer())
    conn = app.state.conn
    db.upsert_device(conn, "Wi-Fi Camera", "aa:bb:cc:00:00:20", CAM, "camera", "wifi")
    db.record_event(conn, "block", "192.168.50.99", "Attacked Wi-Fi Camera: port scan", "suricata", None,
                    {"signature": "scan"}, target_mac="de:ad:be:ef:00:99", victim_ip=CAM)
    return TestClient(app)


def test_requires_password(client):
    assert client.get("/").status_code == 401
    assert client.get("/", auth=("admin", "wrong")).status_code == 401
    assert client.get("/", auth=("owner", PW)).status_code == 401  # the old built-in name is gone


def test_lists_blocked_attacker_and_events(client):
    r = client.get("/", auth=ADMIN)
    assert r.status_code == 200
    assert "192.168.50.99" in r.text and "MAC de:ad:be:ef:00:99" in r.text and "Unblock" in r.text
    ev = client.get("/events/1", auth=ADMIN)
    assert ev.status_code == 200 and "scan" in ev.text and "Wi-Fi Camera" in ev.text


def test_unblock_needs_password_and_confirmation(client):
    url = "/release/192.168.50.99"
    assert client.post(url, data={"password": "nope", "confirm": "yes"}, auth=ADMIN).status_code == 400
    assert client.post(url, data={"password": PW}, auth=ADMIN).status_code == 400
    r = client.post(url, data={"password": PW, "confirm": "yes"}, auth=ADMIN, follow_redirects=False)
    assert r.status_code == 303
    cmds = [" ".join(c) for c in client.app.state.enforcer.executed]
    assert "nft delete element inet tanod block_mac { de:ad:be:ef:00:99 }" in cmds
    assert "nft delete element inet tanod block_ip { 192.168.50.99 }" in cmds
    home = client.get("/", auth=ADMIN).text
    assert "Nothing is blocked" in home and "Unblocked by admin" in home


def test_mac_only_block_can_be_unblocked(client):
    conn = client.app.state.conn
    db.record_event(conn, "block", "11:22:33:44:55:66", "Spoofing", "binding_check",
                    target_mac="11:22:33:44:55:66", victim_ip=CAM)
    r = client.post("/release/11:22:33:44:55:66", data={"password": PW, "confirm": "yes"}, auth=ADMIN,
                    follow_redirects=False)
    assert r.status_code == 303
    cmds = [" ".join(c) for c in client.app.state.enforcer.executed]
    assert not any("block_ip" in c for c in cmds)


def test_alert_is_dismissed_not_unblocked(client):
    conn = client.app.state.conn
    db.record_event(conn, "alert", CAM, "Wi-Fi Camera stopped sending video", "isolation_forest", 73.0, victim_ip=CAM)
    assert "Dismiss" in client.get(f"/release/{CAM}", auth=ADMIN).text
    client.post(f"/release/{CAM}", data={"password": PW, "confirm": "yes"}, auth=ADMIN)
    assert client.app.state.enforcer.executed == []  # nothing to remove from the firewall


def test_release_unknown_target_is_404(client):
    assert client.get("/release/192.168.50.77", auth=ADMIN).status_code == 404


def test_roles_admin_and_user(client):
    conn = client.app.state.conn
    db.set_user(conn, "narz", "narz-secret-1", "Narz", "admin")
    db.set_user(conn, "owner", "owner-secret-1", "Owner", "user")
    admin, user = ("narz", "narz-secret-1"), ("owner", "owner-secret-1")
    assert client.get("/", auth=ADMIN).status_code == 401  # built-in admin stops once accounts exist
    a, u = client.get("/", auth=admin).text, client.get("/", auth=user).text
    assert "(admin)" in a and "Accounts</a>" in a and "admin view" in a and "aa:bb:cc:00:00:20" in a
    assert "(user)" in u and "Accounts</a>" not in u and "admin view" not in u
    assert client.get("/accounts", auth=user).status_code == 403
    assert client.post("/accounts", data={"username": "x", "role": "admin"}, auth=user).status_code == 403
    # the owner can still unblock, with their own password
    r = client.post("/release/192.168.50.99", data={"password": "owner-secret-1", "confirm": "yes"}, auth=user,
                    follow_redirects=False)
    assert r.status_code == 303


def test_admin_creates_and_removes_accounts(client):
    conn = client.app.state.conn
    db.set_user(conn, "narz", "narz-secret-1", "Narz", "admin")
    admin = ("narz", "narz-secret-1")
    r = client.post("/accounts", data={"username": "Owner2", "name": "Bahay", "role": "user"}, auth=admin)
    assert r.status_code == 200 and "Created <b>owner2</b> (user)" in r.text
    assert db.get_role(conn, "owner2") == "user"
    assert client.post("/accounts", data={"username": "owner2", "role": "user"}, auth=admin).status_code == 400
    assert client.post("/accounts", data={"username": "bad name!", "role": "user"}, auth=admin).status_code == 400
    assert client.post("/accounts", data={"username": "y", "role": "root"}, auth=admin).status_code == 400
    assert client.post("/accounts/narz/remove", auth=admin).status_code == 400  # not yourself
    r = client.post("/accounts/owner2/remove", auth=admin, follow_redirects=False)
    assert r.status_code == 303 and db.get_role(conn, "owner2") is None


def test_first_account_must_be_admin(client):
    r = client.post("/accounts", data={"username": "owner", "role": "user"}, auth=ADMIN)
    assert r.status_code == 400 and "admin account first" in r.text


def test_old_accounts_become_admins(tmp_path):
    import sqlite3
    path = tmp_path / "old.db"
    c = sqlite3.connect(path)
    c.executescript("CREATE TABLE users (username TEXT PRIMARY KEY, display_name TEXT, pw_hash TEXT NOT NULL);"
                    "CREATE TABLE devices (id INTEGER PRIMARY KEY, name TEXT NOT NULL, mac TEXT NOT NULL UNIQUE,"
                    " ip TEXT NOT NULL UNIQUE, kind TEXT, status TEXT NOT NULL DEFAULT 'normal', last_risk REAL);"
                    "CREATE TABLE events (id INTEGER PRIMARY KEY, ts REAL NOT NULL, kind TEXT NOT NULL,"
                    " target_ip TEXT NOT NULL, target_mac TEXT, device_id INTEGER, source TEXT, reason TEXT,"
                    " risk REAL, evidence TEXT, released_at REAL);")
    c.execute("INSERT INTO users VALUES ('rod', 'Rod', ?)", (db.hash_password("x"),))
    c.commit()
    conn = db.connect(path)
    assert db.get_role(conn, "rod") == "admin"
    db.record_event(conn, "block", "192.168.50.99", "x", "suricata", victim_ip=CAM)


def test_password_hash_roundtrip():
    h = db.hash_password("abc12345")
    assert h.startswith("pbkdf2_sha256$") and "abc12345" not in h
    assert db.verify_password("abc12345", h) and not db.verify_password("abc12346", h)


def test_change_password(client):
    conn = client.app.state.conn
    db.set_user(conn, "rod", "rod-secret-1", "Rod", "admin")
    auth = ("rod", "rod-secret-1")
    assert "Change password" in client.get("/password", auth=auth).text
    bad = [
        {"current": "wrong-pass", "new": "rod-secret-2", "again": "rod-secret-2"},
        {"current": "rod-secret-1", "new": "short", "again": "short"},
        {"current": "rod-secret-1", "new": "rod-secret-2", "again": "rod-secret-3"},
    ]
    for form in bad:
        assert client.post("/password", data=form, auth=auth).status_code == 400
    r = client.post("/password", data={"current": "rod-secret-1", "new": "rod-secret-2", "again": "rod-secret-2"},
                    auth=auth)
    assert r.status_code == 200 and "Password changed" in r.text
    assert client.get("/", auth=auth).status_code == 401
    assert client.get("/", auth=("rod", "rod-secret-2")).status_code == 200
    assert [u["display_name"] for u in db.list_users(conn)] == ["Rod"]


def test_change_password_needs_named_accounts(client):
    r = client.post("/password", data={"current": PW, "new": "new-pass-123", "again": "new-pass-123"}, auth=ADMIN)
    assert r.status_code == 400 and "TANOD_DASHBOARD_PASSWORD" in r.text


def cams(client, auth=ADMIN):
    return {c["ip"]: c for c in client.get("/camera/status", auth=auth).json()["cameras"]}


def test_camera_stays_live_and_shows_the_blocked_attack(client, monkeypatch):
    monkeypatch.delenv("TANOD_CAMERA_URL", raising=False)
    monkeypatch.delenv("TANOD_PHONE_CAMERA", raising=False)
    st = cams(client)[CAM]
    assert st["source"] == "laptop" and not st["isolated"]
    assert st["attack"]["kind"] == "block" and st["attack"]["mac"] == "de:ad:be:ef:00:99"
    assert "Live camera" in client.get("/", auth=ADMIN).text
    client.app.state.conn.execute("UPDATE events SET released_at=1")
    client.app.state.conn.commit()
    assert cams(client)[CAM]["attack"] is None


def test_camera_status_needs_login(client):
    assert client.get("/camera/status").status_code == 401


JPEG = b"\xff\xd8\xff\xe0" + b"0" * 100


def test_phone_frames_keep_flowing_during_an_attack(client, monkeypatch):
    monkeypatch.delenv("TANOD_CAMERA_URL", raising=False)
    monkeypatch.delenv("TANOD_PHONE_CAMERA", raising=False)
    conn = client.app.state.conn
    db.upsert_device(conn, "Wired CCTV", "aa:bb:cc:00:00:21", "192.168.50.21", "camera", "wired")
    st = cams(client)
    assert st[CAM]["source"] == "laptop"
    assert st["192.168.50.21"]["source"] == "phone" and not st["192.168.50.21"]["live"]
    assert "Which camera is this phone?" in client.get("/cam", auth=ADMIN).text
    assert "Tap Start" in client.get("/cam?ip=192.168.50.21", auth=ADMIN).text
    assert client.get("/cam?ip=10.0.0.1", auth=ADMIN).status_code == 404
    url = "/camera/frame?ip=192.168.50.21"
    assert client.post(url, content=b"not a jpeg", auth=ADMIN).status_code == 400
    db.record_event(conn, "block", "10.10.0.66", "Attacked Wired CCTV: flood", "suricata", victim_ip="192.168.50.21")
    r = client.post(url, content=JPEG, auth=ADMIN)
    assert r.status_code == 200 and not r.json()["isolated"]
    st = cams(client)["192.168.50.21"]
    assert st["live"] and st["attack"]["attacker"] == "10.10.0.66"
    assert client.post(url, content=JPEG).status_code == 401


def test_lan_mode_never_uses_laptop_camera(client, monkeypatch):
    monkeypatch.delenv("TANOD_CAMERA_URL", raising=False)
    monkeypatch.setenv("TANOD_PHONE_CAMERA", "1")
    db.upsert_device(client.app.state.conn, "Wi-Fi Camera", "aa:bb:cc:00:00:20", "192.168.50.20", "camera")
    st = cams(client)["192.168.50.20"]
    assert st["source"] == "phone" and not st["live"]


def test_demo_controls(client, monkeypatch):
    monkeypatch.delenv("TANOD_DEMO", raising=False)
    assert client.post("/demo/attack", data={"kind": "scan"}, auth=ADMIN).status_code == 404
    assert "Demo controls" not in client.get("/", auth=ADMIN).text
    monkeypatch.setenv("TANOD_DEMO", "1")
    client.app.state.conn.execute("UPDATE events SET released_at=1")
    client.app.state.conn.commit()
    home = client.get("/", auth=ADMIN).text
    assert "Run attack" in home and "A4 ARP spoofing" in home
    assert client.post("/demo/attack", data={"kind": "nope"}, auth=ADMIN).status_code == 400
    assert client.post("/demo/attack", data={"kind": "scan"}).status_code == 401
    r = client.post("/demo/attack", data={"kind": "scan", "camera": 1}, auth=ADMIN).json()
    assert r["acted"] and any("Suricata only (Setup A):  yes" in l for l in r["lines"])
    assert any("block 192.168.50.99 (MAC de:ad:be:ef:00:99)" in l for l in r["lines"])
    st = cams(client)[CAM]
    assert st["attack"]["mac"] == "de:ad:be:ef:00:99" and not st["isolated"]
    r = client.post("/demo/attack", data={"kind": "scan", "camera": 1}, auth=ADMIN).json()
    assert not r["acted"] and "already blocked" in r["lines"][-2]
    r = client.post("/demo/attack", data={"kind": "rejoin", "camera": 1}, auth=ADMIN).json()
    assert r["acted"] and any("192.168.50.98" in l for l in r["lines"])


def test_change_link_only_with_several_cameras(client):
    conn = client.app.state.conn
    auth = ADMIN
    db.upsert_device(conn, "IP Camera 1", "aa:bb:cc:00:00:20", "192.168.50.20", "camera")
    assert ">Change</a>" not in client.get("/cam", auth=auth).text
    db.upsert_device(conn, "IP Camera 2", "aa:bb:cc:00:01:02", "192.168.50.21", "camera")
    assert ">Change</a>" in client.get("/cam?ip=192.168.50.21", auth=auth).text


def test_one_phone_per_camera(client):
    conn = client.app.state.conn
    auth = ADMIN
    db.upsert_device(conn, "Wi-Fi Camera", "aa:bb:cc:00:00:20", "192.168.50.20", "camera")
    url = "/camera/frame?ip=192.168.50.20&phone="
    assert client.post(url + "aaa", content=JPEG, auth=auth).status_code == 200
    r = client.post(url + "bbb", content=JPEG, auth=auth)
    assert r.status_code == 409 and r.json()["busy"]
    assert client.post(url + "aaa", content=JPEG, auth=auth).status_code == 200
    # once the first phone stops for a few seconds, another phone may take over
    client.app.state.frame_owner["192.168.50.20"] = ("aaa", 0.0)
    assert client.post(url + "bbb", content=JPEG, auth=auth).status_code == 200
