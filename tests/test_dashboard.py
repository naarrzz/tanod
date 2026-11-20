import pytest
from fastapi.testclient import TestClient

from dashboard import db
from dashboard.app import create_app
from gateway.enforce import Enforcer, MockRelay

PW = "test-pass"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("TANOD_DASHBOARD_PASSWORD", PW)
    relay = MockRelay()
    app = create_app(str(tmp_path / "t.db"), Enforcer(relay=relay, relay_enabled=True))
    conn = app.state.conn
    db.upsert_device(conn, "ESP32 Node 1", "aa:bb:cc:00:00:01", "192.168.50.11", relay_channel=1,
                     relay_cutoff_enabled=True)
    db.record_event(conn, "quarantine", "192.168.50.11", "Unusual behavior", "isolation_forest", 80.0,
                    {"features": {"bytes_sent": 1}}, target_mac="aa:bb:cc:00:00:01")
    relay.cut(1)
    c = TestClient(app)
    c.relay = relay
    return c


def test_requires_password(client):
    assert client.get("/").status_code == 401
    assert client.get("/", auth=("owner", "wrong")).status_code == 401


def test_lists_devices_and_events(client):
    r = client.get("/", auth=("owner", PW))
    assert r.status_code == 200
    assert "ESP32 Node 1" in r.text and "quarantined" in r.text
    ev = client.get("/events/1", auth=("owner", PW))
    assert "bytes_sent" in ev.text


def test_release_needs_password_and_confirmation(client):
    auth = ("owner", PW)
    assert "Power to this device will be turned back on" in client.get("/release/192.168.50.11", auth=auth).text
    r = client.post("/release/192.168.50.11", data={"password": "nope", "confirm": "yes"}, auth=auth)
    assert r.status_code == 400 and "Wrong password" in r.text
    r = client.post("/release/192.168.50.11", data={"password": PW}, auth=auth)
    assert r.status_code == 400 and "confirm" in r.text
    assert client.relay.state(1) == "cut"

    r = client.post("/release/192.168.50.11", data={"password": PW, "confirm": "yes"}, auth=auth,
                    follow_redirects=False)
    assert r.status_code == 303
    assert client.relay.state(1) == "on"
    home = client.get("/", auth=auth).text
    assert "Nothing is blocked" in home and "Released by owner" in home


def test_release_unknown_target_is_404(client):
    assert client.get("/release/192.168.50.77", auth=("owner", PW)).status_code == 404


def test_named_accounts_replace_owner(client):
    conn = client.app.state.conn
    db.set_user(conn, "Rod", "rod-secret-1", "Rod")
    assert client.get("/", auth=("owner", PW)).status_code == 401
    assert client.get("/", auth=("rod", "wrong")).status_code == 401
    r = client.get("/", auth=("rod", "rod-secret-1"))
    assert r.status_code == 200 and "Signed in as rod" in r.text
    # release checks the signed-in user's own password
    auth = ("rod", "rod-secret-1")
    r = client.post("/release/192.168.50.11", data={"password": PW, "confirm": "yes"}, auth=auth)
    assert r.status_code == 400
    r = client.post("/release/192.168.50.11", data={"password": "rod-secret-1", "confirm": "yes"}, auth=auth,
                    follow_redirects=False)
    assert r.status_code == 303
    assert "Released by rod" in client.get("/", auth=auth).text


def test_password_hash_roundtrip():
    h = db.hash_password("abc12345")
    assert h.startswith("pbkdf2_sha256$") and "abc12345" not in h
    assert db.verify_password("abc12345", h) and not db.verify_password("abc12346", h)


def test_change_password(client):
    conn = client.app.state.conn
    db.set_user(conn, "rod", "rod-secret-1", "Rod")
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
    r = client.post("/password", data={"current": PW, "new": "new-pass-123", "again": "new-pass-123"},
                    auth=("owner", PW))
    assert r.status_code == 400 and "TANOD_DASHBOARD_PASSWORD" in r.text
