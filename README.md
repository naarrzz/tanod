# TANOD

**Threat Analysis and Network Observation Device**: a Raspberry Pi 5 Wi-Fi
gateway that watches three ESP32 test nodes and one Wi-Fi IP camera, detects
attacks with Suricata rules plus a per-device Isolation Forest, and responds
with nftables quarantine, an optional relay power cutoff, an owner dashboard
and plain-language alerts.

This repo is the software skeleton for the BSECE thesis prototype. Everything
here runs on a laptop without the hardware: firewall and relay actions are
dry-run or mocked, and traffic can be simulated.

## Safety rule (read first)

Attack tests (T3 to T8) are run **only by the researchers, only on devices they
own, and only on the isolated test network** with no route to the school
network or the internet (check T2 at the start of every test day), as required
by RA 10175 and the adviser-approved test plan. Hacked mode in the node
firmware and any attack scripts must never be pointed at other networks or
devices. Attack scripts are not kept in this repo and are deleted after testing.

## Layout

| Path | What it does |
|---|---|
| `gateway/features.py` | Ten per-device features per 2-second window (Table 4) from packet header metadata |
| `gateway/model.py` | Per-device Isolation Forest, 100 trees, max_samples 256, threshold at the 99.82nd percentile of calibration scores, risk = 100 × s |
| `gateway/decision.py` | Priority 1 Suricata alert → respond; 2 consecutive flagged windows → quarantine; unregistered client sending most of the traffic → block it instead |
| `gateway/enforce.py` | nftables quarantine/block/release command builders (dry-run by default), relay controller (mock + Pi GPIO), relay cutoff off by default |
| `gateway/registry.py` | Registered devices by MAC, LAN subnet, unregistered-client check |
| `gateway/suricata.py` | Reads alerts from Suricata `eve.json` |
| `gateway/simulate.py` | Synthetic traffic for the Table 6 scenarios, runs the whole pipeline, writes to the dashboard DB |
| `dashboard/` | FastAPI + SQLite owner dashboard: devices, events with evidence, password-protected Release with confirmation |
| `alerts/` | Plain-language alerts in Telegram Bot API `sendMessage` format, sent to a local mock endpoint by default |
| `firmware/esp32_node/` | Arduino sketch: normal mode and hacked mode (scan, dummy upload, 1 s beacon) by USB serial command, logs start time |
| `tests/` | pytest tests for features, threshold, decision rules, enforcement, alerts, dashboard |

## Setup (laptop)

Needs Python 3.10 or newer.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pytest
```

Run the simulated pipeline (fills `data/tanod.db` with demo devices and events):

```bash
.venv/bin/python -m gateway.simulate
```

Start the dashboard (user `owner`, password from the env var; the dev default
is `tanod-dev`, change it before any test):

```bash
TANOD_DASHBOARD_PASSWORD=change-this .venv/bin/uvicorn dashboard.app:app --port 8000
```

Open http://127.0.0.1:8000.

Accounts: once any account exists, each person signs in with their own
username, and the built-in `owner` login stops working. Release asks for the
signed-in user's password again.

```bash
.venv/bin/python -m dashboard.users add narz --name "Narz"     # asks for a password
.venv/bin/python -m dashboard.users add rod --generate         # random password, printed once
.venv/bin/python -m dashboard.users list
```

Each person can change their own password from the dashboard (Change password
link beside their name). Running `users add` again on an existing username also
sets a new password.

### Presentation demo

```bash
.venv/bin/python -m dashboard.demo            # demo data + member accounts, serves http://localhost:8000
.venv/bin/python -m dashboard.demo --reset    # put the demo back (Node 1 quarantined, one blocked client)
```

The demo uses `data/demo.db` (simulated data, dry run) and creates accounts
for narz, rod and christian the first time. Their passwords are saved in
`data/demo_accounts.txt`, which is gitignored.

**Live camera panel.** The dashboard shows the camera at the top. The easiest
camera is a phone on the same Wi-Fi as the Mac:

```bash
.venv/bin/python -m dashboard.demo --lan   # prints https://<mac-ip>:8443/cam
```

Open that link on the phone, pick which camera the phone is, accept the certificate warning (it is the demo's
own self-signed certificate in `data/certs/`), sign in, allow the camera and tap
Start. The phone sends JPEG frames to TANOD, and the dashboard on the Mac
(http://localhost:8000) shows them live. While the camera is quarantined, TANOD
refuses the phone's frames and both screens say it was cut off.

**Several cameras.** `--cameras 4` gives the demo four cameras (kept until
changed). The dashboard shows them as a grid, with a dropdown to watch all of
them or just one. Each phone opens `/cam` and picks its camera. Attack one with
`--attack leak --camera 3`. With `--lan`, the dashboard never falls back to the
laptop camera, so a phone pausing for a moment does not switch feeds.

Other sources: `TANOD_CAMERA_URL` (an MJPEG stream from an IP camera app), or a
camera on the laptop, which can be an iPhone through Continuity Camera (pick it
in the dropdown under the feed). While the camera is
quarantined, the dashboard stops relaying the stream and shows why.

The demo dashboard has **Demo controls** under the cameras: Hijack, Outside
scan and Reset buttons (no typing), plus a QR code the camera phone can scan
(with `--lan`). `scripts/TANOD Demo.command` is a double-click launcher for
macOS (copy it to the Desktop); it stops an older demo and starts
`--lan --cameras 1`.

The same scenarios from a second terminal:

```bash
.venv/bin/python -m dashboard.demo --attack leak   # camera tries unknown servers and sends them video -> camera cut off
.venv/bin/python -m dashboard.demo --attack scan   # outside laptop scans the camera -> attacker blocked, feed stays
```

Both run simulated traffic through the trained models and the real decision
logic. `leak` is an exhibit scenario only: in the thesis tests the camera is
an attack target and is never put in hacked mode. Release the camera from the
dashboard to bring the feed back.

**Real Telegram alerts (exhibit, normal network only).** Copy `.env.example`
to `.env` (gitignored), create a bot with @BotFather, put its token in
`TANOD_BOT_TOKEN`, send the bot a message (or add it to the group chat), then:

```bash
.venv/bin/python -m alerts.telegram chats   # prints the chat id to put in TANOD_CHAT_ID
.venv/bin/python -m alerts.telegram test    # sends one test alert
```

After that, `--attack` and every Release send a Telegram message. During the
isolated thesis trials, keep using the local mock below instead.

Alerts go to a local stand-in for the Telegram API. In another terminal:

```bash
.venv/bin/python -m alerts.mock_server
```

then `python -m gateway.simulate --send-alerts`. Received alerts are logged
with their arrival time in `data/alerts_received.jsonl` (for T11).

### Environment variables

| Var | Default | Meaning |
|---|---|---|
| `TANOD_DB` | `data/tanod.db` | SQLite file |
| `TANOD_DASHBOARD_PASSWORD` | `tanod-dev` (dev only) | Dashboard and Release password |
| `TANOD_DRY_RUN` | `1` | `0` runs nft/conntrack commands for real (Pi, root) |
| `TANOD_ALERT_ENDPOINT` | `http://127.0.0.1:8081` | Telegram-format endpoint |
| `TANOD_BOT_TOKEN`, `TANOD_CHAT_ID` | test values | Real values only for the separate Telegram check |
| `TANOD_CAMERA_URL` | unset | MJPEG stream shown on the dashboard |

## What the simulation shows (synthetic data, not results)

With `python -m gateway.simulate` (seed 7):

| Test | Outcome in simulation |
|---|---|
| T3 port scan on camera | attacker blocked (Isolation Forest, unregistered majority rule) |
| T4 password guessing | attacker blocked (simulated Suricata priority 1 alert) |
| T5 flood | **not detected by Isolation Forest**, needs a Suricata rate/threshold rule |
| T6 hacked node scan | hacked node quarantined, scanned devices not quarantined |
| T7 dummy upload | node quarantined |
| T8 1 s beacon | node quarantined |

These numbers come from made-up traffic and only prove that the code paths
work. Real thresholds and detection rates come from the 7-day baseline and the
540 trials.

## Open design points for Narz and the advisers

1. **Isolation Forest saturates.** A value far outside the training range gets
   about the same score as the most extreme training value, so an attack that
   changes only one feature (like the T5 flood, mostly `bytes_received`) can
   stay under the 99.82nd percentile threshold. Plan a Suricata threshold rule
   for floods (Table 6 already says "limit and block the source"), and check
   T5 in Setup C with real baseline data.
2. **Feature 7 (new destinations) is always 0 in training** if the baseline
   destination list is learned from the same five training days. Isolation
   Forest never splits on a constant feature, so it ignores it. Options: learn
   the destination list from days 1 to 3 and train on days 1 to 5, or add a
   simple rule for "new destination" next to the model. Same risk for any
   feature that is constant in the baseline (for example connection attempts
   on a node that keeps one connection open).
3. **Rule 4 in `decision.py` is a skeleton choice, not in the approved text.**
   When a flagged device mostly *received* connection attempts from another
   protected device, it is not quarantined; the sender is judged by its own
   model. Without this, the devices scanned in T6 were quarantined too.
4. **Connection attempts count both directions** (SYNs sent and received), so
   a port scan or password guessing against a device also changes that
   device's features. The decision logic then decides who to block.
5. **Failed connection ratio** counts a TCP attempt as failed when no SYN-ACK
   comes back in the same 2-second window. UDP has no handshake, so it does
   not count.
6. **Majority share** for "most of the suspicious traffic" is set at more than
   50% of the packets reaching the device in that window.

## What still needs the real Pi 5 and hardware

- **Packet capture on `wlan0`**: a live source that turns packets into
  `gateway.features.Packet` records (scapy, `tshark -T fields`, or Zeek
  `conn.log`), plus the long-running loop that scores each window every 2 s.
  Must sustain about 779 packets/s (Eq. 9) and 6.23 Mbps (T10).
- **hostapd / dnsmasq** config: WPA2/WPA3, client isolation, MAC-registered
  devices, DHCP reservations matching `gateway/registry.py`.
- **Suricata** install, community ruleset plus local rules (including a flood
  threshold rule), and tailing `eve.json` into `DecisionEngine.on_suricata_alert`.
- **Zeek** connection logs.
- **nftables for real**: run `Enforcer(dry_run=False).setup()` as root, check
  that quarantine, block and release behave as expected, and that `conntrack`
  is installed.
- **Relays**: `GpioRelay` needs `gpiozero` and the real BCM pin numbers for each
  channel; verify the normally closed wiring (T1) and the under-1 s cutoff (T11).
- **Baseline**: 7 days of normal traffic, train on days 1 to 5, calibrate on
  days 6 to 7, freeze and save the models (`ModelBank.save`).
- **ESP32 firmware**: flash, set the test network SSID/passphrase and the real
  addresses, replace the placeholder report with the real sensor protocol.
- **Telegram**: real bot token and chat ID, verified on an ordinary network
  with no attacks running.
- **Dashboard hardening**: run it only on the management interface for the
  monitoring laptop, HTTPS or a trusted link, real password.
- **Status display** and the temperature stop at 85 °C (system logs).
