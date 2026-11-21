# TANOD

**Threat Analysis and Network Observation Device**: a Raspberry Pi 5 gateway
that protects IP cameras (Wi-Fi cameras on its own access point and wired IP
CCTV on its Ethernet port). It detects attacks with Suricata rules, a
per-camera Isolation Forest and an IP-MAC binding check, **blocks the attacker
by MAC address** (not the camera, so the camera keeps recording), and alerts
the owner on a dashboard and Telegram. It is meant as one more layer next to a
VPN and a firewall, not a replacement for them.

This repo is the software for a BSECE thesis prototype. Everything here runs
on a laptop without the hardware: firewall actions are dry-run and traffic is
simulated.

## Safety rule (read first)

Attack tests (A1 to A9) are run **only by the researchers, only on cameras
they own, and only on the isolated test network** with no route to the school
network or the internet (check the isolation at the start of every test day),
as required by RA 10175 and the adviser-approved test plan. The school's
wired CCTV is monitored only with the school's written permission and is
never attacked. Attack tools must never be pointed at other networks or
devices. Attack scripts are not kept in this repo and are deleted after testing.

## Layout

| Path | What it does |
|---|---|
| `gateway/features.py` | Ten per-camera features per 2-second window from packet header metadata |
| `gateway/model.py` | Per-camera Isolation Forest, 100 trees, max_samples 256, threshold at the 99.82nd percentile of calibration scores, risk = 100 × s |
| `gateway/decision.py` | Who to block: the attacker, by MAC on the LAN and by IP outside it; never the camera or the gateway |
| `gateway/spoof.py` | IP-MAC binding check: ARP/IP spoofing (block the spoofer's MAC) and MAC cloning (block the impostor's IP) |
| `gateway/rules.py`, `suricata/tanod.rules` | TANOD's local Suricata rules, and a laptop stand-in that applies the same thresholds |
| `gateway/enforce.py` | nftables block sets (MAC and IP), hostapd deny list + deauthentication, conntrack; dry run by default |
| `gateway/registry.py` | Registered cameras by MAC (DHCP reservations), approved viewers, IP-to-MAC bindings |
| `gateway/suricata.py` | Reads alerts from Suricata `eve.json` |
| `gateway/simulate.py` | The attack list (A1–A9) on synthetic traffic, with what each detector caught |
| `dashboard/` | FastAPI + SQLite dashboard with admin and user roles, live camera tiles, blocked attackers, evidence, Unblock |
| `alerts/` | Plain-language alerts in Telegram Bot API `sendMessage` format, sent to a local mock endpoint by default |
| `tests/` | pytest tests for features, model, decision rules, spoofing, enforcement, alerts, dashboard and the attack table |

## Attack list

| # | Attack | CIA | Caught by |
|---|---|---|---|
| A1 | Port scan of the camera | C | Suricata, Isolation Forest |
| A2 | Password guessing on the camera login | C | Suricata, Isolation Forest |
| A3 | UDP flood (denial of service) | A | Suricata (rate rule); the Isolation Forest misses it |
| A4 | ARP spoofing (attacker pretends to be the gateway) | C, I | binding check only |
| A5 | MAC cloning (attacker copies the camera's MAC) | C, I, A | binding check only |
| A6 | Unauthorized viewing of the live stream | C | Suricata, Isolation Forest |
| A7 | Hijacked camera sends its video to unknown servers | C | Isolation Forest only |
| A8 | Hijacked camera checks in with a command server | C | **missed** (see open points) |
| A9 | Wi-Fi deauthentication knocks the camera offline | A | Isolation Forest only (alert, no attacker to block) |

`python -m gateway.simulate` prints this table from synthetic traffic, with
the time each detector took. These are code checks, not thesis results.

## Running on real traffic (Pi 5 or a Kali test lab)

Everything above is simulated. To detect and block **real** attacks (for the
live defense demo with Kali Linux), TANOD reads a real interface and Suricata,
and runs real nftables/hostapd commands:

```bash
# Suricata with TANOD's local rules (see suricata/tanod.yaml for the host vars)
sudo suricata -i wlan0 -S suricata/tanod.rules -l /var/log/suricata

# TANOD: watch the interface + Suricata, block the attacker for real (root)
sudo TANOD_DRY_RUN=0 python3 -m gateway.run --iface wlan0 --eve /var/log/suricata/eve.json
```

Leave `TANOD_DRY_RUN` unset to rehearse: it prints the exact block commands
instead of running them. `--pcap capture.pcap` replays a saved capture instead
of sniffing live (needs `scapy`, commented in requirements). The exact Kali
commands for each attack, the lab topology, and what to show the panel are in
[docs/attack-playbook.md](docs/attack-playbook.md).

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

Accounts and roles. **admin** is the research team (installs TANOD, creates
and removes accounts, sees device details); **user** is the camera owner
(watches the cameras, reads alerts and evidence, unblocks). Only an admin
creates accounts, on the Accounts page or from the command line; there is no
public sign-up, because the dashboard controls the owner's network. Until the
first account exists, the built-in `admin` login with
`TANOD_DASHBOARD_PASSWORD` works. Unblock asks for the signed-in user's
password again.

```bash
.venv/bin/python -m dashboard.users add narz --name "Narz" --role admin   # asks for a password
.venv/bin/python -m dashboard.users add owner --generate                  # role user, random password
.venv/bin/python -m dashboard.users list
```

Each person can change their own password from the dashboard (Change password
link beside their name).

### Presentation demo (admin, user and attacker side by side)

```bash
.venv/bin/python -m dashboard.demo --lan --cameras 2   # demo data + accounts, serves http://localhost:8000
.venv/bin/python -m dashboard.demo --reset             # put the demo back
```

The demo uses `data/demo.db` (simulated data, dry run). Accounts for narz,
rod, christian (admin) and owner (user) are created once and saved in
`data/demo_accounts.txt`, which is gitignored; existing passwords are kept.

For the defense: open the dashboard as an admin in one window and as `owner`
in a private window, and keep a terminal for the attacker:

```bash
.venv/bin/python -m dashboard.demo --attack scan     # A1: Suricata and the forest both catch it
.venv/bin/python -m dashboard.demo --attack rejoin   # the blocked attacker changes IP: still blocked by MAC
.venv/bin/python -m dashboard.demo --attack leak     # A7: Suricata misses, the Isolation Forest catches it
.venv/bin/python -m dashboard.demo --attack arp      # A4: only the binding check catches spoofing
.venv/bin/python -m dashboard.demo --help            # every attack
```

Each attack prints what Suricata alone (Setup A), the Isolation Forest and the
binding check caught, then what TANOD did. The camera tile keeps playing and
shows "ATTACK BLOCKED" with the attacker's MAC. With `--buttons`, the same
attacks can be run from a picker on the dashboard.

**Live camera tiles.** With `--lan`, open `https://<mac-ip>:8443/cam` on a
phone (same Wi-Fi), pick which camera it is, accept the certificate warning
(the demo's own self-signed certificate in `data/certs/`), sign in, allow the
camera and tap Start. `TANOD_CAMERA_URL` (an MJPEG stream) also works for the
first camera. `scripts/TANOD Demo.command` is a double-click launcher for macOS.

**Real Telegram alerts (exhibit, normal network only).** Copy `.env.example`
to `.env` (gitignored), create a bot with @BotFather, put its token in
`TANOD_BOT_TOKEN`, send the bot a message (or add it to the group chat), then:

```bash
.venv/bin/python -m alerts.telegram chats   # prints the chat id to put in TANOD_CHAT_ID
.venv/bin/python -m alerts.telegram test    # sends one test alert
```

After that, `--attack` and every Unblock send a Telegram message. During the
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
| `TANOD_DASHBOARD_PASSWORD` | `tanod-dev` (dev only) | Built-in admin password until named accounts exist |
| `TANOD_DRY_RUN` | `1` | `0` runs nft, hostapd_cli and conntrack for real (Pi, root) |
| `TANOD_ALERT_ENDPOINT` | `http://127.0.0.1:8081` | Telegram-format endpoint |
| `TANOD_BOT_TOKEN`, `TANOD_CHAT_ID` | test values | Real values only for the separate Telegram check |
| `TANOD_CAMERA_URL` | unset | MJPEG stream shown on the dashboard |

## Open design points for Narz and the advisers

1. **A8 (beacon) is missed.** Feature 7 (new destinations) is always 0 in
   training when the baseline destination list is learned from the same
   days, and an Isolation Forest never splits on a constant feature. Options:
   learn the destination list from days 1 to 3 and train on days 1 to 5, or
   add a simple "new destination" rule next to the model.
2. **The Isolation Forest saturates on floods (A3).** A value far outside the
   training range scores about the same as the most extreme training value,
   so the flood is left to the Suricata rate rule (sid 9000003/9000005).
3. **A9 (deauthentication) can only be noticed, not blocked.** The forged
   frames never reach IP; TANOD sees the camera go silent and alerts the
   owner. Catching the frames themselves needs a second Wi-Fi card in monitor
   mode (or WPA3 with Protected Management Frames, which stops the attack).
4. **MAC addresses can be changed too.** A MAC block stops an attacker that
   only changes its IP. One that also changes its MAC still needs the Wi-Fi
   passphrase to rejoin and is caught again by the same detectors. WPA3 and a
   unique passphrase limit this.
