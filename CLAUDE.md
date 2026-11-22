# TANOD: context for Claude

Read this first, then README.md and docs/attack-playbook.md.

## What this is
TANOD (Threat Analysis and Network Observation Device) is a BSECE thesis prototype by Narz Alcaide (software), Rod Dela Cruz and Christian Famador (hardware). It is a Raspberry Pi 5 gateway that protects IP cameras: Wi-Fi cameras on its own access point and wired IP CCTV on its Ethernet port. It detects attacks with Suricata rules, a per-camera Isolation Forest and an IP-MAC binding check. It blocks the **attacker** by MAC address, and alerts the owner on a dashboard and Telegram.

## Design rules (decided after the Chapters 1-3 defense, Nov 2026; do not undo)
- Scope is cameras and their network only. The ESP32 test nodes were removed.
- Block the attacker, never the victim camera. On the LAN, block by MAC (an attacker that changes its IP stays blocked). If a hijacked camera talks to an outside server, block that server and keep the camera up.
- Availability matters (CIA triad), so there is **no relay power cutoff** of the camera.
- Roles: **admin** (research group) and **user** (camera owner). Only an admin creates accounts and there is no public sign-up.
- Two test setups per attack: Setup A = Suricata only, Setup B = Suricata + Isolation Forest. The demo must show which attacks only the Isolation Forest catches.
- The next defense needs a live demo with the admin, user and attacker views open side by side.
- TANOD is one extra layer next to a VPN and a firewall. It does not replace them.

## Safety (non-negotiable)
Attacks (A1-A9) run only on the group's own cameras and Pi, on an isolated test network (RA 10175). Never point attack tools at any other network or device. Attack scripts and wordlists are never committed.

## Repo layout
See the table in README.md. In short: gateway/ (detection, decision, enforcement), dashboard/ (FastAPI + SQLite), alerts/ (Telegram format), suricata/ (local rules), tests/ (pytest), docs/.

## How to work in this repo
- Python 3.10+. Setup: python3 -m venv .venv, then .venv/bin/pip install -r requirements.txt.
- Run .venv/bin/pytest before every push. All tests must pass.
- Never push to main. Work on your own branch (name/short-task) and open a pull request. Narz reviews and merges.
- One task per branch and per PR. Keep PRs small, and in the PR description say what changed and how it was tested.
- Do not commit data/, .env, *.db, secrets, passwords or bot tokens (they are in .gitignore). Keep TANOD_DRY_RUN=1 unless you are on the real Pi.
- This repo is public. Do not add personal info, school or employer names beyond what is already here, or private panel notes.
- Write docs in plain English that the group (ECE students) can follow.

## Known gaps (do not claim these are done)
- A8 (beacon to a command server) is missed. See "Open design points" in README.md.
- T9 log of every flagged window is not built yet.
- Nothing has run on the real Raspberry Pi 5 yet: hostapd/dnsmasq config (WPA2/WPA3, client isolation), Suricata on the Pi, live capture, real nftables.
- Dashboard HTTPS and login lockout are future hardening.

## Current tasks
One branch and one PR per task. Narz reviews and merges.

### Christian, task 1: Raspberry Pi 5 setup kit (branch christian/pi-setup)
Goal: someone with a fresh Pi 5 (Raspberry Pi OS 64-bit) follows one doc and gets a working TANOD gateway.
- pi/hostapd.conf: Wi-Fi AP on wlan0. WPA2/WPA3 (WPA3-SAE with WPA2 fallback, Protected Management Frames on where the camera supports it). Client isolation (ap_isolate=1). ctrl_interface on so `hostapd_cli -i wlan0 deny_acl ADD_MAC` and `deauthenticate` work (gateway/enforce.py calls these). macaddr_acl=0, so the deny list is what blocks.
- pi/dnsmasq.conf: DHCP for the camera subnet, with a reserved IP per camera MAC (the registry is keyed by MAC), a lease file the gateway can read, and DNS.
- Wired CCTV on eth0: the same DHCP reservation idea, on its own subnet.
- pi/setup.sh: installs the packages (hostapd, dnsmasq, suricata, nftables, conntrack, python3-venv), copies the configs, turns on IP forwarding, installs the TANOD venv, and copies suricata/tanod.rules. Safe to run twice. No passwords inside it: the Wi-Fi passphrase comes from an env var or a prompt.
- Optional: a systemd unit for `python3 -m gateway.run --iface wlan0 --eve /var/log/suricata/eve.json`.
- docs/pi-setup.md: step by step, plus a "check it works" list (phone joins the AP, gets the reserved IP, two clients cannot ping each other, Suricata writes eve.json, the TANOD_DRY_RUN=1 run prints block commands).
- Do not change gateway/ code in this task. If the code needs something different (interface name, file path), write it in the PR description for Narz.
- Done when the doc and files are in the PR and it was tested on the real Pi (say in the PR what was and was not tested).

### Christian, task 2: Bill of materials (branch christian/bom)
The panel asked for a bill of materials instead of the costing section.
- docs/bill-of-materials.md: a table with item, specs, quantity, unit price (PHP), subtotal, where to buy (store, not a personal link), and what it is for.
- Camera/network scope only: Pi 5 (8 GB) and its 5 V 5 A power supply, microSD, case/cooling, Wi-Fi IP camera(s) (12 V 2 A), Ethernet cable for the wired CCTV port, monitor-mode Wi-Fi adapter for the A9 test, enclosure, fuse, and anything else the hardware still needs. No ESP32 nodes, no relay board (both removed).
- A total, plus 10% contingency. The old paper budget was PHP 21,208 with the ESP32 nodes. Say how much the new total differs.
- Done when the table is complete and prices are current (put the date checked at the top).
