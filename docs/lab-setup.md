# TANOD test lab (Kali + VMs)

How to build the virtual lab that lets you run **real** Kali attacks against
TANOD before the Raspberry Pi is ready. Once it is working, follow
[attack-playbook.md](attack-playbook.md) for the attacks.

This lab covers attacks A1–A6 (and the camera-side A7/A8). The Wi-Fi-only
attack A9 (deauthentication) needs the Pi access point and your monitor-mode
adapter — see the README's "Running on real traffic" section.

## ⚠️ Scope

Everything here is on an isolated, private virtual network with no bridge to
your real Wi-Fi or the internet. Never attack anything outside this lab
(RA 10175).

## The three VMs

| VM | What it is | Address |
|---|---|---|
| **Kali** | the attacker (nmap, hydra, etc.) | 192.168.50.99 |
| **TANOD gateway** | Debian/Ubuntu, runs Suricata + TANOD + nftables | 192.168.50.1 (on the bridge) |
| **Camera** | a plain Linux VM running `tools/camera_sim.py` | 192.168.50.20 |

The gateway sits **in the middle** as a transparent bridge, so all traffic
between Kali and the camera passes through it — the same way every client's
traffic passes through the Pi's Wi-Fi AP in the real system.

```
  Kali ──[net-A]── (eth0)  TANOD gateway  (eth1) ──[net-B]── Camera
                           br0 = 192.168.50.1
                           Suricata + gateway.run + nftables
```

## VMware Fusion (recommended)

Fusion Pro is free for personal use. On Apple Silicon use ARM64 guests
(Kali ARM64, Debian ARM64).

### 1. Make two isolated networks

VMware Fusion → Settings → Network → **+** to add two custom networks:

- **net-A**: uncheck "Connect the host", uncheck "Provide addresses" (no DHCP),
  uncheck "NAT". This keeps it fully isolated.
- **net-B**: same settings.

(If you prefer, one host-only network for both sides also works, but two makes
the gateway a clean in-line bridge and matches the Pi better.)

### 2. Create the VMs

- **Kali**: import the Kali VMware/ARM image. One network adapter → **net-A**.
- **Camera**: a minimal Debian/Ubuntu. One adapter → **net-B**.
- **TANOD gateway**: Debian/Ubuntu, **two** adapters → one on **net-A**, one on
  **net-B**. 2 GB RAM is enough.

### 3. Set static addresses (no DHCP in the lab)

- Kali: `192.168.50.99/24`, gateway `192.168.50.1`
- Camera: `192.168.50.20/24`, gateway `192.168.50.1`
- Gateway: the setup script gives `br0` the `192.168.50.1` address.

On Kali/camera (replace `eth0` with the real name from `ip link`):
```bash
sudo ip addr add 192.168.50.99/24 dev eth0      # .20 on the camera
sudo ip route add default via 192.168.50.1
```

## UTM (alternative)

UTM works too; the inside of the VMs is identical. The difference is the
networking: use UTM's **Emulated VLAN** / host-only mode and put the VMs on the
same isolated network, or give the gateway two network devices. UTM's custom
networking is more manual than Fusion's, which is why Fusion is recommended for
this lab. Everything below (the setup script, camera stand-in, attacks) is the
same.

## Set up the gateway

Clone this repo onto the gateway VM, then run the setup script with its two
interface names (find them with `ip link`):

```bash
git clone https://github.com/naarrzz/tanod.git && cd tanod
sudo ./scripts/lab/tanod-gateway-setup.sh eth0 eth1
```

It installs Suricata, nftables and the TANOD venv, builds the transparent
bridge `br0`, turns on `br_netfilter` so nftables and Suricata see the bridged
traffic, and writes `scripts/lab/lab-run.sh`.

Match the camera's real MAC if you want the MAC-block story to be exact: set
`TANOD_CAMERAS` before running the script, e.g.
```bash
sudo TANOD_CAMERAS="Wi-Fi Camera|<camera-vm-mac>|192.168.50.20|wifi" \
     ./scripts/lab/tanod-gateway-setup.sh eth0 eth1
```

## Run the demo

1. **Camera VM** — start the stand-in camera:
   ```bash
   sudo python3 tools/camera_sim.py --viewer 192.168.50.5
   ```
   (The viewer address is just where the "video" is sent; it does not need to
   exist, the gateway still sees the stream.)

2. **Gateway VM** — rehearse first (dry run prints the block commands):
   ```bash
   ./scripts/lab/lab-run.sh
   ```
   When it looks right, block for real:
   ```bash
   TANOD_DRY_RUN=0 ./scripts/lab/lab-run.sh
   ```

3. **Dashboard** (gateway VM, another terminal) so the panel watches TANOD react:
   ```bash
   ./.venv/bin/uvicorn dashboard.app:app --host 0.0.0.0 --port 8000
   ```

4. **Kali VM** — run the attacks from [attack-playbook.md](attack-playbook.md),
   e.g. `sudo nmap -sS -p- 192.168.50.20`. Watch the dashboard flag the attack
   and block the attacker while the camera stays up.

## Check it works

- From Kali: `ping 192.168.50.20` succeeds (the bridge passes normal traffic).
- `sudo nmap -sS 192.168.50.20` shows the camera ports open (80/554/8080).
- The dry-run gateway prints `block ...` lines when you attack; the dashboard
  shows the attacker in "Blocked attackers".
- With `TANOD_DRY_RUN=0`, after a block, Kali can no longer reach the camera; a
  new IP on Kali is blocked again on its next attack.

## What this lab can and cannot show

- **Shows for real:** A1 scan, A2 brute force, A3 flood, A4 ARP spoof,
  A5 MAC clone, A6 stream viewing — real Kali tools, real Suricata and
  Isolation-Forest detection, real nftables blocking.
- **IP vs MAC blocking:** on the bridge, IP blocking always applies. The full
  MAC block plus kicking the attacker off Wi-Fi (hostapd deny + deauth) is only
  on the Pi, because there is no Wi-Fi here. Say this to the panel.
- **Not here:** A9 Wi-Fi deauthentication (needs the Pi AP + your monitor-mode
  adapter).
