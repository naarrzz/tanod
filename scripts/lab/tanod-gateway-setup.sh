#!/usr/bin/env bash
# Set up the TANOD gateway VM for the Kali test lab (Debian/Ubuntu, two NICs).
#
# The gateway sits INLINE as a transparent bridge between Kali and the camera,
# so all their traffic passes through it, the same way every client's traffic
# passes through the Pi's Wi-Fi access point. Suricata and TANOD watch the
# bridge; nftables blocks the attacker on it.
#
#        Kali VM  ──(host-only net A)──┐
#                                      ├─ [ br0 192.168.50.1 ]  TANOD gateway
#        Camera VM ─(host-only net B)──┘        Suricata + gateway.run + nftables
#
# Run as root ON THE GATEWAY VM, giving it the two interfaces (the two host-only
# adapters). See docs/lab-setup.md for the VMware/UTM clicks.
#
#     sudo ./scripts/lab/tanod-gateway-setup.sh ens33 ens37
#
# Safe to run again. It does NOT start attacks and does NOT touch Wi-Fi.
set -euo pipefail

IF1="${1:-}"
IF2="${2:-}"
BRIDGE_IP="${TANOD_GATEWAY_IP:-192.168.50.1}"
LAN="${TANOD_LAN:-192.168.50.0/24}"
PREFIX="${BRIDGE_IP#*/}"; [ "$PREFIX" = "$BRIDGE_IP" ] && PREFIX=24
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

if [ -z "$IF1" ] || [ -z "$IF2" ]; then
  echo "usage: sudo $0 <iface-to-kali> <iface-to-camera>"
  echo "available interfaces:"; ip -o link show | awk -F': ' '{print "  "$2}' | grep -v lo
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then echo "run as root (sudo)"; exit 1; fi

echo "==> installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq suricata nftables bridge-utils tcpdump iproute2 \
                      python3-venv python3-pip git >/dev/null

echo "==> building the bridge br0 over $IF1 and $IF2 (transparent, inline)"
ip link add name br0 type bridge 2>/dev/null || true
for i in "$IF1" "$IF2"; do
  ip addr flush dev "$i" || true          # the members carry no IP of their own
  ip link set "$i" master br0
  ip link set "$i" up
done
ip link set br0 up
ip addr replace "${BRIDGE_IP%/*}/${PREFIX}" dev br0

echo "==> letting nftables and Suricata see bridged traffic (br_netfilter)"
modprobe br_netfilter || true
cat >/etc/sysctl.d/99-tanod.conf <<EOF
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-arptables = 1
net.ipv4.ip_forward = 1
EOF
sysctl -q --system || true

echo "==> Python environment for TANOD"
cd "$REPO_DIR"
[ -d .venv ] || python3 -m venv .venv
./.venv/bin/pip install -q --upgrade pip
./.venv/bin/pip install -q -r requirements.txt scapy

echo "==> writing the run helper (scripts/lab/lab-run.sh)"
CAMERAS="${TANOD_CAMERAS:-Wi-Fi Camera|52:54:00:aa:bb:20|192.168.50.20|wifi}"
# the Suricata address groups must match the cameras/viewers the registry uses
CAM_IPS="$(printf '%s' "$CAMERAS" | awk -F'[;|]' '{for(i=3;i<=NF;i+=4) printf (i>3?",":"")$i}')"
VIEWERS="${TANOD_VIEWERS:-192.168.50.5}"
cat >"$REPO_DIR/scripts/lab/lab-run.sh" <<EOF
#!/usr/bin/env bash
# Start Suricata + TANOD on the bridge. Rehearse first (dry run); add real blocking with TANOD_DRY_RUN=0.
set -euo pipefail
cd "$REPO_DIR"
export TANOD_CAMERAS="$CAMERAS"
export TANOD_VIEWERS="$VIEWERS"
export TANOD_GATEWAY_IP="${BRIDGE_IP%/*}"
sudo suricata -i br0 -S suricata/tanod.rules -l /var/log/suricata \\
     --set vars.address-groups.CAMERAS="[$CAM_IPS]" \\
     --set vars.address-groups.VIEWERS="[$VIEWERS]" &
sleep 3
sudo -E TANOD_DRY_RUN=\${TANOD_DRY_RUN:-1} ./.venv/bin/python -m gateway.run \\
     --iface br0 --eve /var/log/suricata/eve.json --db data/tanod.db
EOF
chmod +x "$REPO_DIR/scripts/lab/lab-run.sh"

echo
echo "Done. The gateway is now a transparent bridge at ${BRIDGE_IP%/*} on br0."
echo "Set the Kali VM and the camera VM to the SAME 192.168.50.0/24 subnet, gateway ${BRIDGE_IP%/*}."
echo
echo "Next:"
echo "  1. On the camera VM:  sudo python3 tools/camera_sim.py --viewer $VIEWERS"
echo "  2. On this gateway:   ./scripts/lab/lab-run.sh          # dry run, prints the blocks"
echo "     For real blocking: TANOD_DRY_RUN=0 ./scripts/lab/lab-run.sh"
echo "  3. From Kali, run the attacks in docs/attack-playbook.md."
