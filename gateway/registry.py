"""Registered (protected) cameras and the IP-to-MAC bindings TANOD has seen.

Cameras are identified by MAC address, not IP (Section 3.7): an attacker can
change IP in seconds, so every block is placed on the attacker's MAC. Each
camera has a DHCP reservation, so its MAC and IP are known in advance.

link = "wifi" for cameras on TANOD's own access point, "wired" for the
school's wired IP CCTV that is connected through the gateway's Ethernet port.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass


@dataclass
class Device:
    name: str
    mac: str
    ip: str
    kind: str = "camera"
    link: str = "wifi"  # wifi or wired

    def __post_init__(self):
        self.mac = self.mac.lower()


class Registry:
    def __init__(self, devices: list[Device], lan_cidr: str = "192.168.50.0/24", gateway_ip: str = "192.168.50.1",
                 gateway_mac: str = "dc:a6:32:00:00:01", viewers: set[str] | None = None):
        self.devices = {d.ip: d for d in devices}
        self.by_mac = {d.mac: d for d in devices}
        self.lan = ipaddress.ip_network(lan_cidr)
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac.lower()
        # addresses that are allowed to watch the cameras (the owner's NVR or viewing PC)
        self.viewers = set(viewers or ())
        # last MAC seen for each LAN IP (from DHCP leases, ARP and the Wi-Fi association table)
        self.bindings: dict[str, str] = {d.ip: d.mac for d in devices}
        self.bindings[gateway_ip] = self.gateway_mac

    # ---- lookups ---------------------------------------------------------
    def is_protected(self, ip: str) -> bool:
        return ip in self.devices

    def is_lan(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in self.lan
        except ValueError:
            return False

    def is_lan_client(self, ip: str) -> bool:
        return self.is_lan(ip) and ip != self.gateway_ip

    def is_unregistered_client(self, ip: str) -> bool:
        """A client on the LAN that is not a registered camera."""
        return self.is_lan_client(ip) and not self.is_protected(ip)

    def is_viewer(self, ip: str) -> bool:
        return ip in self.viewers

    def get(self, ip: str) -> Device | None:
        return self.devices.get(ip)

    def owner_of_mac(self, mac: str) -> Device | None:
        return self.by_mac.get(mac.lower())

    def mac_of(self, ip: str) -> str | None:
        """The MAC an IP was last seen with. None for addresses outside the LAN
        (their packets arrive with the upstream router's MAC, so only the IP can be blocked)."""
        return self.bindings.get(ip) if self.is_lan(ip) else None

    def observe(self, ip: str, mac: str) -> None:
        """Record a binding seen in a DHCP lease, an ARP reply or the association table."""
        if self.is_lan(ip):
            self.bindings[ip] = mac.lower()


def demo_registry() -> Registry:
    """The test cameras on the isolated network (addresses are examples)."""
    return Registry(
        [
            Device("Wi-Fi Camera", "aa:bb:cc:00:00:20", "192.168.50.20", "camera", "wifi"),
            Device("Wired CCTV", "aa:bb:cc:00:00:21", "192.168.50.21", "camera", "wired"),
        ],
        viewers={"10.10.0.7", "192.168.50.5"},
    )


def registry_from_env() -> Registry:
    """Build the registry from environment variables so the VM lab or the Pi can
    match their real addresses without editing code. Anything not set falls back
    to demo_registry's values. gateway/run.py uses this.

      TANOD_LAN          192.168.50.0/24
      TANOD_GATEWAY_IP   192.168.50.1
      TANOD_GATEWAY_MAC  dc:a6:32:00:00:01   (the gateway's own MAC on the LAN)
      TANOD_VIEWERS      10.10.0.7,192.168.50.5   (comma-separated approved viewers)
      TANOD_CAMERAS      one camera per ';', fields split by '|':  name|mac|ip[|wifi|wired]
                         e.g. "Wi-Fi Camera|52:54:00:aa:bb:20|192.168.50.20|wifi"
    """
    base = demo_registry()
    cams_env = os.environ.get("TANOD_CAMERAS", "").strip()
    if cams_env:
        devices = []
        for part in cams_env.split(";"):
            part = part.strip()
            if not part:
                continue
            f = [x.strip() for x in part.split("|")]
            if len(f) < 3:
                raise ValueError(f"TANOD_CAMERAS entry needs name|mac|ip: {part!r}")
            devices.append(Device(f[0], f[1], f[2], "camera", f[3] if len(f) > 3 else "wifi"))
    else:
        devices = list(base.devices.values())
    viewers_env = os.environ.get("TANOD_VIEWERS")
    viewers = set(v.strip() for v in viewers_env.split(",") if v.strip()) if viewers_env else set(base.viewers)
    return Registry(
        devices,
        lan_cidr=os.environ.get("TANOD_LAN", str(base.lan)),
        gateway_ip=os.environ.get("TANOD_GATEWAY_IP", base.gateway_ip),
        gateway_mac=os.environ.get("TANOD_GATEWAY_MAC", base.gateway_mac),
        viewers=viewers,
    )
