"""Registered (protected) cameras and the IP-to-MAC bindings TANOD has seen.

Cameras are identified by MAC address, not IP (Section 3.7): an attacker can
change IP in seconds, so every block is placed on the attacker's MAC. Each
camera has a DHCP reservation, so its MAC and IP are known in advance.

link = "wifi" for cameras on TANOD's own access point, "wired" for the
school's wired IP CCTV that is connected through the gateway's Ethernet port.
"""
from __future__ import annotations

import ipaddress
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
