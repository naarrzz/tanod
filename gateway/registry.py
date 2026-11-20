"""Registered (protected) devices, identified by MAC address (Section 3.7)."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass
class Device:
    name: str
    mac: str
    ip: str
    kind: str = "esp32"  # esp32 or camera
    relay_channel: int | None = None
    relay_cutoff_enabled: bool = False  # off by default, owner enables per device


class Registry:
    def __init__(self, devices: list[Device], lan_cidr: str = "192.168.50.0/24", gateway_ip: str = "192.168.50.1"):
        self.devices = {d.ip: d for d in devices}
        self.lan = ipaddress.ip_network(lan_cidr)
        self.gateway_ip = gateway_ip

    def is_protected(self, ip: str) -> bool:
        return ip in self.devices

    def is_lan_client(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in self.lan and ip != self.gateway_ip
        except ValueError:
            return False

    def is_unregistered_client(self, ip: str) -> bool:
        """A Wi-Fi client that joined but is not a registered device."""
        return self.is_lan_client(ip) and not self.is_protected(ip)

    def get(self, ip: str) -> Device | None:
        return self.devices.get(ip)


def demo_registry() -> Registry:
    """The four test devices on the isolated network (addresses are examples)."""
    return Registry(
        [
            Device("ESP32 Node 1", "aa:bb:cc:00:00:01", "192.168.50.11", "esp32", relay_channel=1),
            Device("ESP32 Node 2", "aa:bb:cc:00:00:02", "192.168.50.12", "esp32", relay_channel=2),
            Device("ESP32 Node 3", "aa:bb:cc:00:00:03", "192.168.50.13", "esp32", relay_channel=3),
            Device("IP Camera", "aa:bb:cc:00:00:04", "192.168.50.20", "camera", relay_channel=4),
        ]
    )
