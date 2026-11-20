"""nftables quarantine/block/release and relay control.

Dry-run by default: commands are built and logged but not executed. On the
Pi 5, run with dry_run=False as root (or with CAP_NET_ADMIN).

Relay cutoff is OFF by default. It runs only when both the Enforcer has
relay_enabled=True and the device has relay_cutoff_enabled=True. The relay
contacts are normally closed, so energizing a coil cuts the device's power.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
from typing import Callable, Protocol

log = logging.getLogger("tanod.enforce")

TABLE = "tanod"
MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


def _mac(mac: str) -> str:
    if not MAC_RE.match(mac):
        raise ValueError(f"bad MAC address: {mac!r}")
    return mac.lower()


def _ip(ip: str) -> str:
    return str(ipaddress.IPv4Address(ip))


def nft(*args: str) -> list[str]:
    return ["nft", *args]


# ---- command builders --------------------------------------------------
def setup_commands(wlan: str = "wlan0") -> list[list[str]]:
    """Create the TANOD table, sets and drop rules (run once at boot)."""
    t = ("inet", TABLE)
    cmds = [
        nft("add", "table", *t),
        nft("add", "set", *t, "quarantine_mac", "{ type ether_addr; }"),
        nft("add", "set", *t, "quarantine_ip", "{ type ipv4_addr; }"),
        nft("add", "set", *t, "block_mac", "{ type ether_addr; }"),
        nft("add", "set", *t, "block_ip", "{ type ipv4_addr; }"),
        nft("add", "chain", *t, "forward", "{ type filter hook forward priority -10; policy accept; }"),
        nft("add", "chain", *t, "input", "{ type filter hook input priority -10; policy accept; }"),
        nft("add", "rule", *t, "forward", "ether", "saddr", "@quarantine_mac", "drop"),
        nft("add", "rule", *t, "forward", "ip", "daddr", "@quarantine_ip", "drop"),
        nft("add", "rule", *t, "forward", "ether", "saddr", "@block_mac", "drop"),
        nft("add", "rule", *t, "forward", "ip", "saddr", "@block_ip", "drop"),
        nft("add", "rule", *t, "forward", "ip", "daddr", "@block_ip", "drop"),
        # blocked clients also lose access to the gateway itself (dashboard, SSH)
        nft("add", "rule", *t, "input", "iifname", wlan, "ip", "saddr", "@block_ip", "drop"),
    ]
    return cmds


def quarantine_commands(ip: str, mac: str) -> list[list[str]]:
    return [
        nft("add", "element", "inet", TABLE, "quarantine_mac", f"{{ {_mac(mac)} }}"),
        nft("add", "element", "inet", TABLE, "quarantine_ip", f"{{ {_ip(ip)} }}"),
        ["conntrack", "-D", "-s", _ip(ip)],  # drop live connections
    ]


def block_commands(ip: str, mac: str | None = None) -> list[list[str]]:
    cmds = [nft("add", "element", "inet", TABLE, "block_ip", f"{{ {_ip(ip)} }}")]
    if mac:
        cmds.append(nft("add", "element", "inet", TABLE, "block_mac", f"{{ {_mac(mac)} }}"))
    cmds.append(["conntrack", "-D", "-s", _ip(ip)])
    return cmds


def release_commands(ip: str, mac: str | None = None, kind: str = "quarantine") -> list[list[str]]:
    prefix = "quarantine" if kind == "quarantine" else "block"
    cmds = [nft("delete", "element", "inet", TABLE, f"{prefix}_ip", f"{{ {_ip(ip)} }}")]
    if mac:
        cmds.append(nft("delete", "element", "inet", TABLE, f"{prefix}_mac", f"{{ {_mac(mac)} }}"))
    return cmds


# ---- relays ------------------------------------------------------------
class RelayController(Protocol):
    def cut(self, channel: int) -> None: ...
    def restore(self, channel: int) -> None: ...
    def state(self, channel: int) -> str: ...


class MockRelay:
    """Laptop stand-in. Records what the real relays would do."""

    def __init__(self):
        self.cut_channels: set[int] = set()
        self.history: list[tuple[str, int]] = []

    def cut(self, channel: int) -> None:
        self.cut_channels.add(channel)
        self.history.append(("cut", channel))

    def restore(self, channel: int) -> None:
        self.cut_channels.discard(channel)
        self.history.append(("restore", channel))

    def state(self, channel: int) -> str:
        return "cut" if channel in self.cut_channels else "on"


class GpioRelay:
    """Pi 5 relay driver (Figure 3). Needs gpiozero on the Pi.

    channel -> BCM pin mapping must match the relay board wiring.
    Coil energized (GPIO high) = NC contact opens = device power cut.
    """

    def __init__(self, pins: dict[int, int]):
        from gpiozero import OutputDevice  # imported only on the Pi

        self._out = {ch: OutputDevice(pin, active_high=True, initial_value=False) for ch, pin in pins.items()}

    def cut(self, channel: int) -> None:
        self._out[channel].on()

    def restore(self, channel: int) -> None:
        self._out[channel].off()

    def state(self, channel: int) -> str:
        return "cut" if self._out[channel].value else "on"


# ---- enforcer ----------------------------------------------------------
Runner = Callable[[list[str]], None]


def _subprocess_runner(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=5)


class Enforcer:
    def __init__(self, dry_run: bool = True, relay: RelayController | None = None,
                 relay_enabled: bool = False, runner: Runner | None = None):
        self.dry_run = dry_run
        self.relay = relay or MockRelay()
        self.relay_enabled = relay_enabled
        self.runner = runner or _subprocess_runner
        self.executed: list[list[str]] = []

    def _run(self, cmds: list[list[str]]) -> list[list[str]]:
        for c in cmds:
            self.executed.append(c)
            if self.dry_run:
                log.info("[dry-run] %s", " ".join(c))
            else:
                self.runner(c)
        return cmds

    def setup(self) -> list[list[str]]:
        return self._run(setup_commands())

    def quarantine(self, device) -> list[list[str]]:
        cmds = self._run(quarantine_commands(device.ip, device.mac))
        if self.relay_enabled and device.relay_cutoff_enabled and device.relay_channel is not None:
            self.relay.cut(device.relay_channel)
        return cmds

    def block(self, ip: str, mac: str | None = None) -> list[list[str]]:
        return self._run(block_commands(ip, mac))

    def release(self, ip: str, mac: str | None = None, kind: str = "quarantine",
                relay_channel: int | None = None) -> list[list[str]]:
        cmds = self._run(release_commands(ip, mac, kind))
        if relay_channel is not None and self.relay.state(relay_channel) == "cut":
            self.relay.restore(relay_channel)
        return cmds
