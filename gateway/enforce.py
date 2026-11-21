"""Blocking the attacker: nftables, hostapd and conntrack.

TANOD never cuts off the camera being attacked. It blocks the attacker:
- by MAC (nftables ether saddr + hostapd deny list + Wi-Fi deauthentication)
  when the attacker is on the LAN, so a new IP does not get it back in;
- by IP when the attacker is outside the LAN, or when only its IP is safe to
  block (a cloned camera MAC must not be blocked, or the real camera goes down).

Dry run by default: commands are built and logged but not executed. On the
Pi 5, run with dry_run=False as root (or with CAP_NET_ADMIN).
"""
from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
from typing import Callable

log = logging.getLogger("tanod.enforce")

TABLE = "tanod"
WLAN = "wlan0"
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
def setup_commands(wlan: str = WLAN) -> list[list[str]]:
    """Create the TANOD table, sets and drop rules (run once at boot)."""
    t = ("inet", TABLE)
    return [
        nft("add", "table", *t),
        nft("add", "set", *t, "block_mac", "{ type ether_addr; }"),
        nft("add", "set", *t, "block_ip", "{ type ipv4_addr; }"),
        nft("add", "chain", *t, "forward", "{ type filter hook forward priority -10; policy accept; }"),
        nft("add", "chain", *t, "input", "{ type filter hook input priority -10; policy accept; }"),
        nft("add", "rule", *t, "forward", "ether", "saddr", "@block_mac", "drop"),
        nft("add", "rule", *t, "forward", "ip", "saddr", "@block_ip", "drop"),
        nft("add", "rule", *t, "forward", "ip", "daddr", "@block_ip", "drop"),
        # blocked attackers also lose access to the gateway itself (dashboard, SSH, DHCP renewals)
        nft("add", "rule", *t, "input", "ether", "saddr", "@block_mac", "drop"),
        nft("add", "rule", *t, "input", "ip", "saddr", "@block_ip", "drop"),
    ]


def block_commands(ip: str | None = None, mac: str | None = None, wlan: str = WLAN) -> list[list[str]]:
    if not ip and not mac:
        raise ValueError("need an IP or a MAC to block")
    cmds = []
    if mac:
        m = _mac(mac)
        cmds += [
            nft("add", "element", "inet", TABLE, "block_mac", f"{{ {m} }}"),
            # keep it off the Wi-Fi: deny list, then kick it off now
            ["hostapd_cli", "-i", wlan, "deny_acl", "ADD_MAC", m],
            ["hostapd_cli", "-i", wlan, "deauthenticate", m],
        ]
    if ip:
        cmds += [nft("add", "element", "inet", TABLE, "block_ip", f"{{ {_ip(ip)} }}"),
                 ["conntrack", "-D", "-s", _ip(ip)],  # drop its live connections
                 ["conntrack", "-D", "-d", _ip(ip)]]
    return cmds


def release_commands(ip: str | None = None, mac: str | None = None, wlan: str = WLAN) -> list[list[str]]:
    cmds = []
    if mac:
        m = _mac(mac)
        cmds += [nft("delete", "element", "inet", TABLE, "block_mac", f"{{ {m} }}"),
                 ["hostapd_cli", "-i", wlan, "deny_acl", "DEL_MAC", m]]
    if ip:
        cmds.append(nft("delete", "element", "inet", TABLE, "block_ip", f"{{ {_ip(ip)} }}"))
    return cmds


# ---- enforcer ----------------------------------------------------------
Runner = Callable[[list[str]], None]


def _subprocess_runner(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=5)


# A wired attacker is not in hostapd, and conntrack exits non-zero when there was
# nothing to delete; neither should stop the rest of the block.
BEST_EFFORT = {"hostapd_cli", "conntrack"}


class Enforcer:
    def __init__(self, dry_run: bool = True, runner: Runner | None = None, wlan: str = WLAN):
        self.dry_run = dry_run
        self.runner = runner or _subprocess_runner
        self.wlan = wlan
        self.executed: list[list[str]] = []

    def _run(self, cmds: list[list[str]]) -> list[list[str]]:
        for c in cmds:
            self.executed.append(c)
            if self.dry_run:
                log.info("[dry-run] %s", " ".join(c))
                continue
            try:
                self.runner(c)
            except subprocess.CalledProcessError as e:
                if c[0] not in BEST_EFFORT:
                    raise
                log.info("%s: %s", " ".join(c), (e.stderr or "").strip())
        return cmds

    def setup(self) -> list[list[str]]:
        return self._run(setup_commands(self.wlan))

    def block(self, ip: str | None = None, mac: str | None = None) -> list[list[str]]:
        return self._run(block_commands(ip, mac, self.wlan))

    def release(self, ip: str | None = None, mac: str | None = None) -> list[list[str]]:
        return self._run(release_commands(ip, mac, self.wlan))
