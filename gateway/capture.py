"""Turn real network traffic into the Packets and Observations the rest of TANOD uses.

The detection code (features, model, decision, spoof) does not care whether a
packet was made up by the simulator or sniffed off a real interface: it works
on the Packet and Observation dataclasses. This module is the bridge that reads
real frames (live from an interface, or from a pcap file) and produces those.

Each captured frame becomes a Frame:
  - packet:      the IP packet metadata (for the per-camera features), or None
  - observation: an ARP claim "<ip> is-at <mac>" (for the IP-MAC binding check), or None
  - src_ip/src_mac: so the gateway can learn which MAC each IP is using, and
                    block an attacker by its real MAC.

Scapy is imported lazily, only when actually sniffing or reading a pcap, so the
rest of TANOD (and the tests) do not need it. Install it on the Pi / lab VM:
    pip install scapy    (already in requirements.txt)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterator

from .features import Packet
from .spoof import Observation


@dataclass
class Frame:
    ts: float
    src_ip: str | None = None
    src_mac: str | None = None
    packet: Packet | None = None
    observation: Observation | None = None


def make_frame(ts: float, src_mac: str, dst_mac: str, *, src_ip: str | None = None, dst_ip: str | None = None,
               proto: str = "tcp", sport: int = 0, dport: int = 0, size: int = 0,
               syn: bool = False, ack: bool = False, rst: bool = False,
               arp_op: int = 0, arp_ip: str | None = None) -> Frame:
    """Build a Frame from plain fields. Pure and testable; frame_from_scapy fills these in.

    arp_op 1 (request) or 2 (reply) makes an Observation that <arp_ip> is at <src_mac>."""
    src_mac = src_mac.lower() if src_mac else None
    if arp_op in (1, 2) and arp_ip:
        return Frame(ts=ts, src_ip=arp_ip, src_mac=src_mac,
                     observation=Observation(ts=ts, ip=arp_ip, mac=src_mac, via="arp"))
    packet = None
    if src_ip and dst_ip:
        packet = Packet(ts=ts, src=src_ip, dst=dst_ip, size=size, proto=proto,
                        sport=sport, dport=dport, syn=syn, ack=ack, rst=rst)
    return Frame(ts=ts, src_ip=src_ip, src_mac=src_mac, packet=packet)


def frame_from_scapy(pkt) -> Frame | None:
    """Convert one scapy packet into a Frame, or None if it is not IP or ARP."""
    from scapy.layers.inet import IP, TCP, UDP  # noqa: lazy import
    from scapy.layers.l2 import ARP, Ether

    ts = float(getattr(pkt, "time", 0.0))
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
    dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else None

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        return make_frame(ts, src_mac or arp.hwsrc, dst_mac or "", arp_op=int(arp.op), arp_ip=arp.psrc)

    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]
    size = len(pkt)
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        flags = int(t.flags)
        return make_frame(ts, src_mac, dst_mac, src_ip=ip.src, dst_ip=ip.dst, proto="tcp",
                          sport=int(t.sport), dport=int(t.dport), size=size,
                          syn=bool(flags & 0x02), ack=bool(flags & 0x10), rst=bool(flags & 0x04))
    if pkt.haslayer(UDP):
        u = pkt[UDP]
        return make_frame(ts, src_mac, dst_mac, src_ip=ip.src, dst_ip=ip.dst, proto="udp",
                          sport=int(u.sport), dport=int(u.dport), size=size)
    return make_frame(ts, src_mac, dst_mac, src_ip=ip.src, dst_ip=ip.dst, proto="ip", size=size)


def frames_from_pcap(path: str) -> Iterator[Frame]:
    """Read a pcap file (e.g. one Suricata or tcpdump saved) and yield Frames."""
    from scapy.utils import PcapReader

    with PcapReader(path) as reader:
        for pkt in reader:
            frame = frame_from_scapy(pkt)
            if frame:
                yield frame


def sniff_live(iface: str, on_frame: Callable[[Frame], None], stop) -> None:
    """Sniff an interface and call on_frame for each IP/ARP frame until stop() is true.
    Needs root (or CAP_NET_RAW). Runs on the Pi's wlan0 or the lab VM's eth0."""
    from scapy.sendrecv import sniff

    def handle(pkt):
        frame = frame_from_scapy(pkt)
        if frame:
            on_frame(frame)

    sniff(iface=iface, prn=handle, store=False, stop_filter=lambda _p: stop())
