"""Packet normalization helpers."""

from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from fortipot.models import EventKind, PacketEvent
from fortipot.utils.mac import normalize_mac


def build_packet_event(
    *,
    src_ip: str,
    protocol: EventKind,
    dst_ip: str | None = None,
    src_mac: str | None = None,
    dst_mac: str | None = None,
    dst_port: int | None = None,
    tcp_flags: str | None = None,
    arp_target_ip: str | None = None,
    metadata: dict | None = None,
) -> PacketEvent:
    """Build a normalized packet event from already-parsed data."""

    return PacketEvent(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_mac=src_mac,
        dst_mac=dst_mac,
        dst_port=dst_port,
        protocol=protocol,
        tcp_flags=tcp_flags,
        arp_target_ip=arp_target_ip,
        metadata=metadata or {},
    )


def parse_packet(packet: Packet) -> PacketEvent | None:
    """Convert a scapy packet into a normalized event."""

    src_mac = normalize_mac(packet[Ether].src) if Ether in packet else None
    dst_mac = normalize_mac(packet[Ether].dst) if Ether in packet else None

    if ARP in packet:
        arp = packet[ARP]
        return build_packet_event(
            src_ip=arp.psrc,
            dst_ip=arp.pdst or None,
            src_mac=normalize_mac(getattr(arp, "hwsrc", None)) or src_mac,
            dst_mac=normalize_mac(getattr(arp, "hwdst", None)) or dst_mac,
            protocol=EventKind.ARP,
            arp_target_ip=arp.pdst or None,
        )

    if IP not in packet:
        return None

    ip = packet[IP]
    metadata: dict[str, str] = {}
    sniffed_on = getattr(packet, "sniffed_on", None)
    if sniffed_on:
        metadata["interface"] = str(sniffed_on)

    if TCP in packet:
        tcp = packet[TCP]
        return build_packet_event(
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_mac=src_mac,
            dst_mac=dst_mac,
            dst_port=int(tcp.dport),
            protocol=EventKind.TCP,
            tcp_flags=str(tcp.flags),
            metadata=metadata,
        )
    if UDP in packet:
        udp = packet[UDP]
        return build_packet_event(
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_mac=src_mac,
            dst_mac=dst_mac,
            dst_port=int(udp.dport),
            protocol=EventKind.UDP,
            metadata=metadata,
        )
    if ICMP in packet:
        return build_packet_event(
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_mac=src_mac,
            dst_mac=dst_mac,
            protocol=EventKind.ICMP,
            metadata=metadata,
        )
    return None
