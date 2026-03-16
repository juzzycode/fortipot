"""Packet normalization helpers."""

from __future__ import annotations

from fortipot.models import EventKind, PacketEvent


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
