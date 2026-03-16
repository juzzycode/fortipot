"""Behavior signature derivation."""

from __future__ import annotations

from fortipot.config import DetectionConfig
from fortipot.models import EventKind, PacketEvent


def derive_indicators(events: list[PacketEvent], config: DetectionConfig) -> dict[str, int]:
    """Derive indicator counts from a rolling window."""

    dest_hosts = {event.dst_ip for event in events if event.dst_ip}
    dest_ports = {event.dst_port for event in events if event.dst_port is not None}
    arp_targets = {event.arp_target_ip for event in events if event.arp_target_ip}
    icmp_targets = {
        event.dst_ip
        for event in events
        if event.protocol == EventKind.ICMP and event.dst_ip
    }
    syn_ports = {
        event.dst_port
        for event in events
        if event.protocol == EventKind.TCP and event.tcp_flags and "S" in event.tcp_flags and event.dst_port
    }
    service_fanout = {
        port: {event.dst_ip for event in events if event.dst_port == port and event.dst_ip}
        for port in config.service_fanout_ports
    }
    return {
        "unique_hosts": len(dest_hosts),
        "unique_ports": len(dest_ports),
        "arp_targets": len(arp_targets),
        "icmp_targets": len(icmp_targets),
        "syn_ports": len(syn_ports),
        **{f"service_fanout_{port}": len(hosts) for port, hosts in service_fanout.items()},
    }


def matched_behaviors(indicators: dict[str, int], config: DetectionConfig) -> list[str]:
    """Translate indicators into named suspicious behaviors."""

    matches: list[str] = []
    if indicators["syn_ports"] >= config.syn_scan_ports_threshold:
        matches.append("tcp_syn_scan")
    if indicators["unique_hosts"] >= config.host_fanout_threshold:
        matches.append("host_fanout")
    if indicators["arp_targets"] >= config.arp_sweep_threshold:
        matches.append("arp_sweep")
    if indicators["icmp_targets"] >= config.icmp_sweep_threshold:
        matches.append("icmp_sweep")
    for port in config.service_fanout_ports:
        if indicators.get(f"service_fanout_{port}", 0) >= config.host_fanout_threshold:
            matches.append(f"service_fanout_{port}")
    return matches
