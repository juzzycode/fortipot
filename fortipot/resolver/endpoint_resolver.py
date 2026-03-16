"""Passive endpoint resolution."""

from __future__ import annotations

from fortipot.collector.arp_cache import read_arp_cache
from fortipot.models import DetectionDecision, EndpointIdentity, SourceClassification
from fortipot.resolver.inventory import load_inventory
from fortipot.utils.mac import normalize_mac


class EndpointResolver:
    """Resolve local/private endpoints using passive context only."""

    def __init__(self, inventory_path: str | None = None, arp_cache_path: str = "/proc/net/arp") -> None:
        self.inventory = load_inventory(inventory_path)
        self.arp_cache_path = arp_cache_path

    def resolve(self, decision: DetectionDecision) -> EndpointIdentity:
        """Resolve endpoint identity for a detection decision."""

        if decision.classification != SourceClassification.PRIVATE:
            return EndpointIdentity(ip=decision.src_ip, source="non_local", confidence=0.0)
        arp = read_arp_cache(self.arp_cache_path)
        inventory_entry = self.inventory.get(decision.src_ip, {})
        mac = normalize_mac(decision.src_mac) or arp.get(decision.src_ip) or inventory_entry.get("mac")
        hostname = inventory_entry.get("hostname")
        interface = inventory_entry.get("interface")
        vlan = inventory_entry.get("vlan")
        tags = inventory_entry.get("tags", [])
        confidence = 0.9 if mac else 0.5 if hostname else 0.2
        return EndpointIdentity(
            ip=decision.src_ip,
            mac=mac,
            hostname=hostname,
            interface=interface,
            vlan=vlan,
            tags=tags,
            source="passive_inventory",
            confidence=confidence,
        )
