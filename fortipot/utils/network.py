"""Local network identity helpers."""

from __future__ import annotations

from dataclasses import dataclass, field

from scapy.all import get_if_addr, get_if_hwaddr
from scapy.interfaces import get_working_ifaces

from fortipot.utils.mac import normalize_mac


@dataclass
class LocalNetworkIdentity:
    """Host-local IP and MAC addresses discovered from active interfaces."""

    ips: set[str] = field(default_factory=set)
    macs: set[str] = field(default_factory=set)


def discover_local_identity() -> LocalNetworkIdentity:
    """Return host-local IP and MAC addresses for active interfaces."""

    identity = LocalNetworkIdentity(ips={"127.0.0.1", "::1"})
    for iface in get_working_ifaces():
        name = getattr(iface, "name", None)
        if not name:
            continue
        try:
            ip_address = get_if_addr(name)
        except OSError:
            ip_address = ""
        if ip_address and ip_address != "0.0.0.0":
            identity.ips.add(ip_address)
        try:
            mac_address = normalize_mac(get_if_hwaddr(name))
        except OSError:
            mac_address = None
        if mac_address and mac_address != "00:00:00:00:00:00":
            identity.macs.add(mac_address)
    return identity
