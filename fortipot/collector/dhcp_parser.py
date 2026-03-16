"""Passive DHCP lease parsing helpers."""

from __future__ import annotations

from pathlib import Path


def parse_dnsmasq_leases(path: str) -> dict[str, dict[str, str]]:
    """Parse a simple dnsmasq lease file into an inventory map."""

    lease_path = Path(path)
    if not lease_path.exists():
        return {}
    results: dict[str, dict[str, str]] = {}
    for line in lease_path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) >= 4:
            _, mac, ip, hostname = parts[:4]
            results[ip] = {"mac": mac, "hostname": hostname}
    return results
