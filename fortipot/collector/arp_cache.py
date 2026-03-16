"""ARP cache helpers."""

from __future__ import annotations

from pathlib import Path

from fortipot.utils.mac import normalize_mac


def read_arp_cache(path: str = "/proc/net/arp") -> dict[str, str]:
    """Read a Linux ARP cache file if available."""

    arp_path = Path(path)
    if not arp_path.exists():
        return {}
    lines = arp_path.read_text(encoding="utf-8").splitlines()[1:]
    entries: dict[str, str] = {}
    for line in lines:
        parts = [part for part in line.split(" ") if part]
        if len(parts) >= 4:
            entries[parts[0]] = normalize_mac(parts[3]) or parts[3]
    return entries
