"""MAC helpers."""

from __future__ import annotations


def normalize_mac(value: str | None) -> str | None:
    """Normalize a MAC address for comparison."""

    if not value:
        return None
    clean = value.replace("-", ":").replace(".", "").lower()
    if ":" in clean:
        parts = clean.split(":")
        return ":".join(part.zfill(2) for part in parts)
    if len(clean) == 12:
        return ":".join(clean[index : index + 2] for index in range(0, 12, 2))
    return value.lower()
