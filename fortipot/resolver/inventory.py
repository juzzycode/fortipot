"""Local inventory cache."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_inventory(path: str | None) -> dict[str, Any]:
    """Load a small YAML inventory cache."""

    if not path:
        return {}
    inventory_path = Path(path)
    if not inventory_path.exists():
        return {}
    return yaml.safe_load(inventory_path.read_text(encoding="utf-8")) or {}
