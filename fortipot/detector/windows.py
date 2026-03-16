"""Rolling time window helpers."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
from typing import TypeVar

T = TypeVar("T")


def expire_older_than(entries: deque[tuple[datetime, T]], window_seconds: int, now: datetime) -> None:
    """Expire entries outside the rolling window."""

    cutoff = now - timedelta(seconds=window_seconds)
    while entries and entries[0][0] < cutoff:
        entries.popleft()
