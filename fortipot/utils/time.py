"""Time helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


def utc_now() -> datetime:
    """Return the current UTC time."""

    return datetime.now(timezone.utc)


def minutes_from_now(minutes: int) -> datetime:
    """Return a UTC timestamp minutes from now."""

    return utc_now() + timedelta(minutes=minutes)
