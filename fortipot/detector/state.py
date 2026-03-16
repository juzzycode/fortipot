"""In-memory rolling state."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime

from fortipot.detector.windows import expire_older_than
from fortipot.models import PacketEvent


@dataclass
class SourceState:
    """Rolling state for a single source."""

    events: deque[tuple[datetime, PacketEvent]] = field(default_factory=deque)

    def add(self, event: PacketEvent, window_seconds: int) -> None:
        """Add an event and expire old observations."""

        self.events.append((event.timestamp, event))
        expire_older_than(self.events, window_seconds, event.timestamp)

    def current_events(self, window_seconds: int, now: datetime) -> list[PacketEvent]:
        """Return current window events."""

        expire_older_than(self.events, window_seconds, now)
        return [event for _, event in self.events]


class DetectorState:
    """Track all observed sources in memory."""

    def __init__(self) -> None:
        self.sources: dict[str, SourceState] = defaultdict(SourceState)

    def add_event(self, event: PacketEvent, window_seconds: int) -> list[PacketEvent]:
        """Add an event and return the current event window for the source."""

        source = self.sources[event.src_ip]
        source.add(event, window_seconds)
        return source.current_events(window_seconds, event.timestamp)
