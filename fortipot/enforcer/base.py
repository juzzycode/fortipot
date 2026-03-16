"""Base enforcement interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod

from fortipot.models import ActionRecord, DetectionDecision, EndpointIdentity


class Enforcer(ABC):
    """Abstract enforcer interface."""

    @abstractmethod
    def apply(self, decision: DetectionDecision, endpoint: EndpointIdentity | None = None) -> ActionRecord:
        """Apply an enforcement decision."""

    @abstractmethod
    def release(self, ip: str | None = None, mac: str | None = None) -> ActionRecord:
        """Release a previously applied action."""
