"""Public IP block enforcement."""

from __future__ import annotations

from fortipot.config import Settings
from fortipot.enforcer.base import Enforcer
from fortipot.enforcer.fortigate import FortiGateClient
from fortipot.models import (
    ActionRecord,
    ActionStatus,
    DetectionDecision,
    EndpointIdentity,
    RecommendedAction,
    SourceClassification,
)


class PublicBlockEnforcer(Enforcer):
    """Apply public IP block actions."""

    def __init__(self, settings: Settings, client: FortiGateClient) -> None:
        self.settings = settings
        self.client = client

    def apply(self, decision: DetectionDecision, endpoint: EndpointIdentity | None = None) -> ActionRecord:
        result = self.client.block_public_ip(
            ip=decision.src_ip,
            duration_minutes=self.settings.safety.auto_release_minutes,
        )
        return ActionRecord(
            src_ip=decision.src_ip,
            src_mac=decision.src_mac,
            classification=decision.classification,
            action=RecommendedAction.BLOCK,
            mode=self.settings.app.mode,
            status=ActionStatus.EXECUTED,
            reason=decision.reason,
            score=decision.score,
            confidence=decision.confidence,
            details=result,
        )

    def release(self, ip: str | None = None, mac: str | None = None) -> ActionRecord:
        result = self.client.release_endpoint(ip=ip, mac=mac)
        return ActionRecord(
            src_ip=ip or "unknown",
            src_mac=mac,
            classification=SourceClassification.PUBLIC if ip else SourceClassification.UNKNOWN,
            action=RecommendedAction.BLOCK,
            mode=self.settings.app.mode,
            status=ActionStatus.RELEASED,
            reason="manual_release",
            score=0,
            confidence=1.0,
            details=result,
        )
