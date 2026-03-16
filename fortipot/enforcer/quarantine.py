"""Local/private quarantine enforcement."""

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


class QuarantineEnforcer(Enforcer):
    """Apply local/private quarantine through the FortiGate client."""

    def __init__(self, settings: Settings, client: FortiGateClient) -> None:
        self.settings = settings
        self.client = client

    def apply(self, decision: DetectionDecision, endpoint: EndpointIdentity | None = None) -> ActionRecord:
        if self.settings.safety.require_mac_for_local_quarantine and not (endpoint and endpoint.mac):
            return ActionRecord(
                src_ip=decision.src_ip,
                src_mac=decision.src_mac,
                classification=decision.classification,
                action=RecommendedAction.QUARANTINE,
                mode=self.settings.app.mode,
                status=ActionStatus.SKIPPED,
                reason="mac_required_for_quarantine",
                score=decision.score,
                confidence=decision.confidence,
            )
        result = self.client.quarantine_endpoint(
            ip=decision.src_ip,
            mac=endpoint.mac if endpoint else decision.src_mac,
            duration_minutes=self.settings.safety.auto_release_minutes,
        )
        return ActionRecord(
            src_ip=decision.src_ip,
            src_mac=endpoint.mac if endpoint else decision.src_mac,
            classification=decision.classification,
            action=RecommendedAction.QUARANTINE,
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
            classification=SourceClassification.PRIVATE if ip else SourceClassification.UNKNOWN,
            action=RecommendedAction.QUARANTINE,
            mode=self.settings.app.mode,
            status=ActionStatus.RELEASED,
            reason="manual_release",
            score=0,
            confidence=1.0,
            details=result,
        )
