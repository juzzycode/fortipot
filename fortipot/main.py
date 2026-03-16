"""Runtime orchestration for fortipot."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from fortipot.collector.pcap_listener import PacketCaptureListener
from fortipot.config import Settings
from fortipot.detector.engine import DetectionEngine
from fortipot.enforcer.blocker import PublicBlockEnforcer
from fortipot.enforcer.fortigate import FortiGateClient
from fortipot.enforcer.quarantine import QuarantineEnforcer
from fortipot.logging_utils import configure_logging, get_logger
from fortipot.models import (
    ActionRecord,
    ActionStatus,
    PacketEvent,
    RecommendedAction,
    SourceClassification,
)
from fortipot.resolver.endpoint_resolver import EndpointResolver
from fortipot.storage.actions import record_action
from fortipot.storage.db import initialize_database
from fortipot.storage.events import record_event
from fortipot.utils.ip import classify_ip
from fortipot.utils.time import utc_now

logger = get_logger(__name__)


@dataclass
class ActionGuard:
    """In-memory safety checks for automated enforcement."""

    settings: Settings
    recent_actions: deque = field(default_factory=deque)
    last_action_by_source: dict[str, datetime] = field(default_factory=dict)

    def allows(self, src_ip: str, confidence: float) -> tuple[bool, str]:
        """Return whether an automatic action is allowed."""

        now = utc_now()
        if confidence < self.settings.safety.min_confidence_for_isolation:
            return False, "confidence_below_minimum"
        window_start = now - timedelta(minutes=1)
        while self.recent_actions and self.recent_actions[0] < window_start:
            self.recent_actions.popleft()
        if len(self.recent_actions) >= self.settings.safety.max_auto_actions_per_minute:
            return False, "rate_limit_exceeded"
        last_action = self.last_action_by_source.get(src_ip)
        if last_action and now - last_action < timedelta(minutes=self.settings.safety.cooldown_minutes):
            return False, "cooldown_active"
        return True, "allowed"

    def record(self, src_ip: str) -> None:
        """Record an automated action."""

        now = utc_now()
        self.recent_actions.append(now)
        self.last_action_by_source[src_ip] = now


@dataclass
class Runtime:
    """Application runtime container."""

    settings: Settings
    detector: DetectionEngine
    resolver: EndpointResolver
    capture: PacketCaptureListener
    quarantine_enforcer: QuarantineEnforcer
    public_block_enforcer: PublicBlockEnforcer
    action_guard: ActionGuard

    @classmethod
    def from_settings(cls, settings: Settings) -> "Runtime":
        """Build a runtime from settings."""

        initialize_database(settings.storage.sqlite_path)
        client = FortiGateClient(settings.fortigate, dry_run=settings.app.dry_run)
        return cls(
            settings=settings,
            detector=DetectionEngine(settings),
            resolver=EndpointResolver(),
            capture=PacketCaptureListener(
                interface=settings.capture.interface,
                bpf_filter=settings.capture.bpf_filter,
                promiscuous=settings.capture.promiscuous,
            ),
            quarantine_enforcer=QuarantineEnforcer(settings, client),
            public_block_enforcer=PublicBlockEnforcer(settings, client),
            action_guard=ActionGuard(settings),
        )


def handle_decision(runtime: Runtime, event: PacketEvent) -> tuple[int, int | None]:
    """Persist a decision and execute or queue an action if needed."""

    decision = runtime.detector.process_event(event)
    event_id = record_event(runtime.settings.storage.sqlite_path, decision)
    action_id: int | None = None
    if decision.recommended_action in {RecommendedAction.LOG, RecommendedAction.NONE}:
        return event_id, action_id
    if runtime.settings.app.mode.value == "detect_only":
        action = ActionRecord(
            src_ip=decision.src_ip,
            src_mac=decision.src_mac,
            classification=decision.classification,
            action=decision.recommended_action,
            mode=runtime.settings.app.mode,
            status=ActionStatus.SKIPPED,
            reason="detect_only_mode",
            score=decision.score,
            confidence=decision.confidence,
            details={"original_reason": decision.reason},
        )
        action_id = record_action(runtime.settings.storage.sqlite_path, action)
        return event_id, action_id
    if runtime.settings.app.mode.value == "approval_required":
        action = ActionRecord(
            src_ip=decision.src_ip,
            src_mac=decision.src_mac,
            classification=decision.classification,
            action=RecommendedAction.QUEUE,
            mode=runtime.settings.app.mode,
            status=ActionStatus.PROPOSED,
            reason=decision.reason,
            score=decision.score,
            confidence=decision.confidence,
            details={"decision_action": decision.recommended_action.value},
        )
        action_id = record_action(runtime.settings.storage.sqlite_path, action)
        return event_id, action_id
    if (
        runtime.settings.app.mode.value == "fortigate_quarantine"
        and decision.recommended_action == RecommendedAction.BLOCK
    ) or (
        runtime.settings.app.mode.value == "fortigate_block_public"
        and decision.recommended_action == RecommendedAction.QUARANTINE
    ):
        action = ActionRecord(
            src_ip=decision.src_ip,
            src_mac=decision.src_mac,
            classification=decision.classification,
            action=decision.recommended_action,
            mode=runtime.settings.app.mode,
            status=ActionStatus.SKIPPED,
            reason="mode_action_mismatch",
            score=decision.score,
            confidence=decision.confidence,
            details={"original_reason": decision.reason},
        )
        action_id = record_action(runtime.settings.storage.sqlite_path, action)
        return event_id, action_id
    allowed, reason = runtime.action_guard.allows(decision.src_ip, decision.confidence)
    if not allowed:
        action = ActionRecord(
            src_ip=decision.src_ip,
            src_mac=decision.src_mac,
            classification=decision.classification,
            action=decision.recommended_action,
            mode=runtime.settings.app.mode,
            status=ActionStatus.SKIPPED,
            reason=reason,
            score=decision.score,
            confidence=decision.confidence,
            details={"original_reason": decision.reason},
        )
        action_id = record_action(runtime.settings.storage.sqlite_path, action)
        return event_id, action_id
    endpoint = runtime.resolver.resolve(decision)
    if decision.recommended_action == RecommendedAction.BLOCK:
        action = runtime.public_block_enforcer.apply(decision, endpoint)
    elif decision.recommended_action == RecommendedAction.QUARANTINE:
        action = runtime.quarantine_enforcer.apply(decision, endpoint)
    else:
        action = ActionRecord(
            src_ip=decision.src_ip,
            src_mac=decision.src_mac,
            classification=decision.classification,
            action=decision.recommended_action,
            mode=runtime.settings.app.mode,
            status=ActionStatus.SKIPPED,
            reason=decision.reason,
            score=decision.score,
            confidence=decision.confidence,
        )
    if action.status == ActionStatus.EXECUTED:
        runtime.action_guard.record(decision.src_ip)
    action_id = record_action(runtime.settings.storage.sqlite_path, action)
    return event_id, action_id


def run_runtime(runtime: Runtime) -> None:
    """Run the passive listener loop."""

    configure_logging(runtime.settings.app.log_level)
    logger.info(
        "fortipot_starting",
        mode=runtime.settings.app.mode.value,
        dry_run=runtime.settings.app.dry_run,
        interface=runtime.settings.capture.interface,
    )
    for event in runtime.capture.listen():
        handle_decision(runtime, event)


def approve_action(state, action_id: int) -> dict:
    """Approve a queued action.

    This MVP records approval requests and returns a workflow placeholder until
    action replay is expanded in a later release.
    """

    return {"approved": True, "action_id": action_id, "note": "approval workflow placeholder"}


def release_action(state, ip: str | None = None, mac: str | None = None) -> dict:
    """Release an action by IP or MAC."""

    classification = classify_ip(ip, state.settings) if ip else SourceClassification.UNKNOWN
    if classification == SourceClassification.PUBLIC:
        record = state.runtime.public_block_enforcer.release(ip=ip, mac=mac)
    else:
        record = state.runtime.quarantine_enforcer.release(ip=ip, mac=mac)
    action_id = record_action(state.settings.storage.sqlite_path, record)
    return {"released": True, "action_id": action_id}
