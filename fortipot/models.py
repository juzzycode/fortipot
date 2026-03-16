"""Core data models for fortipot."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EnforcementMode(str, Enum):
    """Supported enforcement modes."""

    DETECT_ONLY = "detect_only"
    FORTIGATE_QUARANTINE = "fortigate_quarantine"
    FORTIGATE_BLOCK_PUBLIC = "fortigate_block_public"
    APPROVAL_REQUIRED = "approval_required"


class ActionStatus(str, Enum):
    """Lifecycle states for enforcement actions."""

    PROPOSED = "proposed"
    EXECUTED = "executed"
    RELEASED = "released"
    FAILED = "failed"
    SKIPPED = "skipped"


class SourceClassification(str, Enum):
    """Classification of an observed source."""

    PRIVATE = "private_local"
    PUBLIC = "public"
    ALLOWLISTED = "allowlisted"
    EXEMPT = "exempt_infrastructure"
    UNKNOWN = "unknown"


class RecommendedAction(str, Enum):
    """Recommended action from the detector."""

    NONE = "none"
    LOG = "log"
    ALERT = "alert"
    QUARANTINE = "quarantine"
    BLOCK = "block_public_ip"
    QUEUE = "approval_required"


class EventKind(str, Enum):
    """Normalized event kinds used by the detector."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ARP = "arp"


class PacketEvent(BaseModel):
    """Normalized packet observation."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: str
    dst_ip: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    dst_port: int | None = None
    protocol: EventKind
    tcp_flags: str | None = None
    arp_target_ip: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectionDecision(BaseModel):
    """Detector output for a source within a time window."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: str
    src_mac: str | None = None
    classification: SourceClassification
    score: int
    confidence: float
    matched_behaviors: list[str]
    recommended_action: RecommendedAction
    reason: str
    observed_destinations: list[str] = Field(default_factory=list)
    observed_ports: list[int] = Field(default_factory=list)


class EndpointIdentity(BaseModel):
    """Resolved endpoint information for local/private sources."""

    ip: str
    mac: str | None = None
    hostname: str | None = None
    interface: str | None = None
    vlan: str | None = None
    tags: list[str] = Field(default_factory=list)
    source: str = "unknown"
    confidence: float = 0.0
    last_seen: datetime | None = None


class ActionRecord(BaseModel):
    """Stored action record."""

    id: int | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: str
    src_mac: str | None = None
    classification: SourceClassification
    action: RecommendedAction
    mode: EnforcementMode
    status: ActionStatus
    reason: str
    score: int
    confidence: float
    details: dict[str, Any] = Field(default_factory=dict)


@dataclass(slots=True)
class SimulationScenario:
    """Simulation input used by CLI tests and local demos."""

    name: str
    events: list[PacketEvent] = field(default_factory=list)
