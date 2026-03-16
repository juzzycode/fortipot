"""Detection engine implementation."""

from __future__ import annotations

from fortipot.config import Settings
from fortipot.detector.scorer import calculate_score, recommended_action
from fortipot.detector.signatures import derive_indicators, matched_behaviors
from fortipot.detector.state import DetectorState
from fortipot.models import DetectionDecision, PacketEvent, RecommendedAction, SourceClassification
from fortipot.utils.ip import classify_ip


class DetectionEngine:
    """Passive rolling detector."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.state = DetectorState()

    def process_event(self, event: PacketEvent) -> DetectionDecision:
        """Process one normalized event."""

        classification = classify_ip(event.src_ip, self.settings)
        events = self.state.add_event(event, self.settings.detection.window_seconds)
        bait_ports = self.settings.bait.active_ports()
        indicators = derive_indicators(events, self.settings.detection, bait_ports=bait_ports)
        behaviors = matched_behaviors(indicators, self.settings.detection, bait_ports=bait_ports)
        score, confidence = calculate_score(indicators, behaviors, self.settings.detection)
        action = recommended_action(score, self.settings.detection)
        if classification == SourceClassification.PUBLIC and action in {
            RecommendedAction.ALERT,
            RecommendedAction.QUARANTINE,
        }:
            action = RecommendedAction.BLOCK
        if classification in {SourceClassification.ALLOWLISTED, SourceClassification.EXEMPT}:
            action = RecommendedAction.NONE
            confidence = 0.0
        return DetectionDecision(
            src_ip=event.src_ip,
            src_mac=event.src_mac,
            classification=classification,
            score=score,
            confidence=confidence,
            matched_behaviors=behaviors,
            recommended_action=action,
            reason=self._build_reason(classification, behaviors, score),
            observed_destinations=sorted({entry.dst_ip for entry in events if entry.dst_ip}),
            observed_ports=sorted({entry.dst_port for entry in events if entry.dst_port is not None}),
        )

    @staticmethod
    def _build_reason(classification: SourceClassification, behaviors: list[str], score: int) -> str:
        """Create a readable decision reason."""

        behavior_text = ",".join(behaviors) if behaviors else "baseline_observation"
        return f"classification={classification.value} score={score} behaviors={behavior_text}"
