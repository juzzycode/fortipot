"""Rolling behavior scoring."""

from __future__ import annotations

from fortipot.config import DetectionConfig
from fortipot.models import RecommendedAction


def calculate_score(indicators: dict[str, int], matches: list[str], config: DetectionConfig) -> tuple[int, float]:
    """Calculate a rolling suspicion score and confidence."""

    score = 0
    score += min(indicators.get("unique_ports", 0), 20)
    score += min(indicators.get("unique_hosts", 0) * 2, 20)
    score += min(indicators.get("arp_targets", 0) * 2, 20)
    score += min(indicators.get("icmp_targets", 0) * 2, 20)
    score += len(matches) * 8
    confidence = min(score / max(config.isolate_score, 1), 1.0)
    return score, round(confidence, 2)


def recommended_action(score: int, config: DetectionConfig) -> RecommendedAction:
    """Map score to a recommendation."""

    if score >= config.isolate_score:
        return RecommendedAction.QUARANTINE
    if score >= config.alert_score:
        return RecommendedAction.ALERT
    return RecommendedAction.LOG
