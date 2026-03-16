from fortipot.config import DetectionConfig
from fortipot.detector.scorer import calculate_score, recommended_action
from fortipot.models import RecommendedAction


def test_scoring_reaches_quarantine() -> None:
    config = DetectionConfig()
    indicators = {"unique_ports": 15, "unique_hosts": 10, "arp_targets": 0, "icmp_targets": 0}
    score, confidence = calculate_score(indicators, ["tcp_syn_scan", "host_fanout"], config)
    assert score >= config.isolate_score
    assert confidence == 1.0
    assert recommended_action(score, config) == RecommendedAction.QUARANTINE
