from fortipot.collector.packet_parser import build_packet_event
from fortipot.config import Settings
from fortipot.detector.engine import DetectionEngine
from fortipot.models import EventKind, RecommendedAction


def test_detector_flags_syn_scan() -> None:
    engine = DetectionEngine(Settings())
    decision = None
    for port in range(20, 35):
        decision = engine.process_event(
            build_packet_event(
                src_ip="10.0.0.5",
                dst_ip="10.0.0.10",
                dst_port=port,
                protocol=EventKind.TCP,
                tcp_flags="S",
            )
        )
    assert decision is not None
    assert "tcp_syn_scan" in decision.matched_behaviors
    assert decision.recommended_action in {RecommendedAction.ALERT, RecommendedAction.QUARANTINE}


def test_detector_flags_bait_port_touch() -> None:
    settings = Settings.model_validate(
        {
            "bait": {
                "enabled": True,
                "ssh": {"enabled": True, "port": 22},
            }
        }
    )
    engine = DetectionEngine(settings)

    decision = engine.process_event(
        build_packet_event(
            src_ip="10.0.0.25",
            dst_ip="10.0.0.10",
            dst_port=22,
            protocol=EventKind.TCP,
            tcp_flags="S",
        )
    )

    assert "bait_port_touch" in decision.matched_behaviors
