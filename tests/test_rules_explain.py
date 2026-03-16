from fortipot.config import Settings
from fortipot.detector.rules import explain_rules


def test_explain_rules_reflects_detection_settings() -> None:
    settings = Settings.model_validate(
        {
            "detection": {
                "window_seconds": 30,
                "alert_score": 20,
                "isolate_score": 40,
                "syn_scan_ports_threshold": 8,
                "host_fanout_threshold": 6,
                "arp_sweep_threshold": 9,
                "icmp_sweep_threshold": 7,
                "service_fanout_ports": [22, 80],
            }
        }
    )

    payload = explain_rules(settings)

    assert payload["window_seconds"] == 30
    assert payload["actions"]["alert_at_or_above"] == 20
    assert payload["actions"]["quarantine_at_or_above"] == 40
    assert payload["thresholds"]["service_fanout_ports"] == [22, 80]
    assert any(rule["name"] == "service_fanout_80" for rule in payload["rules"])
