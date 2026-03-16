"""Rule explanation helpers."""

from __future__ import annotations

from fortipot.config import DetectionConfig, Settings


def explain_rules(settings: Settings) -> dict:
    """Return a structured explanation of the active rule system."""

    config = settings.detection
    return {
        "window_seconds": config.window_seconds,
        "thresholds": _thresholds(config),
        "rules": _rules(settings),
        "scoring": _scoring(config),
        "actions": {
            "log_at_or_above": 0,
            "alert_at_or_above": config.alert_score,
            "quarantine_at_or_above": config.isolate_score,
            "public_sources": "alert/quarantine recommendations are upgraded to block_public_ip",
            "allowlisted_or_exempt_sources": "recommended action becomes none and confidence becomes 0.0",
        },
    }


def _thresholds(config: DetectionConfig) -> dict[str, int | list[int]]:
    return {
        "syn_scan_ports_threshold": config.syn_scan_ports_threshold,
        "host_fanout_threshold": config.host_fanout_threshold,
        "arp_sweep_threshold": config.arp_sweep_threshold,
        "icmp_sweep_threshold": config.icmp_sweep_threshold,
        "bait_touch_threshold": config.bait_touch_threshold,
        "service_fanout_ports": config.service_fanout_ports,
    }


def _rules(settings: Settings) -> list[dict[str, str | int]]:
    config = settings.detection
    rules = [
        {
            "name": "tcp_syn_scan",
            "trigger": f"unique TCP SYN destination ports >= {config.syn_scan_ports_threshold}",
            "indicator": "syn_ports",
        },
        {
            "name": "host_fanout",
            "trigger": f"unique destination hosts >= {config.host_fanout_threshold}",
            "indicator": "unique_hosts",
        },
        {
            "name": "arp_sweep",
            "trigger": f"unique ARP target IPs >= {config.arp_sweep_threshold}",
            "indicator": "arp_targets",
        },
        {
            "name": "icmp_sweep",
            "trigger": f"unique ICMP destination hosts >= {config.icmp_sweep_threshold}",
            "indicator": "icmp_targets",
        },
        *(
            [
                {
                    "name": "bait_port_touch",
                    "trigger": (
                        f"unique bait ports touched >= {config.bait_touch_threshold} "
                        f"across configured bait ports {settings.bait.active_ports()}"
                    ),
                    "indicator": "bait_touched",
                }
            ]
            if settings.bait.active_ports()
            else []
        ),
        *[
            {
                "name": f"service_fanout_{port}",
                "trigger": f"unique destination hosts on port {port} >= {config.host_fanout_threshold}",
                "indicator": f"service_fanout_{port}",
            }
            for port in config.service_fanout_ports
        ],
    ]
    return rules


def _scoring(config: DetectionConfig) -> dict[str, object]:
    return {
        "formula": [
            "score += min(unique_ports, 20)",
            "score += min(unique_hosts * 2, 20)",
            "score += min(arp_targets * 2, 20)",
            "score += min(icmp_targets * 2, 20)",
            "score += len(matched_behaviors) * 8",
        ],
        "confidence": f"min(score / {max(config.isolate_score, 1)}, 1.0), rounded to 2 decimals",
    }
