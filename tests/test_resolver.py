from pathlib import Path

from fortipot.collector.packet_parser import build_packet_event
from fortipot.config import Settings
from fortipot.detector.engine import DetectionEngine
from fortipot.models import EventKind
from fortipot.resolver.endpoint_resolver import EndpointResolver


def test_resolver_uses_inventory(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text(
        "10.0.0.25:\n  hostname: workstation-25\n  mac: aa:bb:cc:dd:ee:ff\n  vlan: quarantine-ready\n",
        encoding="utf-8",
    )
    engine = DetectionEngine(Settings())
    decision = engine.process_event(
        build_packet_event(
            src_ip="10.0.0.25",
            dst_ip="10.0.0.10",
            dst_port=445,
            protocol=EventKind.TCP,
            tcp_flags="S",
        )
    )
    resolver = EndpointResolver(inventory_path=str(inventory), arp_cache_path=str(tmp_path / "arp"))
    endpoint = resolver.resolve(decision)
    assert endpoint.hostname == "workstation-25"
    assert endpoint.mac == "aa:bb:cc:dd:ee:ff"
