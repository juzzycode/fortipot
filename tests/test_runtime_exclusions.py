from fortipot.collector.packet_parser import build_packet_event
from fortipot.config import Settings
from fortipot.main import Runtime
from fortipot.models import EventKind
from fortipot.utils.network import LocalNetworkIdentity


def test_runtime_ignores_local_source_ip() -> None:
    runtime = Runtime.from_settings(
        Settings.model_validate(
            {
                "capture": {
                    "exclude_local_sources": False,
                }
            }
        )
    )
    runtime.local_identity = LocalNetworkIdentity(ips={"10.0.0.5"}, macs=set())

    event = build_packet_event(src_ip="10.0.0.5", protocol=EventKind.ICMP)

    assert runtime.should_ignore_event(event) is True


def test_runtime_ignores_local_source_mac() -> None:
    runtime = Runtime.from_settings(
        Settings.model_validate(
            {
                "capture": {
                    "exclude_local_sources": False,
                }
            }
        )
    )
    runtime.local_identity = LocalNetworkIdentity(ips=set(), macs={"aa:bb:cc:dd:ee:ff"})

    event = build_packet_event(
        src_ip="10.0.0.25",
        src_mac="AA:BB:CC:DD:EE:FF",
        protocol=EventKind.TCP,
        dst_port=22,
        tcp_flags="S",
    )

    assert runtime.should_ignore_event(event) is True


def test_runtime_allows_non_local_sources() -> None:
    runtime = Runtime.from_settings(
        Settings.model_validate(
            {
                "capture": {
                    "exclude_local_sources": False,
                }
            }
        )
    )
    runtime.local_identity = LocalNetworkIdentity(ips={"10.0.0.5"}, macs={"aa:bb:cc:dd:ee:ff"})

    event = build_packet_event(src_ip="10.0.0.25", src_mac="11:22:33:44:55:66", protocol=EventKind.ICMP)

    assert runtime.should_ignore_event(event) is False
