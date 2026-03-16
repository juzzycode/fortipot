from pathlib import Path

from fortipot.collector.packet_parser import build_packet_event
from fortipot.config import Settings
from fortipot.main import Runtime, handle_decision
from fortipot.models import EventKind
from fortipot.storage.actions import list_actions


def test_handle_decision_queues_in_approval_mode(tmp_path: Path) -> None:
    settings = Settings.model_validate(
        {
            "app": {"mode": "approval_required", "dry_run": True},
            "storage": {"sqlite_path": str(tmp_path / "fortipot.db")},
        }
    )
    runtime = Runtime.from_settings(settings)
    event = build_packet_event(
        src_ip="10.0.0.25",
        dst_ip="10.0.0.10",
        dst_port=445,
        protocol=EventKind.TCP,
        tcp_flags="S",
    )
    for port in range(20, 35):
        event = build_packet_event(
            src_ip="10.0.0.25",
            dst_ip="10.0.0.10",
            dst_port=port,
            protocol=EventKind.TCP,
            tcp_flags="S",
        )
        handle_decision(runtime, event)
    actions = list_actions(settings.storage.sqlite_path)
    assert actions
    assert actions[0]["status"] == "proposed"


def test_public_scan_recommends_block(tmp_path: Path) -> None:
    settings = Settings.model_validate(
        {
            "app": {"mode": "fortigate_block_public", "dry_run": True},
            "storage": {"sqlite_path": str(tmp_path / "fortipot.db")},
        }
    )
    runtime = Runtime.from_settings(settings)
    for port in range(20, 35):
        handle_decision(
            runtime,
            build_packet_event(
                src_ip="8.8.8.8",
                dst_ip="10.0.0.10",
                dst_port=port,
                protocol=EventKind.TCP,
                tcp_flags="S",
            ),
        )
    actions = list_actions(settings.storage.sqlite_path)
    assert actions
    assert actions[0]["action"] == "block_public_ip"


def test_detect_only_never_executes_actions(tmp_path: Path) -> None:
    settings = Settings.model_validate(
        {
            "app": {"mode": "detect_only", "dry_run": True},
            "storage": {"sqlite_path": str(tmp_path / "fortipot.db")},
        }
    )
    runtime = Runtime.from_settings(settings)
    for port in range(20, 35):
        handle_decision(
            runtime,
            build_packet_event(
                src_ip="10.0.0.25",
                dst_ip="10.0.0.10",
                dst_port=port,
                protocol=EventKind.TCP,
                tcp_flags="S",
            ),
        )
    actions = list_actions(settings.storage.sqlite_path)
    assert actions
    assert actions[0]["status"] == "skipped"
    assert actions[0]["reason"] == "detect_only_mode"
