"""Typer CLI for fortipot."""

from __future__ import annotations

import json
from pathlib import Path

import typer
import uvicorn

from fortipot import get_version
from fortipot.api.server import create_app
from fortipot.collector.packet_parser import build_packet_event
from fortipot.config import load_settings
from fortipot.detector.engine import DetectionEngine
from fortipot.detector.rules import explain_rules
from fortipot.logging_utils import configure_logging
from fortipot.main import Runtime, release_action, run_runtime
from fortipot.models import EventKind
from fortipot.storage.actions import list_actions
from fortipot.storage.db import initialize_database
from fortipot.storage.events import list_events

app = typer.Typer(help="fortipot defensive network tripwire")
events_app = typer.Typer()
actions_app = typer.Typer()
quarantine_app = typer.Typer()
app.add_typer(events_app, name="events")
app.add_typer(actions_app, name="actions")
app.add_typer(quarantine_app, name="quarantine")


@app.command()
def run(config: Path = typer.Option(Path("config.example.yaml"), exists=False)) -> None:
    """Run the passive detector."""

    settings = load_settings(config)
    runtime = Runtime.from_settings(settings)
    run_runtime(runtime)


@app.command("check-config")
def check_config(config: Path = typer.Option(Path("config.example.yaml"), exists=False)) -> None:
    """Validate config and print a redacted summary."""

    settings = load_settings(config)
    typer.echo(json.dumps(settings.redacted_dict(), indent=2))


@app.command()
def health(config: Path = typer.Option(Path("config.example.yaml"), exists=False)) -> None:
    """Check local runtime health."""

    settings = load_settings(config)
    initialize_database(settings.storage.sqlite_path)
    typer.echo(json.dumps({"status": "ok", "mode": settings.app.mode.value}))


@app.command("explain-rules")
def explain_rules_command(config: Path = typer.Option(Path("config.example.yaml"), exists=False)) -> None:
    """Print the active detector rule and scoring configuration."""

    settings = load_settings(config)
    typer.echo(json.dumps(explain_rules(settings), indent=2))


@events_app.command("list")
def events_list(
    config: Path = typer.Option(Path("config.example.yaml"), exists=False),
    limit: int = typer.Option(20, min=1, max=500),
) -> None:
    """List recent events."""

    settings = load_settings(config)
    typer.echo(json.dumps(list_events(settings.storage.sqlite_path, limit=limit), indent=2))


@actions_app.command("list")
def actions_list(
    config: Path = typer.Option(Path("config.example.yaml"), exists=False),
    limit: int = typer.Option(20, min=1, max=500),
) -> None:
    """List recent actions."""

    settings = load_settings(config)
    typer.echo(json.dumps(list_actions(settings.storage.sqlite_path, limit=limit), indent=2))


@quarantine_app.command("release")
def quarantine_release(
    config: Path = typer.Option(Path("config.example.yaml"), exists=False),
    ip: str | None = typer.Option(None),
    mac: str | None = typer.Option(None),
) -> None:
    """Release by IP or MAC."""

    settings = load_settings(config)
    runtime = Runtime.from_settings(settings)
    state = type("CliState", (), {"runtime": runtime, "settings": settings})()
    typer.echo(json.dumps(release_action(state, ip=ip, mac=mac), indent=2))


@app.command()
def simulate(
    scenario: str = typer.Option(..., help="Simulation scenario name"),
    config: Path = typer.Option(Path("config.example.yaml"), exists=False),
) -> None:
    """Simulate a detection scenario."""

    settings = load_settings(config)
    configure_logging(settings.app.log_level)
    engine = DetectionEngine(settings)
    for event in _scenario_events(scenario):
        decision = engine.process_event(event)
        typer.echo(decision.model_dump_json())


@app.command()
def api(
    config: Path = typer.Option(Path("config.example.yaml"), exists=False),
    host: str = "127.0.0.1",
    port: int = 8080,
) -> None:
    """Run the FastAPI service."""

    uvicorn.run(create_app(str(config)), host=host, port=port)


@app.command()
def version() -> None:
    """Print the version."""

    typer.echo(get_version())


def main() -> None:
    """Console script entry point."""

    app()


def _scenario_events(name: str):
    if name == "syn_scan":
        return [
            build_packet_event(
                src_ip="10.0.0.25",
                dst_ip="10.0.0.10",
                dst_port=port,
                src_mac="aa:bb:cc:dd:ee:ff",
                protocol=EventKind.TCP,
                tcp_flags="S",
            )
            for port in range(20, 35)
        ]
    if name == "icmp_sweep":
        return [
            build_packet_event(
                src_ip="10.0.0.25",
                dst_ip=f"10.0.0.{index}",
                protocol=EventKind.ICMP,
                src_mac="aa:bb:cc:dd:ee:ff",
            )
            for index in range(10, 25)
        ]
    raise typer.BadParameter(f"Unsupported scenario: {name}")


if __name__ == "__main__":
    main()
