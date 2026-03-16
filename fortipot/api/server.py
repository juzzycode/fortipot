"""FastAPI app factory."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import FastAPI

from fortipot.config import Settings, get_settings
from fortipot.main import Runtime


@dataclass
class AppState:
    """Shared API state."""

    runtime: Runtime
    settings: Settings


def get_app_state() -> AppState:
    """Dependency hook."""

    raise RuntimeError("App state not initialized")


def create_app(config_path: str | None = None) -> FastAPI:
    """Create the FastAPI application."""

    from fortipot.api.routes_actions import router as actions_router
    from fortipot.api.routes_events import router as events_router
    from fortipot.api.routes_health import router as health_router

    settings = get_settings(config_path)
    runtime = Runtime.from_settings(settings)
    app_state = AppState(runtime=runtime, settings=settings)
    app = FastAPI(title="fortipot", version="0.1.0")
    app.state.fortipot = app_state

    def _state_dependency() -> AppState:
        return app.state.fortipot

    app.dependency_overrides[get_app_state] = _state_dependency

    @app.get("/config/redacted")
    def config_redacted() -> dict:
        """Return redacted configuration."""

        return settings.redacted_dict()

    app.include_router(health_router)
    app.include_router(events_router)
    app.include_router(actions_router)
    return app
