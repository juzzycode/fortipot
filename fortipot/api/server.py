"""FastAPI app factory."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

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
    from fortipot.api.routes_rules import router as rules_router

    settings = get_settings(config_path)
    runtime = Runtime.from_settings(settings)
    app_state = AppState(runtime=runtime, settings=settings)
    app = FastAPI(title="fortipot", version="0.1.0")
    app.state.fortipot = app_state

    def _state_dependency() -> AppState:
        return app.state.fortipot

    app.dependency_overrides[get_app_state] = _state_dependency

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        """Return a simple browser-friendly API index."""

        links = [
            ("/health", "Health"),
            ("/rules", "Rules"),
            ("/events", "Events"),
            ("/actions", "Actions"),
            ("/config/redacted", "Redacted Config"),
            ("/docs", "OpenAPI Docs"),
            ("/redoc", "ReDoc"),
        ]
        items = "\n".join(f'<li><a href="{href}">{label}</a></li>' for href, label in links)
        return f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>fortipot API</title>
    <style>
      body {{
        margin: 2rem auto;
        max-width: 42rem;
        padding: 0 1rem;
        font: 16px/1.5 system-ui, sans-serif;
        color: #1f2937;
        background: #f8fafc;
      }}
      main {{
        background: white;
        border: 1px solid #e5e7eb;
        border-radius: 12px;
        padding: 1.5rem;
        box-shadow: 0 10px 30px rgba(15, 23, 42, 0.06);
      }}
      h1 {{
        margin-top: 0;
      }}
      ul {{
        padding-left: 1.25rem;
      }}
      a {{
        color: #0f766e;
        text-decoration: none;
      }}
      a:hover {{
        text-decoration: underline;
      }}
    </style>
  </head>
  <body>
    <main>
      <h1>fortipot API</h1>
      <p>Local API index for browsing the main endpoints.</p>
      <ul>
        {items}
      </ul>
    </main>
  </body>
</html>
""".strip()

    @app.get("/config/redacted")
    def config_redacted() -> dict:
        """Return redacted configuration."""

        return settings.redacted_dict()

    app.include_router(health_router)
    app.include_router(rules_router)
    app.include_router(events_router)
    app.include_router(actions_router)
    return app
