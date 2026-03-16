"""Event routes."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from fortipot.api.server import get_app_state
from fortipot.storage.events import list_events

router = APIRouter()


@router.get("/events")
def events(state=Depends(get_app_state)) -> Response:
    """List recent events."""

    events_list = list_events(state.settings.storage.sqlite_path)
    body = _render_events_json(events_list)
    return Response(content=body, media_type="application/json")


def _render_events_json(events_list: list[dict]) -> str:
    """Render event output with spacing between entries for readability."""

    if not events_list:
        return "[]"
    rendered = [json.dumps(event, indent=2, default=str) for event in events_list]
    return "[\n" + ",\n\n".join(rendered) + "\n]"
