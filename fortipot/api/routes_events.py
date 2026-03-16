"""Event routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from fortipot.api.server import get_app_state
from fortipot.storage.events import list_events

router = APIRouter()


@router.get("/events")
def events(state=Depends(get_app_state)) -> list[dict]:
    """List recent events."""

    return list_events(state.settings.storage.sqlite_path)
