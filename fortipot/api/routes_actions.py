"""Action routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from fortipot.api.server import get_app_state
from fortipot.main import approve_action, release_action
from fortipot.storage.actions import list_actions

router = APIRouter()


class ApproveRequest(BaseModel):
    """Approve action request."""

    action_id: int


class ReleaseRequest(BaseModel):
    """Manual release request."""

    ip: str | None = None
    mac: str | None = None


@router.get("/actions")
def actions(state=Depends(get_app_state)) -> list[dict]:
    """List recent actions."""

    return list_actions(state.settings.storage.sqlite_path)


@router.post("/actions/approve")
def approve(payload: ApproveRequest, state=Depends(get_app_state)) -> dict:
    """Approve a queued action."""

    return approve_action(state, payload.action_id)


@router.post("/actions/release")
def release(payload: ReleaseRequest, state=Depends(get_app_state)) -> dict:
    """Release an action by IP or MAC."""

    return release_action(state, ip=payload.ip, mac=payload.mac)
