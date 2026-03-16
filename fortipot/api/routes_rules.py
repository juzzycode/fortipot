"""Rule explanation routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from fortipot.api.server import get_app_state
from fortipot.detector.rules import explain_rules

router = APIRouter()


@router.get("/rules")
def rules(state=Depends(get_app_state)) -> dict:
    """Return the active detector rules and thresholds."""

    return explain_rules(state.settings)
