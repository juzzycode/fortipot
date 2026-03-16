"""Action storage accessors."""

from __future__ import annotations

import json

from fortipot.models import ActionRecord
from fortipot.storage.db import get_connection


def record_action(db_path: str, action: ActionRecord) -> int:
    """Persist an action record."""

    payload = (
        action.timestamp.isoformat(),
        action.src_ip,
        action.src_mac,
        action.classification.value,
        action.action.value,
        action.mode.value,
        action.status.value,
        action.reason,
        action.score,
        action.confidence,
        json.dumps(action.details),
    )
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO actions (
                timestamp, src_ip, src_mac, classification, action, mode, status,
                reason, score, confidence, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            payload,
        )
        return int(cursor.lastrowid)


def list_actions(db_path: str, limit: int = 100) -> list[dict]:
    """List recent actions."""

    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM actions ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
