"""Event storage accessors."""

from __future__ import annotations

import json

from fortipot.models import DetectionDecision
from fortipot.storage.db import get_connection


def record_event(db_path: str, decision: DetectionDecision) -> int:
    """Persist a detection decision."""

    payload = (
        decision.timestamp.isoformat(),
        decision.src_ip,
        decision.src_mac,
        decision.classification.value,
        decision.score,
        decision.confidence,
        json.dumps(decision.matched_behaviors),
        decision.recommended_action.value,
        decision.reason,
        json.dumps(decision.observed_destinations),
        json.dumps(decision.observed_ports),
    )
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO events (
                timestamp, src_ip, src_mac, classification, score, confidence,
                matched_behaviors, recommended_action, reason,
                observed_destinations, observed_ports
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            payload,
        )
        return int(cursor.lastrowid)


def list_events(db_path: str, limit: int = 100) -> list[dict]:
    """List recent events."""

    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
