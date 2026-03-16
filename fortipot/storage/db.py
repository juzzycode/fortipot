"""SQLite database helpers."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_mac TEXT,
    classification TEXT NOT NULL,
    score INTEGER NOT NULL,
    confidence REAL NOT NULL,
    matched_behaviors TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    reason TEXT NOT NULL,
    observed_destinations TEXT NOT NULL,
    observed_ports TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_mac TEXT,
    classification TEXT NOT NULL,
    action TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    score INTEGER NOT NULL,
    confidence REAL NOT NULL,
    details TEXT NOT NULL
);
"""


def initialize_database(path: str) -> None:
    """Initialize the SQLite schema if needed."""

    db_path = Path(path)
    if db_path.parent:
        db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA)


@contextmanager
def get_connection(path: str) -> Iterator[sqlite3.Connection]:
    """Yield a SQLite connection with row factory enabled."""

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
