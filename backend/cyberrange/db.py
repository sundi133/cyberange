"""SQLite persistence for the control plane runtime state.

Holds mutable operational entities: ranges, exercise runs, timeline events,
evidence artifacts, detection results, findings, and the audit ledger.
Immutable content (scenarios, modules, topologies) lives in the catalog.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

_DEFAULT_PATH = Path(__file__).parent.parent / "data" / "cyberrange.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS ranges (
    id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    topology_id TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expiry_at TEXT,
    meta TEXT
);

CREATE TABLE IF NOT EXISTS lifecycle_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    range_id TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    action TEXT,
    actor TEXT,
    at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exercises (
    id TEXT PRIMARY KEY,
    range_id TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    started_at TEXT,
    ended_at TEXT,
    status TEXT NOT NULL,
    score TEXT,
    meta TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exercise_id TEXT NOT NULL,
    ts_utc TEXT NOT NULL,
    source TEXT NOT NULL,
    actor TEXT,
    kind TEXT NOT NULL,
    technique_id TEXT,
    payload TEXT,
    integrity_hash TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    exercise_id TEXT NOT NULL,
    submitted_by TEXT,
    role TEXT,
    ts_utc TEXT NOT NULL,
    classification TEXT,
    description TEXT,
    integrity_hash TEXT NOT NULL,
    linked_event INTEGER
);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exercise_id TEXT NOT NULL,
    rule_version TEXT,
    technique_id TEXT,
    verdict TEXT,
    latency_s REAL,
    fp_context TEXT,
    ts_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc TEXT NOT NULL,
    actor TEXT,
    role TEXT,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT
);
"""


class Database:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else _DEFAULT_PATH
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def execute(self, sql: str, params: tuple = ()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params).fetchall())

    def query_one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def close(self):
        self._conn.close()


def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    d = dict(row)
    for k, v in list(d.items()):
        if k in ("meta", "payload", "score") and isinstance(v, str):
            try:
                d[k] = json.loads(v)
            except (json.JSONDecodeError, TypeError):
                pass
    return d
