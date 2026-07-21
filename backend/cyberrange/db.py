"""Persistence for the control-plane runtime state.

Two interchangeable backends behind one interface:

- SQLite (default) — zero dependencies, great for local dev and tests.
- PostgreSQL / Supabase — used automatically when DATABASE_URL (or
  SUPABASE_DB_URL) points at a postgres:// DSN. Requires `psycopg`.

Holds mutable operational entities: ranges, exercises, timeline events,
evidence, detections, audit ledger, users/sessions, and the learning tables
(cohorts, assignments, progress). Immutable content lives in the catalog.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path

_DEFAULT_PATH = Path(__file__).parent.parent / "data" / "cyberrange.db"

# {AUTOPK} is substituted per backend: SQLite uses an AUTOINCREMENT integer,
# Postgres uses BIGSERIAL. Everything else is portable SQL.
_SCHEMA = """
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
    id {AUTOPK},
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
    id {AUTOPK},
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
    id {AUTOPK},
    exercise_id TEXT NOT NULL,
    rule_id TEXT,
    rule_version TEXT,
    technique_id TEXT,
    verdict TEXT,
    basis TEXT,
    severity TEXT,
    latency_s REAL,
    fp_context TEXT,
    detail TEXT,
    ts_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id {AUTOPK},
    ts_utc TEXT NOT NULL,
    actor TEXT,
    role TEXT,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    display_name TEXT,
    role TEXT NOT NULL,
    pw_hash TEXT NOT NULL,
    pw_salt TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    created_by TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cohorts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cohort_members (
    cohort_id TEXT NOT NULL,
    username TEXT NOT NULL,
    added_at TEXT NOT NULL,
    PRIMARY KEY (cohort_id, username)
);

CREATE TABLE IF NOT EXISTS assignments (
    id TEXT PRIMARY KEY,
    cohort_id TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    title TEXT,
    due_at TEXT,
    assigned_by TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS progress (
    id {AUTOPK},
    username TEXT NOT NULL,
    assignment_id TEXT,
    scenario_id TEXT NOT NULL,
    exercise_id TEXT,
    steps_done TEXT,
    quiz_score REAL,
    quiz_total INTEGER,
    status TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (username, assignment_id, scenario_id)
);
"""

_JSON_COLUMNS = ("meta", "payload", "score", "steps_done")


def _schema_for(dialect: str) -> str:
    autopk = ("INTEGER PRIMARY KEY AUTOINCREMENT" if dialect == "sqlite"
              else "BIGSERIAL PRIMARY KEY")
    return _SCHEMA.replace("{AUTOPK}", autopk)


def is_postgres_dsn(dsn) -> bool:
    return isinstance(dsn, str) and dsn.startswith(("postgres://", "postgresql://"))


# ---------------------------------------------------------------- SQLite ----
class Database:
    """SQLite backend (default)."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else _DEFAULT_PATH
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self._conn.executescript(_schema_for("sqlite"))
            self._conn.commit()

    def execute(self, sql: str, params: tuple = ()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def execute_returning_id(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur.lastrowid

    def query(self, sql: str, params: tuple = ()) -> list:
        with self._lock:
            return list(self._conn.execute(sql, params).fetchall())

    def query_one(self, sql: str, params: tuple = ()):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def close(self):
        self._conn.close()


# -------------------------------------------------------------- Postgres ----
def _to_pg(sql: str) -> str:
    """Translate the app's SQLite-flavored SQL to PostgreSQL."""
    ignore = "INSERT OR IGNORE" in sql
    sql = sql.replace("INSERT OR IGNORE INTO", "INSERT INTO")
    sql = sql.replace("?", "%s")
    if ignore and "ON CONFLICT" not in sql:
        sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
    return sql


class PostgresDatabase:
    """PostgreSQL / Supabase backend. Selected when DATABASE_URL is a DSN."""

    def __init__(self, dsn: str):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:  # pragma: no cover - env dependent
            raise RuntimeError(
                "DATABASE_URL points at Postgres but `psycopg` is not installed. "
                "Run: pip install 'psycopg[binary]'") from exc
        self._psycopg = psycopg
        self._dict_row = dict_row
        self.dsn = dsn
        self._lock = threading.Lock()
        self._connect()
        self._init_schema()

    def _connect(self):
        self._conn = self._psycopg.connect(
            self.dsn, autocommit=True, row_factory=self._dict_row)

    def _run(self, sql: str, params: tuple):
        """Execute with a one-shot reconnect if the connection dropped."""
        try:
            return self._conn.execute(sql, params)
        except self._psycopg.OperationalError:
            self._connect()
            return self._conn.execute(sql, params)

    def _init_schema(self):
        with self._lock:
            for stmt in _schema_for("postgres").split(";"):
                if stmt.strip():
                    self._run(stmt, ())

    def execute(self, sql: str, params: tuple = ()):
        with self._lock:
            return self._run(_to_pg(sql), params)

    def execute_returning_id(self, sql: str, params: tuple = ()) -> int:
        q = _to_pg(sql)
        if "returning" not in q.lower():
            q = q.rstrip().rstrip(";") + " RETURNING id"
        with self._lock:
            cur = self._run(q, params)
            row = cur.fetchone()
            return row["id"] if row else None

    def query(self, sql: str, params: tuple = ()) -> list:
        with self._lock:
            return self._run(_to_pg(sql), params).fetchall()

    def query_one(self, sql: str, params: tuple = ()):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def close(self):
        self._conn.close()


# ---------------------------------------------------------------- factory ----
def connect(dsn: str | Path | None = None):
    """Return the right backend. Postgres if `dsn` (or DATABASE_URL /
    SUPABASE_DB_URL) is a postgres:// DSN; otherwise SQLite."""
    if dsn is None:
        dsn = os.environ.get("DATABASE_URL") or os.environ.get("SUPABASE_DB_URL")
    if is_postgres_dsn(dsn):
        return PostgresDatabase(dsn)
    return Database(dsn)


def row_to_dict(row) -> dict | None:
    if row is None:
        return None
    d = dict(row)
    for k, v in list(d.items()):
        if k in _JSON_COLUMNS and isinstance(v, str):
            try:
                d[k] = json.loads(v)
            except (json.JSONDecodeError, TypeError):
                pass
    return d
