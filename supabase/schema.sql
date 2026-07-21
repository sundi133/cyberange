-- CyberRange schema for PostgreSQL / Supabase.
-- The app auto-creates these tables on boot (CREATE TABLE IF NOT EXISTS),
-- so running this by hand is OPTIONAL. Provided for review, RLS setup, or
-- provisioning the database ahead of first deploy.
--
-- Apply via the Supabase SQL editor, or: psql "$DATABASE_URL" -f supabase/schema.sql

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
    id BIGSERIAL PRIMARY KEY,
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
    id BIGSERIAL PRIMARY KEY,
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
    id BIGSERIAL PRIMARY KEY,
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
    id BIGSERIAL PRIMARY KEY,
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
    id BIGSERIAL PRIMARY KEY,
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
