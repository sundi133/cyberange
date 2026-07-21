"""Control-plane service layer.

Orchestrates the domain: provisioning ranges through the lifecycle state
machine, running exercises, recording a synchronized UTC timeline, capturing
evidence with integrity hashes, computing explainable scores, and writing an
append-only audit ledger. Persistence is delegated to db.Database.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import secrets
import subprocess
import uuid
from datetime import datetime, timedelta, timezone

from . import (auth, catalog, detection, execution, lifecycle, provisioning,
               rbac, scoring, siem)
from .db import Database, row_to_dict

SESSION_TTL_HOURS = 12
MIN_PASSWORD_LEN = 4


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
    return h.hexdigest()


class ServiceError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


class CyberRangeService:
    def __init__(self, db: Database, event_sink: "siem.EventSink | None" = None):
        self.db = db
        # Probe once: real container execution when Docker is up, else simulate.
        self._docker_ok = execution.docker_available()
        # Optional SIEM forwarding (Wazuh). No-op unless WAZUH_INGEST_ENABLED=1.
        self.siem = event_sink or siem.EventSink()
        # Live container ranges: provision real persistent targets per range and
        # run modules inside them. Off unless CR_LIVE_RANGES=1 (and Docker up).
        self._live_ranges = (
            os.environ.get("CR_LIVE_RANGES", "").lower() in ("1", "true", "yes")
            and self._docker_ok)
        self._seed_admin()

    # ---- users & auth (FR-12, spec section 6) ----------------------------
    def _seed_admin(self):
        """Bootstrap a default admin so someone can reach the admin panel."""
        if self.db.query_one("SELECT username FROM users LIMIT 1"):
            return
        password = os.environ.get("CR_ADMIN_PASSWORD", "admin")
        self._insert_user("admin", "Platform Admin", "admin", password,
                          created_by="system")

    def _insert_user(self, username, display_name, role, password, created_by):
        pw_hash, salt = auth.hash_password(password)
        self.db.execute(
            "INSERT INTO users (username, display_name, role, pw_hash, pw_salt, "
            "active, created_at, created_by) VALUES (?,?,?,?,?,1,?,?)",
            (username, display_name or username, role, pw_hash, salt, _now(), created_by),
        )

    def create_user(self, actor: str, actor_role: str, username: str,
                    password: str, role: str, display_name: str | None = None) -> dict:
        rbac.require(actor_role, "admin:manage_users")
        username = (username or "").strip()
        if not username:
            raise ServiceError("username is required", 400)
        if role not in rbac.ROLES:
            raise ServiceError(f"unknown role: {role}", 400)
        if len(password or "") < MIN_PASSWORD_LEN:
            raise ServiceError(
                f"password must be at least {MIN_PASSWORD_LEN} characters", 400)
        if self.db.query_one("SELECT username FROM users WHERE username=?", (username,)):
            raise ServiceError(f"user already exists: {username}", 409)
        self._insert_user(username, display_name, role, password, created_by=actor)
        self._audit(actor, actor_role, "admin:create_user", username, role)
        return self.get_user(username)

    def get_user(self, username: str) -> dict:
        row = self.db.query_one(
            "SELECT username, display_name, role, active, created_at, created_by "
            "FROM users WHERE username=?", (username,))
        if not row:
            raise ServiceError(f"unknown user: {username}", 404)
        d = dict(row)
        d["active"] = bool(d["active"])
        return d

    def list_users(self, actor: str, actor_role: str) -> list[dict]:
        rbac.require(actor_role, "admin:manage_users")
        rows = self.db.query(
            "SELECT username, display_name, role, active, created_at, created_by "
            "FROM users ORDER BY created_at")
        out = []
        for r in rows:
            d = dict(r)
            d["active"] = bool(d["active"])
            out.append(d)
        return out

    def set_user_active(self, actor: str, actor_role: str, username: str,
                        active: bool) -> dict:
        rbac.require(actor_role, "admin:manage_users")
        self.get_user(username)  # validate exists
        if username == actor and not active:
            raise ServiceError("you cannot deactivate your own account", 409)
        self.db.execute("UPDATE users SET active=? WHERE username=?",
                        (1 if active else 0, username))
        if not active:
            # Revoke any live sessions for a deactivated user.
            self.db.execute("DELETE FROM sessions WHERE username=?", (username,))
        self._audit(actor, actor_role, "admin:set_user_active", username, str(active))
        return self.get_user(username)

    def login(self, username: str, password: str) -> dict:
        row = self.db.query_one("SELECT * FROM users WHERE username=?", (username,))
        # Generic error — never reveal whether the username exists.
        if not row or not row["active"] \
                or not auth.verify_password(password, row["pw_salt"], row["pw_hash"]):
            raise ServiceError("invalid credentials", 401)
        token = auth.new_token()
        now = datetime.now(timezone.utc)
        expires = (now + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
        self.db.execute(
            "INSERT INTO sessions (token, username, created_at, expires_at) "
            "VALUES (?,?,?,?)", (token, username, now.isoformat(), expires))
        self._audit(username, row["role"], "auth:login", username, "")
        return {
            "token": token, "username": username, "role": row["role"],
            "display_name": row["display_name"], "expires_at": expires,
            "permissions": sorted(rbac.permissions_for(row["role"])),
        }

    def resolve_token(self, token: str) -> dict | None:
        row = self.db.query_one(
            "SELECT s.token, s.expires_at, u.username, u.role, u.active, u.display_name "
            "FROM sessions s JOIN users u ON u.username = s.username "
            "WHERE s.token=?", (token,))
        if not row or not row["active"]:
            return None
        if row["expires_at"] < _now():
            self.db.execute("DELETE FROM sessions WHERE token=?", (token,))
            return None
        return {"username": row["username"], "role": row["role"],
                "display_name": row["display_name"],
                "permissions": sorted(rbac.permissions_for(row["role"]))}

    def logout(self, token: str) -> dict:
        self.db.execute("DELETE FROM sessions WHERE token=?", (token,))
        return {"ok": True}

    # ---- audit -----------------------------------------------------------
    def _audit(self, actor: str, role: str, action: str, target: str, detail: str = ""):
        self.db.execute(
            "INSERT INTO audit (ts_utc, actor, role, action, target, detail) "
            "VALUES (?,?,?,?,?,?)",
            (_now(), actor, role, action, target, detail),
        )

    def audit_log(self, limit: int = 200) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [row_to_dict(r) for r in rows]

    # ---- ranges ----------------------------------------------------------
    def create_range(self, actor: str, role: str, scenario_id: str,
                     tenant: str = "default", ttl_hours: int = 8) -> dict:
        rbac.require(role, "range:create")
        scenario = catalog.get_scenario(scenario_id)
        if not scenario:
            raise ServiceError(f"Unknown scenario: {scenario_id}", 404)
        topology_id = scenario["topology_id"]
        if not catalog.get_topology(topology_id):
            raise ServiceError(f"Scenario references unknown topology: {topology_id}", 500)

        rid = f"range-{uuid.uuid4().hex[:12]}"
        now = _now()
        expiry = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
        self.db.execute(
            "INSERT INTO ranges (id, tenant, scenario_id, topology_id, state, "
            "created_at, updated_at, expiry_at, meta) VALUES (?,?,?,?,?,?,?,?,?)",
            (rid, tenant, scenario_id, topology_id, lifecycle.INITIAL_STATE,
             now, now, expiry, json.dumps({})),
        )
        self._log_lifecycle(rid, None, lifecycle.INITIAL_STATE, "create", actor)
        self._audit(actor, role, "range:create", rid, scenario_id)
        return self.get_range(rid)

    def get_range(self, range_id: str) -> dict:
        row = self.db.query_one("SELECT * FROM ranges WHERE id=?", (range_id,))
        if not row:
            raise ServiceError(f"Unknown range: {range_id}", 404)
        d = row_to_dict(row)
        d["lifecycle_log"] = [
            row_to_dict(r) for r in self.db.query(
                "SELECT * FROM lifecycle_log WHERE range_id=? ORDER BY id", (range_id,)
            )
        ]
        return d

    def list_ranges(self, tenant: str | None = None) -> list[dict]:
        if tenant:
            rows = self.db.query(
                "SELECT * FROM ranges WHERE tenant=? ORDER BY created_at DESC", (tenant,)
            )
        else:
            rows = self.db.query("SELECT * FROM ranges ORDER BY created_at DESC")
        return [row_to_dict(r) for r in rows]

    def _log_lifecycle(self, range_id, from_state, to_state, action, actor):
        self.db.execute(
            "INSERT INTO lifecycle_log (range_id, from_state, to_state, action, actor, at) "
            "VALUES (?,?,?,?,?,?)",
            (range_id, from_state, to_state, action, actor, _now()),
        )

    def lifecycle_action(self, actor: str, role: str, range_id: str, action: str) -> dict:
        rbac.require(role, "range:lifecycle")
        row = self.db.query_one("SELECT * FROM ranges WHERE id=?", (range_id,))
        if not row:
            raise ServiceError(f"Unknown range: {range_id}", 404)
        src = row["state"]
        try:
            dst = lifecycle.apply_action(src, action, is_admin=rbac.is_admin(role))
        except lifecycle.LifecycleError as exc:
            raise ServiceError(str(exc), 409)
        self.db.execute(
            "UPDATE ranges SET state=?, updated_at=? WHERE id=?", (dst, _now(), range_id)
        )
        self._log_lifecycle(range_id, src, dst, action, actor)
        self._audit(actor, role, f"range:lifecycle:{action}", range_id, f"{src}->{dst}")
        if self._live_ranges:
            self._live_range_action(actor, role, range_id, action)
        return self.get_range(range_id)

    def _live_range_action(self, actor: str, role: str, range_id: str, action: str):
        """Stand up / recycle / tear down real per-range containers."""
        try:
            if action == "provision":
                info = provisioning.provision(range_id)
                self.db.execute("UPDATE ranges SET meta=? WHERE id=?",
                                (json.dumps({"targets": info["targets"],
                                             "network": info["network"]}), range_id))
                self._audit(actor, role, "range:provision", range_id,
                            f"targets: {', '.join(t['hostname'] for t in info['targets'])}")
            elif action == "reset":
                provisioning.reset(range_id)
                self._audit(actor, role, "range:reset", range_id, "targets recycled")
            elif action == "destroy":
                provisioning.teardown(range_id)
        except Exception as exc:  # noqa: BLE001 - provisioning must not corrupt state
            self._audit(actor, role, "range:provision_error", range_id, str(exc))

    # ---- exercises -------------------------------------------------------
    def start_exercise(self, actor: str, role: str, range_id: str) -> dict:
        rbac.require(role, "range:lifecycle")
        rng = self.get_range(range_id)
        if rng["state"] not in ("READY", "RUNNING"):
            # Auto-advance a READY range; otherwise reject.
            if rng["state"] == "READY":
                self.lifecycle_action(actor, role, range_id, "start")
            else:
                raise ServiceError(
                    f"Range must be READY to start an exercise (is {rng['state']})", 409
                )
        else:
            if rng["state"] == "READY":
                self.lifecycle_action(actor, role, range_id, "start")

        exid = f"run-{uuid.uuid4().hex[:12]}"
        self.db.execute(
            "INSERT INTO exercises (id, range_id, scenario_id, started_at, status, meta) "
            "VALUES (?,?,?,?,?,?)",
            (exid, range_id, rng["scenario_id"], _now(), "running", json.dumps({})),
        )
        self._audit(actor, role, "exercise:start", exid, range_id)
        self.record_event(actor, role, exid, source="exercise-engine",
                          kind="exercise-started", actor_name=actor)
        return self.get_exercise(exid)

    def get_exercise(self, exercise_id: str) -> dict:
        row = self.db.query_one("SELECT * FROM exercises WHERE id=?", (exercise_id,))
        if not row:
            raise ServiceError(f"Unknown exercise: {exercise_id}", 404)
        return row_to_dict(row)

    def list_exercises(self, range_id: str | None = None) -> list[dict]:
        if range_id:
            rows = self.db.query(
                "SELECT * FROM exercises WHERE range_id=? ORDER BY started_at DESC",
                (range_id,),
            )
        else:
            rows = self.db.query("SELECT * FROM exercises ORDER BY started_at DESC")
        return [row_to_dict(r) for r in rows]

    # ---- timeline / telemetry (FR-07) ------------------------------------
    def record_event(self, actor: str, role: str, exercise_id: str, *,
                     source: str, kind: str, technique_id: str | None = None,
                     actor_name: str | None = None, payload: dict | None = None) -> dict:
        self.get_exercise(exercise_id)  # validate
        ts = _now()
        payload_json = json.dumps(payload or {})
        integrity = _hash(exercise_id, ts, source, kind, str(technique_id), payload_json)
        new_id = self.db.execute_returning_id(
            "INSERT INTO events (exercise_id, ts_utc, source, actor, kind, technique_id, "
            "payload, integrity_hash) VALUES (?,?,?,?,?,?,?,?)",
            (exercise_id, ts, source, actor_name or actor, kind, technique_id,
             payload_json, integrity),
        )
        # Forward to the SIEM (Wazuh) when enabled — never on the detection path.
        if kind != "detection":
            self.siem.write({
                "id": new_id, "exercise_id": exercise_id, "ts_utc": ts,
                "source": source, "actor": actor_name or actor, "kind": kind,
                "technique_id": technique_id, "payload": payload or {},
                "integrity_hash": integrity,
            })
        return {"id": new_id, "ts_utc": ts, "integrity_hash": integrity}

    def inject(self, actor: str, role: str, exercise_id: str, text: str,
               inject_type: str = "instructor") -> dict:
        rbac.require(role, "exercise:inject")
        ev = self.record_event(actor, role, exercise_id, source="instructor",
                               kind=f"inject:{inject_type}",
                               payload={"text": text})
        self._audit(actor, role, "exercise:inject", exercise_id, text)
        return ev

    def timeline(self, exercise_id: str) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM events WHERE exercise_id=? ORDER BY ts_utc, id", (exercise_id,)
        )
        return [row_to_dict(r) for r in rows]

    # ---- module execution ------------------------------------------------
    def execute_module(self, actor: str, role: str, exercise_id: str,
                       module_id: str, inputs: dict | None = None,
                       in_lesson: bool = False) -> dict:
        rbac.require(role, "module:execute")
        module = catalog.get_module(module_id)
        if not module:
            raise ServiceError(f"Unknown module: {module_id}", 404)
        if not module.get("signed"):
            raise ServiceError(f"Refusing to execute unsigned module: {module_id}", 403)
        if module.get("safety_class") == "PROHIBITED":
            raise ServiceError("Prohibited safety class cannot be executed", 403)
        # S2 is gated to admin/instructor for free-form use, but the platform may
        # run a curated S2 step inside a guided lesson on the learner's behalf.
        if module.get("safety_class") == "S2" and not in_lesson \
                and not rbac.is_admin(role) and role != "instructor":
            raise ServiceError(
                "S2 modules require administrator or instructor approval", 403
            )
        # If the range has live persistent targets, run the behavior INSIDE the
        # victim host (state persists across steps; targets reachable over the
        # range network). Otherwise fall back to a throwaway container or sim.
        spec = module.get("execution") or {}
        range_row = self.db.query_one(
            "SELECT range_id FROM exercises WHERE id=?", (exercise_id,))
        range_id = range_row["range_id"] if range_row else None
        timeout = module.get("timeout_seconds", 60)
        try:
            if (self._live_ranges and range_id and spec.get("adapter") == "docker"
                    and provisioning.is_provisioned(range_id)):
                out, err, rc, dur = provisioning.exec_in_victim(
                    range_id, spec["cmd"], timeout)
                result = execution.build_result(
                    module, out, err, rc, dur, adapter="docker-exec",
                    image=f"victim@{provisioning.net_name(range_id)}")
            else:
                adapter = execution.select_adapter(module, docker_ok=self._docker_ok)
                result = adapter.run(module, inputs or {}, timeout)
        except execution.ExecutionError as exc:
            self._audit(actor, role, "module:execute:error", exercise_id,
                        f"{module_id}: {exc}")
            raise ServiceError(f"module execution failed: {exc}", 502)
        except (OSError, subprocess.SubprocessError) as exc:
            self._audit(actor, role, "module:execute:error", exercise_id,
                        f"{module_id}: {exc}")
            raise ServiceError(f"target execution failed: {exc}", 502)

        for rec in result.records:
            self.record_event(
                actor, role, exercise_id, source=f"module:{module_id}",
                kind=rec["kind"], technique_id=rec.get("technique_id"),
                actor_name=actor, payload=rec["payload"],
            )
        self._audit(actor, role, "module:execute", exercise_id,
                    f"{module_id} ({result.summary.get('adapter')})")
        # Run the detection engine over the freshly captured telemetry so
        # verdicts fire from rules, not a manual form.
        detections = self.run_detections(exercise_id)
        return {
            "executed": module_id,
            "real": result.real,
            "adapter": result.summary.get("adapter"),
            "techniques": module.get("technique_ids", []),
            "events_recorded": len(result.records),
            "detections_fired": len(detections),
            "detections": detections,
            "expected_telemetry": module.get("expected_telemetry", []),
            "summary": result.summary,
        }

    # ---- evidence (FR-05) ------------------------------------------------
    def submit_evidence(self, actor: str, role: str, exercise_id: str, *,
                        description: str, classification: str = "synthetic",
                        linked_event: int | None = None) -> dict:
        rbac.require(role, "exercise:submit_evidence")
        self.get_exercise(exercise_id)
        eid = f"ev-{uuid.uuid4().hex[:12]}"
        ts = _now()
        integrity = _hash(eid, exercise_id, actor, ts, description)
        self.db.execute(
            "INSERT INTO evidence (id, exercise_id, submitted_by, role, ts_utc, "
            "classification, description, integrity_hash, linked_event) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (eid, exercise_id, actor, role, ts, classification, description,
             integrity, linked_event),
        )
        self.record_event(actor, role, exercise_id, source="evidence",
                          kind="evidence-submitted", actor_name=actor,
                          payload={"evidence_id": eid, "description": description})
        return {"id": eid, "integrity_hash": integrity, "ts_utc": ts}

    def list_evidence(self, exercise_id: str) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM evidence WHERE exercise_id=? ORDER BY ts_utc", (exercise_id,)
        )
        return [row_to_dict(r) for r in rows]

    # ---- detections ------------------------------------------------------
    def record_detection(self, actor: str, role: str, exercise_id: str, *,
                         technique_id: str, verdict: str, rule_version: str,
                         latency_s: float = 0.0, fp_context: str = "",
                         rule_id: str | None = None, basis: str = "manual",
                         severity: str = "medium", detail: str = "") -> dict:
        self.get_exercise(exercise_id)
        new_id = self.db.execute_returning_id(
            "INSERT INTO detections (exercise_id, rule_id, rule_version, technique_id, "
            "verdict, basis, severity, latency_s, fp_context, detail, ts_utc) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (exercise_id, rule_id, rule_version, technique_id, verdict, basis, severity,
             latency_s, fp_context, detail, _now()),
        )
        return {"id": new_id}

    def run_detections(self, exercise_id: str) -> list[dict]:
        """Fire the detection-rule engine over the timeline and record any new
        rule matches automatically (FR-08). Idempotent per rule."""
        rules = catalog.detection_rules()
        events = self.timeline(exercise_id)
        existing = {d["rule_id"] for d in self.list_detections(exercise_id)
                    if d.get("rule_id")}
        hits = detection.evaluate(
            rules, events, now=datetime.now(timezone.utc), already_fired=existing)
        recorded = []
        for hit in hits:
            self.record_detection(
                "detection-engine", "admin", exercise_id,
                technique_id=hit["technique_id"], verdict="detected",
                rule_version=hit["rule_version"], latency_s=hit["latency_s"],
                rule_id=hit["rule_id"], basis=hit["basis"],
                severity=hit["severity"], detail=hit["evidence"],
            )
            # Surface the detection on the shared timeline.
            self.record_event(
                "detection-engine", "admin", exercise_id, source="detection-engine",
                kind="detection", technique_id=hit["technique_id"],
                actor_name="detection-engine",
                payload={"real": hit["basis"] == "log", "rule_id": hit["rule_id"],
                         "title": hit["title"], "severity": hit["severity"],
                         "basis": hit["basis"], "latency_s": hit["latency_s"],
                         "evidence": hit["evidence"]},
            )
            recorded.append(hit)
        return recorded

    def ingest_siem_alert(self, actor: str, role: str, *, exercise_id: str,
                          rule_id: str, level: int, description: str,
                          technique_id: str | None = None,
                          full_log: str | None = None) -> dict:
        """Record a REAL detection raised by an external SIEM (Wazuh). Called by
        the alert-forwarder with a Wazuh alert. basis='siem' distinguishes these
        from the built-in engine's log/technique detections."""
        rbac.require(role, "admin:audit")
        self.get_exercise(exercise_id)
        severity = "high" if level >= 10 else ("medium" if level >= 7 else "low")
        self.record_detection(
            actor, role, exercise_id, technique_id=technique_id or "",
            verdict="detected", rule_version=str(rule_id), basis="siem",
            severity=severity, latency_s=0.0, detail=(description or "")[:200])
        self.record_event(
            actor, role, exercise_id, source="wazuh-siem", kind="detection",
            technique_id=technique_id, actor_name="wazuh",
            payload={"real": True, "siem": True, "rule_id": rule_id, "level": level,
                     "title": description, "basis": "siem",
                     "evidence": (full_log or "")[:200]})
        self._audit("wazuh", role, "siem:alert", exercise_id,
                    f"rule {rule_id} L{level}")
        return {"ok": True, "rule_id": rule_id, "severity": severity}

    def list_detections(self, exercise_id: str) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM detections WHERE exercise_id=? ORDER BY id", (exercise_id,)
        )
        return [row_to_dict(r) for r in rows]

    # ---- scoring (FR-09) -------------------------------------------------
    # Dimensions computed automatically from exercise data rather than entered
    # by hand. Others (investigation, response, collaboration) remain rubric
    # inputs; an instructor can still override any dimension (audited).
    DERIVED_DIMENSIONS = ("detection", "red_execution")

    def derived_dimension_scores(self, exercise_id: str) -> dict:
        """Derive the detection and red-execution dimensions from the timeline
        and recorded detections (spec §7: coverage, MTTD, attribution)."""
        ex = self.get_exercise(exercise_id)
        scenario = catalog.get_scenario(ex["scenario_id"]) or {}
        expected = set(scenario.get("technique_ids", []))

        timeline = self.timeline(exercise_id)
        observed = {e["technique_id"] for e in timeline
                    if e.get("technique_id") and e["kind"] in ("ttp-exec", "ttp-emulation")}
        detections = self.list_detections(exercise_id)
        detected = {d["technique_id"] for d in detections if d.get("verdict") == "detected"}
        log_detected = {d["technique_id"] for d in detections
                        if d.get("verdict") == "detected" and d.get("basis") == "log"}
        latencies = [d["latency_s"] for d in detections
                     if d.get("verdict") == "detected" and d.get("latency_s") is not None]

        # Detection: coverage of the expected techniques (weighted 90) plus a
        # fidelity bonus (weighted 10) for detections backed by real log evidence.
        if expected:
            coverage = len(detected & expected) / len(expected)
        else:
            coverage = 1.0 if detected else 0.0
        fidelity = (len(log_detected) / len(detected)) if detected else 0.0
        detection_score = round(min(100.0, coverage * 90 + fidelity * 10), 1)

        # Red execution: did red actually run the expected techniques.
        if expected:
            red = len(observed & expected) / len(expected)
        else:
            red = 1.0 if observed else 0.0
        red_score = round(red * 100, 1)

        mttd = round(sum(latencies) / len(latencies), 3) if latencies else None
        return {
            "detection": detection_score,
            "red_execution": red_score,
            "_detail": {
                "expected": sorted(expected), "observed": sorted(observed),
                "detected": sorted(detected), "log_detected": sorted(log_detected),
                "coverage": round(coverage, 3), "log_fidelity": round(fidelity, 3),
                "mean_mttd_s": mttd,
            },
        }

    def score_exercise(self, actor: str, role: str, exercise_id: str,
                       raw_scores: dict, penalties: list | None = None,
                       overrides: list | None = None) -> dict:
        rbac.require(role, "scoring:read")
        ex = self.get_exercise(exercise_id)

        pen_objs = [scoring.Penalty(**p) for p in (penalties or [])]
        ov_objs = []
        for o in overrides or []:
            rbac.require(role, "exercise:score_override")
            ov_objs.append(scoring.Override(**o))

        # Derived dimensions take precedence over any submitted slider values.
        derived = self.derived_dimension_scores(exercise_id)
        detail = derived.pop("_detail")
        effective = dict(raw_scores)
        effective.update(derived)

        detections = self.list_detections(exercise_id)
        evidence_refs = {
            "detection": [f"det:{d['id']}:{d['rule_id'] or d['technique_id']}"
                          for d in detections]
        }
        result = scoring.compute_score(
            effective, penalties=pen_objs, overrides=ov_objs, evidence=evidence_refs
        )
        payload = result.to_dict()
        payload["derived"] = {"dimensions": list(self.DERIVED_DIMENSIONS), **detail}
        self.db.execute(
            "UPDATE exercises SET score=? WHERE id=?",
            (json.dumps(payload), exercise_id),
        )
        if ov_objs:
            self._audit(actor, role, "exercise:score_override", exercise_id,
                        json.dumps([o.__dict__ for o in ov_objs]))
        return payload

    def end_exercise(self, actor: str, role: str, exercise_id: str) -> dict:
        rbac.require(role, "range:lifecycle")
        ex = self.get_exercise(exercise_id)
        self.record_event(actor, role, exercise_id, source="exercise-engine",
                          kind="exercise-ended", actor_name=actor)
        self.db.execute(
            "UPDATE exercises SET ended_at=?, status=? WHERE id=?",
            (_now(), "completed", exercise_id),
        )
        # Move the range through completion + evidence lock.
        rid = ex["range_id"]
        rng = self.get_range(rid)
        if rng["state"] in ("RUNNING", "PAUSED"):
            self.lifecycle_action(actor, role, rid, "complete")
            self.lifecycle_action(actor, role, rid, "lock_evidence")
        self._audit(actor, role, "exercise:end", exercise_id, rid)
        return self.get_exercise(exercise_id)

    # ---- reporting (FR-11) ----------------------------------------------
    def build_report(self, exercise_id: str) -> dict:
        ex = self.get_exercise(exercise_id)
        scenario = catalog.get_scenario(ex["scenario_id"]) or {}
        timeline = self.timeline(exercise_id)
        evidence = self.list_evidence(exercise_id)
        detections = self.list_detections(exercise_id)

        techniques_seen = sorted({
            e["technique_id"] for e in timeline if e.get("technique_id")
        })
        detected = sorted({
            d["technique_id"] for d in detections if d.get("verdict") == "detected"
        })
        gaps = [t for t in scenario.get("technique_ids", []) if t not in detected]

        return {
            "exercise_id": exercise_id,
            "scenario": {
                "id": scenario.get("id"),
                "name": scenario.get("name"),
                "mode": scenario.get("mode"),
                "objectives": scenario.get("objectives", []),
            },
            "status": ex["status"],
            "started_at": ex.get("started_at"),
            "ended_at": ex.get("ended_at"),
            "score": ex.get("score"),
            "coverage": {
                "expected": scenario.get("technique_ids", []),
                "observed": techniques_seen,
                "detected": detected,
                "gaps": gaps,
            },
            "timeline_events": len(timeline),
            "evidence_count": len(evidence),
            "evidence": evidence,
            "detections": detections,
            "recommendations": self._recommendations(gaps),
        }

    @staticmethod
    def _recommendations(gaps: list[str]) -> list[str]:
        if not gaps:
            return ["Coverage complete for scenario techniques; consider raising difficulty."]
        recs = [f"Add or tune detection content for {t}." for t in gaps]
        recs.append("Run a Purple detection sprint to validate the new content via replay.")
        return recs

    # ---- purple replay (FR-10) ------------------------------------------
    def purple_compare(self, baseline: dict, replay: dict) -> dict:
        return scoring.purple_delta(baseline, replay)

    # ===================================================================
    #  Learning platform: cohorts, rosters, assignments, lessons, grades
    # ===================================================================

    # ---- cohorts (classes) ----------------------------------------------
    def create_cohort(self, actor: str, role: str, name: str) -> dict:
        rbac.require(role, "cohort:manage")
        if not (name or "").strip():
            raise ServiceError("class name is required", 400)
        cid = f"class-{uuid.uuid4().hex[:10]}"
        self.db.execute(
            "INSERT INTO cohorts (id, name, owner, created_at) VALUES (?,?,?,?)",
            (cid, name.strip(), actor, _now()))
        self._audit(actor, role, "cohort:create", cid, name)
        return self.get_cohort(cid)

    def get_cohort(self, cohort_id: str) -> dict:
        row = self.db.query_one("SELECT * FROM cohorts WHERE id=?", (cohort_id,))
        if not row:
            raise ServiceError(f"unknown class: {cohort_id}", 404)
        d = row_to_dict(row)
        d["members"] = [row_to_dict(r) for r in self.db.query(
            "SELECT cm.username, cm.added_at, u.display_name, u.role, u.active "
            "FROM cohort_members cm JOIN users u ON u.username = cm.username "
            "WHERE cm.cohort_id=? ORDER BY cm.username", (cohort_id,))]
        d["assignments"] = self.list_assignments(cohort_id)
        return d

    def list_cohorts(self, actor: str, role: str) -> list[dict]:
        rbac.require(role, "cohort:manage")
        if rbac.is_admin(role):
            rows = self.db.query("SELECT * FROM cohorts ORDER BY created_at DESC")
        else:
            rows = self.db.query(
                "SELECT * FROM cohorts WHERE owner=? ORDER BY created_at DESC", (actor,))
        out = []
        for r in rows:
            d = row_to_dict(r)
            d["member_count"] = self.db.query_one(
                "SELECT COUNT(*) c FROM cohort_members WHERE cohort_id=?", (r["id"],))["c"]
            d["assignment_count"] = self.db.query_one(
                "SELECT COUNT(*) c FROM assignments WHERE cohort_id=?", (r["id"],))["c"]
            out.append(d)
        return out

    def add_member(self, actor: str, role: str, cohort_id: str, username: str) -> dict:
        rbac.require(role, "cohort:manage")
        self.get_cohort(cohort_id)
        self.get_user(username)  # validate exists
        self.db.execute(
            "INSERT OR IGNORE INTO cohort_members (cohort_id, username, added_at) "
            "VALUES (?,?,?)", (cohort_id, username, _now()))
        self._audit(actor, role, "cohort:add_member", cohort_id, username)
        return {"ok": True}

    def remove_member(self, actor: str, role: str, cohort_id: str, username: str) -> dict:
        rbac.require(role, "cohort:manage")
        self.db.execute("DELETE FROM cohort_members WHERE cohort_id=? AND username=?",
                        (cohort_id, username))
        self._audit(actor, role, "cohort:remove_member", cohort_id, username)
        return {"ok": True}

    def import_roster(self, actor: str, role: str, cohort_id: str, csv_text: str) -> dict:
        """Bulk-enroll students from CSV: username[,display_name[,password]].
        Creates missing accounts as 'solo' (student) and returns any generated
        passwords so the instructor can distribute them."""
        rbac.require(role, "cohort:manage")
        self.get_cohort(cohort_id)
        created, added, errors, credentials = 0, 0, [], []
        reader = csv.reader(io.StringIO(csv_text))
        for lineno, row in enumerate(reader, 1):
            if not row or not row[0].strip():
                continue
            username = row[0].strip()
            if username.lower() in ("username", "user", "email"):
                continue  # header row
            display = row[1].strip() if len(row) > 1 and row[1].strip() else username
            password = row[2].strip() if len(row) > 2 and row[2].strip() else ""
            existing = self.db.query_one("SELECT username FROM users WHERE username=?", (username,))
            if not existing:
                if not password:
                    password = "cr-" + secrets.token_hex(3)
                    credentials.append({"username": username, "password": password})
                try:
                    self._insert_user(username, display, "solo", password, created_by=actor)
                    created += 1
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"line {lineno} ({username}): {exc}")
                    continue
            self.db.execute(
                "INSERT OR IGNORE INTO cohort_members (cohort_id, username, added_at) "
                "VALUES (?,?,?)", (cohort_id, username, _now()))
            added += 1
        self._audit(actor, role, "cohort:import_roster", cohort_id,
                    f"created={created} enrolled={added}")
        return {"created": created, "enrolled": added, "errors": errors,
                "credentials": credentials}

    # ---- assignments -----------------------------------------------------
    def create_assignment(self, actor: str, role: str, cohort_id: str,
                          scenario_id: str, title: str | None = None,
                          due_at: str | None = None) -> dict:
        rbac.require(role, "assignment:manage")
        self.get_cohort(cohort_id)
        scenario = catalog.get_scenario(scenario_id)
        if not scenario:
            raise ServiceError(f"unknown scenario: {scenario_id}", 404)
        aid = f"asn-{uuid.uuid4().hex[:10]}"
        self.db.execute(
            "INSERT INTO assignments (id, cohort_id, scenario_id, title, due_at, "
            "assigned_by, created_at) VALUES (?,?,?,?,?,?,?)",
            (aid, cohort_id, scenario_id, title or scenario["name"], due_at, actor, _now()))
        self._audit(actor, role, "assignment:create", aid, f"{cohort_id}/{scenario_id}")
        return row_to_dict(self.db.query_one("SELECT * FROM assignments WHERE id=?", (aid,)))

    def list_assignments(self, cohort_id: str) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM assignments WHERE cohort_id=? ORDER BY created_at", (cohort_id,))
        return [row_to_dict(r) for r in rows]

    def my_assignments(self, actor: str, role: str) -> list[dict]:
        rbac.require(role, "learn:participate")
        rows = self.db.query(
            "SELECT a.* FROM assignments a JOIN cohort_members cm "
            "ON cm.cohort_id = a.cohort_id WHERE cm.username=? ORDER BY a.created_at DESC",
            (actor,))
        out = []
        for r in rows:
            a = row_to_dict(r)
            scenario = catalog.get_scenario(a["scenario_id"]) or {}
            a["scenario_name"] = scenario.get("name")
            a["difficulty"] = scenario.get("difficulty")
            learning = scenario.get("learning") or {}
            a["step_count"] = len(learning.get("steps", []))
            a["quiz_count"] = len(learning.get("quiz", []))
            prog = self._get_progress(actor, a["id"], a["scenario_id"])
            a["progress"] = self._progress_view(prog, scenario)
            out.append(a)
        return out

    # ---- lessons & progress ---------------------------------------------
    def _get_progress(self, username: str, assignment_id: str, scenario_id: str):
        return self.db.query_one(
            "SELECT * FROM progress WHERE username=? AND assignment_id=? AND scenario_id=?",
            (username, assignment_id, scenario_id))

    def _progress_view(self, prog, scenario) -> dict:
        learning = (scenario or {}).get("learning") or {}
        total_steps = len(learning.get("steps", []))
        if not prog:
            return {"status": "not_started", "steps_done": [], "total_steps": total_steps,
                    "quiz_score": None, "quiz_total": len(learning.get("quiz", [])),
                    "score": None}
        p = row_to_dict(prog)
        steps_done = p.get("steps_done") or []
        pct = None
        if p.get("quiz_total"):
            pct = round(100.0 * (p.get("quiz_score") or 0) / p["quiz_total"], 1)
        return {"status": p["status"], "steps_done": steps_done, "total_steps": total_steps,
                "quiz_score": p.get("quiz_score"), "quiz_total": p.get("quiz_total"),
                "score": pct, "exercise_id": p.get("exercise_id")}

    def _upsert_progress(self, username, assignment_id, scenario_id, **fields):
        prog = self._get_progress(username, assignment_id, scenario_id)
        if not prog:
            self.db.execute(
                "INSERT INTO progress (username, assignment_id, scenario_id, status, "
                "steps_done, updated_at) VALUES (?,?,?,?,?,?)",
                (username, assignment_id, scenario_id, fields.get("status", "in_progress"),
                 json.dumps(fields.get("steps_done", [])), _now()))
            prog = self._get_progress(username, assignment_id, scenario_id)
        sets, vals = [], []
        for k, v in fields.items():
            sets.append(f"{k}=?")
            vals.append(json.dumps(v) if k == "steps_done" else v)
        sets.append("updated_at=?"); vals.append(_now())
        vals.append(prog["id"])
        self.db.execute(f"UPDATE progress SET {', '.join(sets)} WHERE id=?", tuple(vals))
        return self._get_progress(username, assignment_id, scenario_id)

    def start_lesson(self, actor: str, role: str, scenario_id: str,
                     assignment_id: str = "self") -> dict:
        rbac.require(role, "learn:participate")
        scenario = catalog.get_scenario(scenario_id)
        if not scenario or "learning" not in scenario:
            raise ServiceError(f"no lesson for scenario {scenario_id}", 404)
        prog = self._get_progress(actor, assignment_id, scenario_id)
        exercise_id = row_to_dict(prog).get("exercise_id") if prog else None
        # Auto-provision a private range + exercise for this learner if needed.
        if not exercise_id or not self.db.query_one(
                "SELECT id FROM exercises WHERE id=?", (exercise_id,)):
            rng = self.create_range(actor, "instructor", scenario_id, tenant=f"learn:{actor}")
            for a in ("preflight", "provision", "seed", "ready"):
                self.lifecycle_action(actor, "instructor", rng["id"], a)
            ex = self.start_exercise(actor, "instructor", rng["id"])
            exercise_id = ex["id"]
        prog = self._upsert_progress(actor, assignment_id, scenario_id,
                                     status="in_progress", exercise_id=exercise_id)
        return {"exercise_id": exercise_id,
                "lesson": scenario["learning"],
                "scenario": {"id": scenario["id"], "name": scenario["name"],
                             "difficulty": scenario.get("difficulty"),
                             "technique_ids": scenario.get("technique_ids", [])},
                "progress": self._progress_view(prog, scenario)}

    def run_lesson_step(self, actor: str, role: str, scenario_id: str, step_index: int,
                        assignment_id: str = "self") -> dict:
        rbac.require(role, "learn:participate")
        scenario = catalog.get_scenario(scenario_id)
        learning = (scenario or {}).get("learning") or {}
        steps = learning.get("steps", [])
        if step_index < 0 or step_index >= len(steps):
            raise ServiceError("invalid step", 400)
        prog = self._get_progress(actor, assignment_id, scenario_id)
        if not prog or not row_to_dict(prog).get("exercise_id"):
            raise ServiceError("start the lesson first", 409)
        exercise_id = row_to_dict(prog)["exercise_id"]
        step = steps[step_index]
        result = None
        if step.get("module_id"):
            # Platform runs the curated step (may be S2) on the learner's behalf.
            result = self.execute_module(actor, role, exercise_id, step["module_id"],
                                         in_lesson=True)
        done = set(row_to_dict(prog).get("steps_done") or [])
        done.add(step_index)
        prog = self._upsert_progress(actor, assignment_id, scenario_id,
                                     steps_done=sorted(done))
        return {"step_index": step_index, "execution": result,
                "progress": self._progress_view(prog, scenario)}

    def submit_quiz(self, actor: str, role: str, scenario_id: str, answers: list,
                    assignment_id: str = "self") -> dict:
        rbac.require(role, "learn:participate")
        scenario = catalog.get_scenario(scenario_id)
        quiz = ((scenario or {}).get("learning") or {}).get("quiz", [])
        if not quiz:
            raise ServiceError("no quiz for this lesson", 404)
        results, correct = [], 0
        for i, question in enumerate(quiz):
            chosen = answers[i] if i < len(answers) else None
            is_correct = chosen == question["answer"]
            if is_correct:
                correct += 1
            results.append({
                "index": i, "chosen": chosen, "correct": is_correct,
                "correct_answer": question["answer"], "explain": question.get("explain", "")})
        prog = self._get_progress(actor, assignment_id, scenario_id) or \
            self._upsert_progress(actor, assignment_id, scenario_id, status="in_progress")
        steps_done = row_to_dict(prog).get("steps_done") or []
        total_steps = len(((scenario or {}).get("learning") or {}).get("steps", []))
        status = "completed" if len(steps_done) >= total_steps else "in_progress"
        prog = self._upsert_progress(actor, assignment_id, scenario_id,
                                     quiz_score=correct, quiz_total=len(quiz), status=status)
        self._audit(actor, role, "lesson:quiz", scenario_id,
                    f"{correct}/{len(quiz)}")
        return {"score": correct, "total": len(quiz),
                "pct": round(100.0 * correct / len(quiz), 1),
                "results": results, "status": status,
                "progress": self._progress_view(prog, scenario)}

    # ---- gradebook -------------------------------------------------------
    def gradebook(self, actor: str, role: str, cohort_id: str) -> dict:
        rbac.require(role, "gradebook:read")
        cohort = self.get_cohort(cohort_id)
        assignments = cohort["assignments"]
        rows = []
        for member in cohort["members"]:
            cells = {}
            for a in assignments:
                scenario = catalog.get_scenario(a["scenario_id"]) or {}
                prog = self._get_progress(member["username"], a["id"], a["scenario_id"])
                cells[a["id"]] = self._progress_view(prog, scenario)
            completed = sum(1 for c in cells.values() if c["status"] == "completed")
            scored = [c["score"] for c in cells.values() if c["score"] is not None]
            rows.append({
                "username": member["username"],
                "display_name": member.get("display_name"),
                "cells": cells,
                "completed": completed,
                "avg_score": round(sum(scored) / len(scored), 1) if scored else None,
            })
        return {"cohort": {"id": cohort["id"], "name": cohort["name"]},
                "assignments": assignments, "rows": rows}
