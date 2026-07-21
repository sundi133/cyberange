"""Control-plane service layer.

Orchestrates the domain: provisioning ranges through the lifecycle state
machine, running exercises, recording a synchronized UTC timeline, capturing
evidence with integrity hashes, computing explainable scores, and writing an
append-only audit ledger. Persistence is delegated to db.Database.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

from . import auth, catalog, detection, execution, lifecycle, rbac, scoring
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
    def __init__(self, db: Database):
        self.db = db
        # Probe once: real container execution when Docker is up, else simulate.
        self._docker_ok = execution.docker_available()
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
        return self.get_range(range_id)

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
        cur = self.db.execute(
            "INSERT INTO events (exercise_id, ts_utc, source, actor, kind, technique_id, "
            "payload, integrity_hash) VALUES (?,?,?,?,?,?,?,?)",
            (exercise_id, ts, source, actor_name or actor, kind, technique_id,
             payload_json, integrity),
        )
        return {"id": cur.lastrowid, "ts_utc": ts, "integrity_hash": integrity}

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
                       module_id: str, inputs: dict | None = None) -> dict:
        rbac.require(role, "module:execute")
        module = catalog.get_module(module_id)
        if not module:
            raise ServiceError(f"Unknown module: {module_id}", 404)
        if not module.get("signed"):
            raise ServiceError(f"Refusing to execute unsigned module: {module_id}", 403)
        if module.get("safety_class") == "PROHIBITED":
            raise ServiceError("Prohibited safety class cannot be executed", 403)
        if module.get("safety_class") == "S2" and not rbac.is_admin(role) \
                and role != "instructor":
            raise ServiceError(
                "S2 modules require administrator or instructor approval", 403
            )
        # Pick a real (Docker) or simulated adapter and run the behavior. The
        # adapter emits telemetry records; each becomes a timeline event.
        adapter = execution.select_adapter(module, docker_ok=self._docker_ok)
        try:
            result = adapter.run(module, inputs or {}, module.get("timeout_seconds", 60))
        except execution.ExecutionError as exc:
            self._audit(actor, role, "module:execute:error", exercise_id,
                        f"{module_id}: {exc}")
            raise ServiceError(f"module execution failed: {exc}", 502)

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
        cur = self.db.execute(
            "INSERT INTO detections (exercise_id, rule_id, rule_version, technique_id, "
            "verdict, basis, severity, latency_s, fp_context, detail, ts_utc) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (exercise_id, rule_id, rule_version, technique_id, verdict, basis, severity,
             latency_s, fp_context, detail, _now()),
        )
        return {"id": cur.lastrowid}

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

    def list_detections(self, exercise_id: str) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM detections WHERE exercise_id=? ORDER BY id", (exercise_id,)
        )
        return [row_to_dict(r) for r in rows]

    # ---- scoring (FR-09) -------------------------------------------------
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

        # Attach detection evidence per technique as scoring evidence refs.
        detections = self.list_detections(exercise_id)
        evidence_refs = {
            "detection": [f"det:{d['id']}:{d['technique_id']}" for d in detections]
        }
        result = scoring.compute_score(
            raw_scores, penalties=pen_objs, overrides=ov_objs, evidence=evidence_refs
        )
        self.db.execute(
            "UPDATE exercises SET score=? WHERE id=?",
            (json.dumps(result.to_dict()), exercise_id),
        )
        if ov_objs:
            self._audit(actor, role, "exercise:score_override", exercise_id,
                        json.dumps([o.__dict__ for o in ov_objs]))
        return result.to_dict()

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
