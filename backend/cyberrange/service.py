"""Control-plane service layer.

Orchestrates the domain: provisioning ranges through the lifecycle state
machine, running exercises, recording a synchronized UTC timeline, capturing
evidence with integrity hashes, computing explainable scores, and writing an
append-only audit ledger. Persistence is delegated to db.Database.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

from . import catalog, lifecycle, rbac, scoring
from .db import Database, row_to_dict


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
        # Emulate the module producing its declared telemetry on the timeline.
        for tech in module.get("technique_ids", []):
            self.record_event(
                actor, role, exercise_id, source=f"module:{module_id}",
                kind="ttp-emulation", technique_id=tech,
                actor_name=actor,
                payload={"module": module_id, "safety_class": module["safety_class"],
                         "inputs": inputs or {}},
            )
        self._audit(actor, role, "module:execute", exercise_id, module_id)
        return {"executed": module_id, "techniques": module.get("technique_ids", []),
                "expected_telemetry": module.get("expected_telemetry", [])}

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
                         latency_s: float = 0.0, fp_context: str = "") -> dict:
        self.get_exercise(exercise_id)
        cur = self.db.execute(
            "INSERT INTO detections (exercise_id, rule_version, technique_id, verdict, "
            "latency_s, fp_context, ts_utc) VALUES (?,?,?,?,?,?,?)",
            (exercise_id, rule_version, technique_id, verdict, latency_s, fp_context, _now()),
        )
        return {"id": cur.lastrowid}

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
