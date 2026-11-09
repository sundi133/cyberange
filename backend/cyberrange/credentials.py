"""Skills reports and completion certificates.

Aggregates what a learner has actually demonstrated - guided lessons completed
and CTF/lab challenges solved - into an ATT&CK + framework (NICE / NIST CSF /
CIS / CAE) skills profile, and issues verifiable completion certificates from
that profile. Nothing here is invented: every technique credited traces back to
a lesson the learner finished or a challenge they solved.
"""

from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime, timezone

from . import catalog, rbac
from .db import row_to_dict
from .service import ServiceError


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Credentials:
    CERT_KINDS = ("skills", "cohort")

    def __init__(self, db, audit):
        self.db = db
        self._audit = audit

    # --------------------------------------------------------- skills ------
    def skills(self, actor: str, role: str, username: str | None = None) -> dict:
        """A learner's demonstrated-skills profile. Self, or an instructor /
        admin viewing a learner (needs gradebook:read)."""
        target = username or actor
        if target != actor:
            rbac.require(role, "gradebook:read")
        user = self.db.query_one(
            "SELECT username, display_name FROM users WHERE username=?", (target,))
        if not user:
            raise ServiceError(f"Unknown user: {target}", 404)
        display = user["display_name"] or target

        # Guided lessons completed -> the scenarios' techniques.
        lesson_techs: set[str] = set()
        completed = []
        for r in self.db.query(
                "SELECT DISTINCT scenario_id FROM progress "
                "WHERE username=? AND status='completed'", (target,)):
            sc = catalog.get_scenario(r["scenario_id"])
            if sc:
                completed.append({"id": sc["id"], "name": sc["name"],
                                  "difficulty": sc.get("difficulty")})
                lesson_techs.update(sc.get("technique_ids", []))

        # Challenges solved (practice labs + competitions) -> their techniques.
        solve_techs: set[str] = set()
        points = 0
        by_category: dict[str, int] = {}
        for s in self.db.query(
                "SELECT challenge_id, points_awarded, bonus FROM competition_solves "
                "WHERE username=?", (target,)):
            points += int(s["points_awarded"] or 0) + int(s["bonus"] or 0)
            ch = self.db.query_one(
                "SELECT category, technique_id FROM competition_challenges WHERE id=?",
                (s["challenge_id"],))
            if ch:
                cat = ch["category"] or "misc"
                by_category[cat] = by_category.get(cat, 0) + 1
                if ch["technique_id"]:
                    solve_techs.add(ch["technique_id"])

        techniques = sorted(lesson_techs | solve_techs)
        coverage = catalog.framework_coverage(techniques)
        return {
            "username": target, "display_name": display, "generated_at": _now(),
            "stats": {
                "lessons_completed": len(completed),
                "labs_solved": sum(by_category.values()),
                "techniques_demonstrated": len(techniques),
                "points": points,
                "nice_roles": len(coverage["nice"]),
            },
            "techniques": techniques,
            "scenarios_completed": completed,
            "solves_by_category": by_category,
            "framework_coverage": coverage,
        }

    # ----------------------------------------------------- certificates ----
    def issue(self, actor: str, role: str, *, username: str, kind: str = "skills",
              subject_id: str | None = None, title: str | None = None) -> dict:
        rbac.require(role, "cohort:manage")
        if kind not in self.CERT_KINDS:
            raise ServiceError(f"kind must be one of {self.CERT_KINDS}", 400)
        profile = self.skills(actor, role, username)
        subject_name = None
        if kind == "cohort":
            if not subject_id:
                raise ServiceError("a cohort certificate needs subject_id", 400)
            coh = self.db.query_one("SELECT name FROM cohorts WHERE id=?", (subject_id,))
            if not coh:
                raise ServiceError("unknown cohort", 404)
            subject_name = coh["name"]
        title = title or (f"Certificate of Completion — {subject_name}"
                          if kind == "cohort" else "Cybersecurity Skills Certificate")
        cid = "CR-CERT-" + uuid.uuid4().hex[:10]
        code = secrets.token_hex(6)
        meta = {"stats": profile["stats"], "techniques": profile["techniques"],
                "framework_coverage": profile["framework_coverage"]}
        self.db.execute(
            "INSERT INTO certificates (id, username, display_name, kind, subject_id, "
            "subject_name, title, verify_code, issued_by, issued_at, meta) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (cid, username, profile["display_name"], kind, subject_id, subject_name,
             title, code, actor, _now(), json.dumps(meta)))
        self._audit(actor, role, "certificate:issue", cid, f"{username} {kind}")
        return self.get(cid)

    def get(self, cid: str) -> dict:
        row = row_to_dict(self.db.query_one(
            "SELECT * FROM certificates WHERE id=?", (cid,)))
        if not row:
            raise ServiceError("Unknown certificate", 404)
        return row

    def list(self, actor: str, role: str, username: str | None = None) -> list[dict]:
        target = username or actor
        if target != actor:
            rbac.require(role, "gradebook:read")
        return [row_to_dict(r) for r in self.db.query(
            "SELECT * FROM certificates WHERE username=? ORDER BY issued_at DESC",
            (target,))]

    def verify(self, code: str) -> dict:
        """Public attestation - no auth. Returns only what a verifier needs."""
        row = row_to_dict(self.db.query_one(
            "SELECT * FROM certificates WHERE verify_code=?", (code,)))
        if not row:
            return {"valid": False}
        meta = row.get("meta") or {}
        return {"valid": True, "id": row["id"], "holder": row["display_name"],
                "title": row["title"], "subject": row.get("subject_name"),
                "issued_at": row["issued_at"], "issued_by": row.get("issued_by"),
                "techniques_demonstrated": len((meta.get("techniques") or []))}
