"""Competitions, CTF challenges, scheduling, and leaderboards.

A competition is a scheduled event (start/end window) holding a set of
challenges. Each challenge carries a hidden flag, stored as a salted SHA-256
hash - never in plaintext - and a point value. Participants join a team and
submit flags; a correct, not-yet-solved flag records a solve (with first-blood
tracking) and advances the team on a live leaderboard.

RBAC is enforced here (not only at the route), consistent with the rest of the
service layer: `competition:manage` to create/author, `competition:participate`
to join and submit, `competition:read` to view.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import datetime, timezone

from . import rbac
from .db import row_to_dict
from .service import ServiceError


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None = None) -> str:
    return (dt or _now()).isoformat()


def _norm_flag(flag: str) -> str:
    return (flag or "").strip()


def hash_flag(flag: str, salt: str | None = None) -> tuple[str, str]:
    """Return (hash_hex, salt_hex) for a flag. Salted SHA-256."""
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + _norm_flag(flag)).encode("utf-8")).hexdigest()
    return digest, salt


def verify_flag(flag: str, salt: str, expected_hash: str) -> bool:
    candidate, _ = hash_flag(flag, salt)
    return hmac.compare_digest(candidate, expected_hash)


# Dynamic-scoring defaults (CTFd-style). A challenge opens at its full `points`
# and decays toward `min_points` as teams solve it, reaching the floor at about
# `decay` solves. All solvers share the challenge's current value, so a rarely
# solved (harder) challenge stays worth more for everyone who cracked it.
DEFAULT_DECAY = 20
DEFAULT_MIN_FRACTION = 0.5


def dynamic_value(initial: int, minimum, decay, solves: int) -> int:
    """Current worth of a challenge after `solves` solves (CTFd decay curve)."""
    initial = int(initial)
    minimum = initial if minimum is None else min(int(minimum), initial)
    solves = max(0, int(solves))
    if not decay or int(decay) <= 0 or minimum >= initial or solves == 0:
        return initial
    f = (minimum - initial) / float(int(decay) ** 2)
    v = round(f * (solves ** 2) + initial)
    return int(max(minimum, min(initial, v)))


class Competitions:
    def __init__(self, db, audit, docker_ok=None):
        self.db = db
        self._audit = audit  # callable(actor, role, action, target, detail)
        self.docker_ok = docker_ok

    def _secret(self, row: dict) -> str:
        """Per-competition secret used to derive hands-on proof tokens."""
        meta = row.get("meta") or {}
        if isinstance(meta, dict) and meta.get("lab_secret"):
            return meta["lab_secret"]
        # Stable fallback for rows created before secrets were stored.
        return hashlib.sha256(("lab:" + row["id"]).encode()).hexdigest()[:32]

    @staticmethod
    def _bonus_pct(row: dict) -> int:
        meta = row.get("meta") or {}
        return int(meta.get("first_blood_bonus_pct", 0)) if isinstance(meta, dict) else 0

    # ----------------------------------------------------------- status ----
    @staticmethod
    def _status(row: dict) -> str:
        """Derive the live status from the publish flag and the schedule."""
        if not row.get("published"):
            return "draft"
        now = _iso()
        start, end = row.get("start_at"), row.get("end_at")
        if start and now < start:
            return "scheduled"
        if end and now >= end:
            return "ended"
        return "live"

    def _get_row(self, cid: str) -> dict:
        row = row_to_dict(self.db.query_one(
            "SELECT * FROM competitions WHERE id=?", (cid,)))
        if not row:
            raise ServiceError("Unknown competition", 404)
        return row

    def _solve_counts(self, cid: str) -> dict:
        return {r["challenge_id"]: r["n"] for r in self.db.query(
            "SELECT challenge_id, COUNT(*) AS n FROM competition_solves "
            "WHERE competition_id=? GROUP BY challenge_id", (cid,))}

    @staticmethod
    def _value(chal: dict, scoring: str, solves: int) -> int:
        """Current worth of a challenge: fixed for static, decayed for dynamic."""
        if scoring == "dynamic":
            return dynamic_value(chal["points"], chal.get("min_points"),
                                 chal.get("decay"), solves)
        return int(chal["points"])

    def _team_points(self, cid: str, team_id: str, scoring: str,
                     counts: dict | None = None) -> int:
        counts = self._solve_counts(cid) if counts is None else counts
        chals = {r["id"]: row_to_dict(r) for r in self.db.query(
            "SELECT id, points, min_points, decay FROM competition_challenges "
            "WHERE competition_id=?", (cid,))}
        total = 0
        for r in self.db.query(
                "SELECT challenge_id, bonus FROM competition_solves "
                "WHERE competition_id=? AND team_id=?", (cid, team_id)):
            c = chals.get(r["challenge_id"])
            if c:
                total += self._value(c, scoring, counts.get(r["challenge_id"], 0))
            # First-blood bonus is locked at solve time, on top of the live value.
            total += int(r["bonus"] or 0)
        return total

    # ----------------------------------------------------------- authoring -
    def create(self, actor: str, role: str, *, name: str, description: str = "",
               mode: str = "ctf", scoring: str = "static",
               start_at: str | None = None, end_at: str | None = None,
               published: bool = False, first_blood_bonus_pct: int = 0) -> dict:
        rbac.require(role, "competition:manage")
        if not name or not name.strip():
            raise ServiceError("Competition name is required", 400)
        if mode not in ("ctf", "exercise"):
            raise ServiceError("mode must be 'ctf' or 'exercise'", 400)
        if scoring not in ("static", "dynamic"):
            raise ServiceError("scoring must be 'static' or 'dynamic'", 400)
        if start_at and end_at and end_at <= start_at:
            raise ServiceError("end_at must be after start_at", 400)
        try:
            fb_pct = max(0, min(100, int(first_blood_bonus_pct)))
        except (TypeError, ValueError):
            raise ServiceError("first_blood_bonus_pct must be 0-100", 400)
        cid = "CR-COMP-" + uuid.uuid4().hex[:10]
        meta = json.dumps({"lab_secret": secrets.token_hex(16),
                           "first_blood_bonus_pct": fb_pct})
        self.db.execute(
            "INSERT INTO competitions (id, name, description, mode, scoring, "
            "start_at, end_at, published, created_by, created_at, meta) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (cid, name.strip(), description, mode, scoring, start_at, end_at,
             1 if published else 0, actor, _iso(), meta))
        self._audit(actor, role, "competition:create", cid, name.strip())
        return self.get(cid)

    def update(self, actor: str, role: str, cid: str, **fields) -> dict:
        rbac.require(role, "competition:manage")
        self._get_row(cid)
        allowed = {"name", "description", "start_at", "end_at", "published", "scoring"}
        sets, params = [], []
        for key, val in fields.items():
            if key not in allowed or val is None:
                continue
            if key == "published":
                val = 1 if val else 0
            sets.append(f"{key}=?")
            params.append(val)
        if sets:
            params.append(cid)
            self.db.execute(
                f"UPDATE competitions SET {', '.join(sets)} WHERE id=?", tuple(params))
            self._audit(actor, role, "competition:update", cid, ",".join(sorted(fields)))
        return self.get(cid)

    def add_challenge(self, actor: str, role: str, cid: str, *, title: str,
                      flag: str, category: str = "misc", technique_id: str = "",
                      difficulty: str = "medium", points: int = 100,
                      prompt: str = "", hint: str = "", module_id: str = "",
                      min_points=None, decay=None) -> dict:
        rbac.require(role, "competition:manage")
        comp = self._get_row(cid)
        if not title or not title.strip():
            raise ServiceError("Challenge title is required", 400)
        if not _norm_flag(flag):
            raise ServiceError("A non-empty flag is required", 400)
        try:
            points = int(points)
        except (TypeError, ValueError):
            raise ServiceError("points must be an integer", 400)
        if points <= 0:
            raise ServiceError("points must be positive", 400)
        # Dynamic challenges decay toward a floor; static ones are fixed.
        if comp["scoring"] == "dynamic":
            min_points = (round(points * DEFAULT_MIN_FRACTION)
                          if min_points is None else int(min_points))
            min_points = max(0, min(min_points, points))  # clamp to [0, points]
            decay = DEFAULT_DECAY if decay is None else max(1, int(decay))
        else:
            min_points, decay = points, 0
        digest, salt = hash_flag(flag)
        ch_id = "CR-CHAL-" + uuid.uuid4().hex[:10]
        ordinal = self.db.query_one(
            "SELECT COUNT(*) AS n FROM competition_challenges WHERE competition_id=?",
            (cid,))["n"]
        self.db.execute(
            "INSERT INTO competition_challenges (id, competition_id, title, category, "
            "technique_id, difficulty, points, min_points, decay, prompt, hint, "
            "module_id, flag_hash, flag_salt, ordinal, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ch_id, cid, title.strip(), category, technique_id, difficulty, points,
             min_points, decay, prompt, hint, module_id, digest, salt, ordinal, _iso()))
        self._audit(actor, role, "competition:add_challenge", ch_id,
                    f"{cid} {points}pt {category}")
        return {"id": ch_id, "competition_id": cid, "title": title.strip(),
                "points": points, "category": category}

    def add_challenges_bulk(self, actor: str, role: str, cid: str,
                            challenges: list[dict]) -> int:
        """Add many challenges in one call (used to seed a challenge bank)."""
        rbac.require(role, "competition:manage")
        self._get_row(cid)
        n = 0
        for ch in challenges:
            self.add_challenge(actor, role, cid, **ch)
            n += 1
        return n

    # ------------------------------------------------------------- reading -
    def _challenge_public(self, row: dict, solved_ids: set | None = None,
                          *, value=None, solves=None) -> dict:
        """A challenge as seen by participants - never includes the flag.
        `value` is the current (possibly decayed) worth; `points` the ceiling."""
        out = {
            "id": row["id"], "title": row["title"], "category": row["category"],
            "technique_id": row["technique_id"], "difficulty": row["difficulty"],
            "points": value if value is not None else row["points"],
            "max_points": row["points"], "min_points": row.get("min_points"),
            "decay": row.get("decay"), "solves": solves,
            "prompt": row["prompt"], "hint": row["hint"],
            "module_id": row["module_id"], "ordinal": row["ordinal"],
        }
        if solved_ids is not None:
            out["solved"] = row["id"] in solved_ids
        return out

    def list(self, role: str) -> list[dict]:
        rbac.require(role, "competition:read")
        rows = [row_to_dict(r) for r in self.db.query(
            "SELECT * FROM competitions ORDER BY created_at DESC")]
        out = []
        for row in rows:
            cid = row["id"]
            nchal = self.db.query_one(
                "SELECT COUNT(*) AS n FROM competition_challenges WHERE competition_id=?",
                (cid,))["n"]
            nteam = self.db.query_one(
                "SELECT COUNT(*) AS n FROM competition_teams WHERE competition_id=?",
                (cid,))["n"]
            categories = {r["category"] or "misc": r["n"] for r in self.db.query(
                "SELECT category, COUNT(*) AS n FROM competition_challenges "
                "WHERE competition_id=? GROUP BY category ORDER BY n DESC", (cid,))}
            nhandson = self.db.query_one(
                "SELECT COUNT(*) AS n FROM competition_challenges "
                "WHERE competition_id=? AND module_id IS NOT NULL AND module_id<>''",
                (cid,))["n"]
            out.append({
                "id": cid, "name": row["name"], "description": row["description"],
                "mode": row["mode"], "scoring": row["scoring"],
                "start_at": row["start_at"], "end_at": row["end_at"],
                "status": self._status(row), "published": bool(row["published"]),
                "challenges": nchal, "teams": nteam,
                "categories": categories, "hands_on": nhandson,
            })
        return out

    def get(self, cid: str, actor: str | None = None, role: str | None = None) -> dict:
        if role is not None:
            rbac.require(role, "competition:read")
        row = self._get_row(cid)
        chal_rows = [row_to_dict(r) for r in self.db.query(
            "SELECT * FROM competition_challenges WHERE competition_id=? "
            "ORDER BY ordinal, created_at", (cid,))]
        scoring = row["scoring"]
        counts = self._solve_counts(cid)
        solved_ids = set()
        my_team = None
        if actor:
            my_team = self._team_for(cid, actor)
            if my_team:
                solved_ids = {r["challenge_id"] for r in self.db.query(
                    "SELECT challenge_id FROM competition_solves "
                    "WHERE competition_id=? AND team_id=?", (cid, my_team["id"]))}
        pct = self._bonus_pct(row)
        public = []
        for c in chal_rows:
            n = counts.get(c["id"], 0)
            value = self._value(c, scoring, n)
            entry = self._challenge_public(c, solved_ids, value=value, solves=n)
            if pct > 0:
                entry["blooded"] = n > 0            # first blood already claimed?
                if n == 0:
                    entry["first_blood_bonus"] = round(value * pct / 100)
            public.append(entry)
        return {
            "id": cid, "name": row["name"], "description": row["description"],
            "mode": row["mode"], "scoring": scoring,
            "first_blood_bonus_pct": pct,
            "start_at": row["start_at"], "end_at": row["end_at"],
            "status": self._status(row), "published": bool(row["published"]),
            "total_points": sum(p["points"] for p in public),
            "challenges": public, "my_team": my_team,
        }

    # ------------------------------------------------------------- teams ---
    def _team_for(self, cid: str, username: str) -> dict | None:
        row = self.db.query_one(
            "SELECT t.id, t.name FROM competition_team_members m "
            "JOIN competition_teams t ON t.id = m.team_id "
            "WHERE m.competition_id=? AND m.username=?", (cid, username))
        return row_to_dict(row) if row else None

    def join(self, actor: str, role: str, cid: str, team_name: str) -> dict:
        rbac.require(role, "competition:participate")
        self._get_row(cid)
        if not team_name or not team_name.strip():
            raise ServiceError("Team name is required", 400)
        team_name = team_name.strip()
        existing = self._team_for(cid, actor)
        if existing:
            if existing["name"] == team_name:
                return existing
            raise ServiceError(
                f"You are already on team '{existing['name']}' in this competition", 409)
        team = row_to_dict(self.db.query_one(
            "SELECT id, name FROM competition_teams WHERE competition_id=? AND name=?",
            (cid, team_name)))
        if not team:
            tid = "CR-TEAM-" + uuid.uuid4().hex[:10]
            self.db.execute(
                "INSERT INTO competition_teams (id, competition_id, name, created_by, "
                "created_at) VALUES (?,?,?,?,?)", (tid, cid, team_name, actor, _iso()))
            team = {"id": tid, "name": team_name}
        self.db.execute(
            "INSERT INTO competition_team_members (competition_id, team_id, username, "
            "joined_at) VALUES (?,?,?,?)", (cid, team["id"], actor, _iso()))
        self._audit(actor, role, "competition:join", cid, team_name)
        return team

    def _ensure_team(self, actor: str, role: str, cid: str) -> dict:
        """Return the actor's team, auto-creating a solo team if none."""
        team = self._team_for(cid, actor)
        if team:
            return team
        return self.join(actor, role, cid, actor)

    # ----------------------------------------------------------- submit ----
    def submit_flag(self, actor: str, role: str, cid: str, challenge_id: str,
                    flag: str) -> dict:
        rbac.require(role, "competition:participate")
        row = self._get_row(cid)
        status = self._status(row)
        if status != "live":
            raise ServiceError(
                f"Submissions are closed - competition is {status}", 409)
        chal = row_to_dict(self.db.query_one(
            "SELECT * FROM competition_challenges WHERE id=? AND competition_id=?",
            (challenge_id, cid)))
        if not chal:
            raise ServiceError("Unknown challenge", 404)
        team = self._ensure_team(actor, role, cid)

        correct = verify_flag(flag, chal["flag_salt"], chal["flag_hash"])
        if not correct:
            self._audit(actor, role, "competition:submit_wrong", challenge_id, cid)
            return {"correct": False, "challenge_id": challenge_id}

        already = self.db.query_one(
            "SELECT id FROM competition_solves WHERE competition_id=? AND "
            "challenge_id=? AND team_id=?", (cid, challenge_id, team["id"]))
        if already:
            return {"correct": True, "already_solved": True, "points": 0,
                    "challenge_id": challenge_id}

        prior = self.db.query_one(
            "SELECT COUNT(*) AS n FROM competition_solves WHERE competition_id=? AND "
            "challenge_id=?", (cid, challenge_id))["n"]
        first_blood = prior == 0
        scoring = row["scoring"]
        # Current worth after counting this solve (decays with each solve).
        points = self._value(chal, scoring, prior + 1)
        # First blood earns an extra bonus, locked now on top of the live value.
        pct = self._bonus_pct(row)
        bonus = round(points * pct / 100) if (first_blood and pct > 0) else 0
        self.db.execute(
            "INSERT INTO competition_solves (competition_id, challenge_id, team_id, "
            "username, points_awarded, bonus, first_blood, solved_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (cid, challenge_id, team["id"], actor, points, bonus,
             1 if first_blood else 0, _iso()))
        self._audit(actor, role, "competition:solve", challenge_id,
                    f"{cid} {points}pt{f'+{bonus} blood' if bonus else ''}"
                    f"{' first-blood' if first_blood else ''}")
        team_total = self._team_points(cid, team["id"], scoring)
        return {"correct": True, "points": points, "bonus": bonus,
                "first_blood": first_blood, "team": team["name"],
                "team_total": team_total, "dynamic": scoring == "dynamic",
                "solves": prior + 1, "challenge_id": challenge_id}

    # ----------------------------------------------------- practice arena --
    PRACTICE_NAME = "CyberRange Practice Arena"

    def seed_practice_arena(self, actor: str = "system", role: str = "admin") -> dict:
        """Create (idempotently) a standing, always-open competition populated
        with the generated practice-lab library. Safe to call repeatedly."""
        from . import labs
        existing = self.db.query_one(
            "SELECT id FROM competitions WHERE name=?", (self.PRACTICE_NAME,))
        created = not existing
        if existing:
            cid = existing["id"]
        else:
            comp = self.create(
                actor, role, name=self.PRACTICE_NAME,
                description=("Always-open practice library: labs auto-mapped to the "
                             "ATT&CK catalog, detection rules, and framework crosswalks."),
                mode="ctf", scoring="static",
                start_at="1970-01-01T00:00:00+00:00", end_at=None, published=True)
            cid = comp["id"]
        # Incremental: generate the current library and add only challenges whose
        # title is not already present, so re-running after importing/signing new
        # modules folds the new hands-on labs in without duplicating.
        secret = self._secret(self._get_row(cid))
        generated = labs.generate_labs() + labs.generate_handson_labs(secret)
        have_titles = {r["title"] for r in self.db.query(
            "SELECT title FROM competition_challenges WHERE competition_id=?", (cid,))}
        fresh = [g for g in generated if g["title"] not in have_titles]
        if fresh:
            self.add_challenges_bulk(actor, role, cid, fresh)
        total = self.db.query_one(
            "SELECT COUNT(*) AS n FROM competition_challenges WHERE competition_id=?",
            (cid,))["n"]
        return {"id": cid, "created": created, "added": len(fresh), "challenges": total}

    def run_lab(self, actor: str, role: str, cid: str, challenge_id: str) -> dict:
        """Execute a hands-on lab's backing module on an isolated target and
        return the real output - which ends with the proof token the player then
        submits as the flag. Degrades to a labelled simulated run without Docker."""
        rbac.require(role, "competition:participate")
        row = self._get_row(cid)
        if self._status(row) != "live":
            raise ServiceError(f"Competition is {self._status(row)}, not live", 409)
        chal = row_to_dict(self.db.query_one(
            "SELECT * FROM competition_challenges WHERE id=? AND competition_id=?",
            (challenge_id, cid)))
        if not chal:
            raise ServiceError("Unknown challenge", 404)
        module_id = chal.get("module_id")
        if not module_id:
            raise ServiceError("This challenge is not a hands-on lab", 400)

        from . import catalog, execution, labs
        module = catalog.get_module(module_id)
        if not module:
            raise ServiceError(f"Unknown module: {module_id}", 404)
        if not module.get("signed"):
            raise ServiceError(f"Refusing to run unsigned module: {module_id}", 403)
        spec = module.get("execution") or {}
        if spec.get("adapter") != "docker":
            raise ServiceError("This lab's module is not container-executable", 400)

        token = labs.proof_token(self._secret(row), module_id)
        base_cmd = spec.get("cmd") or ["sh", "-c", ":"]
        inner = base_cmd[-1] if isinstance(base_cmd, list) and base_cmd else ":"
        wrapped = dict(module)
        wrapped_spec = dict(spec)
        wrapped_spec["cmd"] = ["sh", "-c", f'{inner}; echo "{token}"']
        wrapped["execution"] = wrapped_spec

        adapter = execution.select_adapter(wrapped, docker_ok=self.docker_ok)
        try:
            result = adapter.run(wrapped, {}, int(module.get("timeout_seconds", 120)))
        except execution.ExecutionError as exc:
            raise ServiceError(f"Execution failed: {exc}", 500)

        output = [r["payload"]["line"] for r in result.records
                  if r.get("kind") == "process-output" and "line" in r.get("payload", {})]
        note = None
        if not result.real:
            # Simulated: the wrapped echo did not actually run. Surface the token
            # with an honest label rather than leaving the lab unsolvable.
            output = output + [token]
            note = ("Simulated run - no Docker host reachable. On a real execution "
                    "tier the token is emitted by the live container.")
        self._audit(actor, role, "competition:lab_run", challenge_id,
                    f"{cid} {module_id} {'real' if result.real else 'sim'}")
        return {"module_id": module_id, "real": bool(result.real),
                "output": output, "note": note}

    # -------------------------------------------------------- leaderboard --
    def leaderboard(self, cid: str, role: str | None = None) -> dict:
        if role is not None:
            rbac.require(role, "competition:read")
        comp = self._get_row(cid)
        scoring = comp["scoring"]
        counts = self._solve_counts(cid)
        teams = [row_to_dict(r) for r in self.db.query(
            "SELECT id, name FROM competition_teams WHERE competition_id=?", (cid,))]
        board = []
        for team in teams:
            # Score is the sum of each solved challenge's CURRENT value, so a
            # dynamic board re-prices every team as challenges decay.
            points = self._team_points(cid, team["id"], scoring, counts)
            agg = self.db.query_one(
                "SELECT COUNT(*) AS solves, COALESCE(SUM(first_blood),0) AS bloods, "
                "MAX(solved_at) AS last FROM competition_solves "
                "WHERE competition_id=? AND team_id=?", (cid, team["id"]))
            members = [r["username"] for r in self.db.query(
                "SELECT username FROM competition_team_members "
                "WHERE competition_id=? AND team_id=?", (cid, team["id"]))]
            board.append({
                "team": team["name"], "team_id": team["id"],
                "points": int(points), "solves": int(agg["solves"] or 0),
                "bloods": int(agg["bloods"] or 0),
                "last_solve": agg["last"], "members": members,
            })
        # Rank by points desc, then earliest last-solve (faster to the score).
        board.sort(key=lambda r: (-r["points"], r["last_solve"] or "~"))
        for i, entry in enumerate(board, 1):
            entry["rank"] = i
        return {"competition_id": cid, "name": comp["name"],
                "status": self._status(comp), "standings": board}
