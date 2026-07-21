"""Scoring engine (spec section 7, FR-09).

Default team score = weighted objective points - safety/policy penalties.
Every scoring input is explainable: the breakdown lists each dimension,
its raw score, weight, and contribution, plus penalties and overrides.

Purple-team improvement is reported as baseline-to-replay change, never as
a winner/loser score (see purple_delta).
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Default dimension weights (must sum to 1.0). Mirrors seed/reference.json.
DEFAULT_WEIGHTS = {
    "red_execution": 0.25,
    "detection": 0.25,
    "investigation": 0.20,
    "response": 0.20,
    "collaboration": 0.10,
}


@dataclass
class DimensionScore:
    dimension: str
    raw: float          # 0-100 quality score for the dimension
    weight: float
    evidence_refs: list[str] = field(default_factory=list)

    @property
    def contribution(self) -> float:
        return round(self.raw * self.weight, 2)


@dataclass
class Penalty:
    reason: str
    points: float       # positive number subtracted from the total
    evidence_ref: str | None = None


@dataclass
class Override:
    dimension: str
    old_raw: float
    new_raw: float
    instructor: str
    justification: str


@dataclass
class ScoreResult:
    dimensions: list[DimensionScore]
    penalties: list[Penalty]
    overrides: list[Override]
    total: float
    weighted_before_penalty: float

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "weighted_before_penalty": self.weighted_before_penalty,
            "dimensions": [
                {
                    "dimension": d.dimension,
                    "raw": d.raw,
                    "weight": d.weight,
                    "contribution": d.contribution,
                    "evidence_refs": d.evidence_refs,
                }
                for d in self.dimensions
            ],
            "penalties": [
                {"reason": p.reason, "points": p.points, "evidence_ref": p.evidence_ref}
                for p in self.penalties
            ],
            "overrides": [
                {
                    "dimension": o.dimension,
                    "old_raw": o.old_raw,
                    "new_raw": o.new_raw,
                    "instructor": o.instructor,
                    "justification": o.justification,
                }
                for o in self.overrides
            ],
        }


def compute_score(
    raw_scores: dict[str, float],
    *,
    weights: dict[str, float] | None = None,
    penalties: list[Penalty] | None = None,
    overrides: list[Override] | None = None,
    evidence: dict[str, list[str]] | None = None,
) -> ScoreResult:
    """Compute an explainable weighted score.

    raw_scores: dimension -> 0..100 quality score.
    Overrides are applied on top of raw_scores (last override wins per dim).
    """
    weights = weights or DEFAULT_WEIGHTS
    penalties = penalties or []
    overrides = overrides or []
    evidence = evidence or {}

    effective = dict(raw_scores)
    for ov in overrides:
        effective[ov.dimension] = ov.new_raw

    dims: list[DimensionScore] = []
    for dim, weight in weights.items():
        raw = float(effective.get(dim, 0.0))
        raw = max(0.0, min(100.0, raw))
        dims.append(DimensionScore(dim, raw, weight, evidence.get(dim, [])))

    weighted = round(sum(d.contribution for d in dims), 2)
    penalty_total = round(sum(p.points for p in penalties), 2)
    total = round(max(0.0, weighted - penalty_total), 2)

    return ScoreResult(
        dimensions=dims,
        penalties=penalties,
        overrides=overrides,
        total=total,
        weighted_before_penalty=weighted,
    )


def objective_completion(objectives: list[dict], completed_ids: set) -> dict:
    """Roll objective points into completion ratios per role."""
    by_role: dict[str, dict] = {}
    for idx, obj in enumerate(objectives):
        role = obj.get("role", "team")
        oid = obj.get("id", idx)
        pts = float(obj.get("points", 0))
        bucket = by_role.setdefault(role, {"earned": 0.0, "possible": 0.0})
        bucket["possible"] += pts
        if oid in completed_ids or str(oid) in completed_ids:
            bucket["earned"] += pts
    for bucket in by_role.values():
        possible = bucket["possible"] or 1.0
        bucket["ratio"] = round(bucket["earned"] / possible, 3)
    return by_role


def purple_delta(baseline: dict[str, float], replay: dict[str, float]) -> dict:
    """Baseline-to-replay coverage change; not a win/lose score."""
    keys = set(baseline) | set(replay)
    per_technique = {}
    for k in sorted(keys):
        b = float(baseline.get(k, 0.0))
        r = float(replay.get(k, 0.0))
        per_technique[k] = {"baseline": b, "replay": r, "delta": round(r - b, 3)}
    b_avg = round(sum(baseline.values()) / len(baseline), 3) if baseline else 0.0
    r_avg = round(sum(replay.values()) / len(replay), 3) if replay else 0.0
    return {
        "per_technique": per_technique,
        "baseline_coverage": b_avg,
        "replay_coverage": r_avg,
        "improvement": round(r_avg - b_avg, 3),
    }
