"""Generate red/blue drill scenarios from the signed Atomic Red Team pack.

The catalog ships a handful of hand-authored, story-driven scenarios. This
composes additional *technique drills* from the vetted ART modules: for every
ATT&CK technique that has enough signed atomics, it bundles them into one
container-backed scenario - red runs the real variants of that technique, blue
hunts the telemetry. Each scenario is built and validated through the same
authoring path as a hand-written one (modules must exist and be signed), so this
can never compose unsigned content.

The result is written to seed/scenarios.imported.json, which the catalog loads
alongside the curated seed. Regenerate with `python -m cyberrange gen-scenarios`.
"""

from __future__ import annotations

import collections

from . import authoring, catalog

MIN_ATOMICS = 3     # a technique needs at least this many signed atomics
MAX_PER_DRILL = 8   # cap modules per scenario so an exercise stays runnable


def generate_scenarios() -> list[dict]:
    fw = catalog.frameworks().get("techniques", {})
    art = [m for m in catalog.modules()
           if (m.get("_import") or {}).get("source") == "atomic-red-team"
           and m.get("signed")
           and (m.get("execution") or {}).get("adapter") == "docker"]

    by_tech: dict[str, list] = collections.defaultdict(list)
    for m in art:
        tech = (m.get("technique_ids") or [""])[0]
        if tech:
            by_tech[tech].append(m)

    modules_by_id = {m["id"]: m for m in catalog.modules()}
    used: set[str] = set()
    existing = {s["id"] for s in catalog.scenarios()}
    out = []
    for tech in sorted(by_tech):
        mods = by_tech[tech]
        if len(mods) < MIN_ATOMICS:
            continue
        mods = mods[:MAX_PER_DRILL]
        tactic = fw.get(tech, {}).get("tactic")
        label = f"{tactic} — {tech}" if tactic else tech
        difficulty = "advanced" if any(m.get("safety_class") == "S2" for m in mods) \
            else "intermediate"
        cfg = {
            "id": f"CR-DRILL-{tech.replace('.', '_')}",
            "name": f"{label} drill (Linux)",
            "mode": "red-blue",
            "difficulty": difficulty,
            "topology_id": "TOPO-DOCKER",
            "modules": [m["id"] for m in mods],
            "team_objective": (
                f"Red runs {len(mods)} real variants of {tech} on an isolated "
                f"container; blue reconstructs the activity from the telemetry."),
            "objectives": {
                "red": {"text": f"Execute the {tech} techniques and prove access.",
                        "points": 40},
                "blue": {"text": f"Detect and scope the {tech} activity from the logs.",
                         "points": 60},
            },
            "expected_evidence": [
                f"Process/output telemetry from each {tech} module",
                "Automatic detections where a rule matches the real output",
            ],
        }
        out.append(authoring.build_scenario(cfg, modules_by_id, used, existing))
    return out


def summary() -> dict:
    scs = generate_scenarios()
    return {"scenarios": len(scs),
            "modules_used": sum(len(s["module_ids"]) for s in scs)}
