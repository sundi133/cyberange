"""Content catalog loader (FR-01).

Loads immutable seed content (tactics, TTP modules, scenarios, topologies,
reference tables) from JSON and offers search/filter over it.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path

SEED_DIR = Path(__file__).parent / "seed"


@functools.lru_cache(maxsize=None)
def _load(name: str):
    with open(SEED_DIR / f"{name}.json", encoding="utf-8") as fh:
        return json.load(fh)


def tactics() -> list[dict]:
    return _load("tactics")


def modules() -> list[dict]:
    return _load("modules")


def scenarios() -> list[dict]:
    return _load("scenarios")


def topologies() -> list[dict]:
    return _load("topologies")


def reference() -> dict:
    return _load("reference")


def get_scenario(scenario_id: str) -> dict | None:
    return next((s for s in scenarios() if s["id"] == scenario_id), None)


def get_module(module_id: str) -> dict | None:
    return next((m for m in modules() if m["id"] == module_id), None)


def get_topology(topology_id: str) -> dict | None:
    return next((t for t in topologies() if t["id"] == topology_id), None)


def search_scenarios(
    *,
    role: str | None = None,
    tactic: str | None = None,
    difficulty: str | None = None,
    technique: str | None = None,
    platform: str | None = None,
    query: str | None = None,
) -> list[dict]:
    """FR-01: search/filter the scenario catalog."""
    results = scenarios()
    if difficulty:
        results = [s for s in results if s.get("difficulty") == difficulty]
    if technique:
        results = [s for s in results if technique in s.get("technique_ids", [])]
    if role:
        results = [
            s for s in results
            if any(o.get("role") == role for o in s.get("objectives", []))
            or role in s.get("mode", "")
        ]
    if platform:
        results = [
            s for s in results
            if any(
                (get_module(mid) or {}).get("platform") == platform
                for mid in s.get("module_ids", [])
            )
        ]
    if tactic:
        tactic_l = tactic.lower()
        tech_for_tactic = {
            t["attack"] for t in tactics() if tactic_l in t["tactic"].lower()
        }
        # attack fields may be compound like "T1087/T1018"
        flat = set()
        for a in tech_for_tactic:
            flat.update(a.split("/"))
        results = [
            s for s in results
            if flat & set(s.get("technique_ids", []))
        ]
    if query:
        q = query.lower()
        results = [
            s for s in results
            if q in s["name"].lower() or q in s.get("team_objective", "").lower()
        ]
    return results


def search_modules(
    *,
    platform: str | None = None,
    safety_class: str | None = None,
    technique: str | None = None,
    tactic: str | None = None,
) -> list[dict]:
    results = modules()
    if platform:
        results = [m for m in results if m.get("platform") == platform]
    if safety_class:
        results = [m for m in results if m.get("safety_class") == safety_class]
    if technique:
        results = [m for m in results if technique in m.get("technique_ids", [])]
    if tactic:
        results = [m for m in results if m.get("tactic", "").lower() == tactic.lower()]
    return results
