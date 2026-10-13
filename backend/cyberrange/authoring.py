"""Scenario authoring: turn a compact config into a full, validated scenario.

Shared by the offline builder (scripts/build_scenarios.py) and the in-product
authoring API (POST /api/scenarios), so both compose and validate identically.

The validation here is the safety boundary for authored content: a scenario may
only reference modules that exist and are signed, so authoring - whether from a
config file or the UI - can never compose unsigned or imported content.
"""

from __future__ import annotations

import re

MODES = {"red-blue", "solo", "purple"}
DIFFICULTIES = {"introductory", "intermediate", "advanced"}
_SAFETY_ORDER = ["S0", "S1", "S2"]

_DEFAULT_OBJECTIVES = {
    "red-blue": [
        {"role": "red", "text": "Complete the attack path and prove access.", "points": 40},
        {"role": "blue", "text": "Detect the activity, scope it, and preserve evidence.", "points": 60},
    ],
    "solo": [
        {"role": "solo", "text": "Run the attack and identify what it left behind.", "points": 100},
    ],
    "purple": [
        {"role": "purple", "text": "Replay the techniques and improve detection coverage.", "points": 100},
    ],
}


class ConfigError(ValueError):
    """A config is missing something or references content that is not usable."""


def _slug(text: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "-", text.upper()).strip("-")[:28]


def build_scenario(cfg: dict, modules_by_id: dict[str, dict],
                   used_ids: set[str], existing_ids: set[str] | None = None) -> dict:
    """Compose and validate one scenario. Raises ConfigError on bad input."""
    existing_ids = existing_ids or set()

    name = (cfg.get("name") or "").strip()
    if not name:
        raise ConfigError("every scenario needs a 'name'")

    mode = cfg.get("mode", "red-blue")
    if mode not in MODES:
        raise ConfigError(f"{name!r}: mode must be one of {sorted(MODES)}, got {mode!r}")

    difficulty = cfg.get("difficulty", "intermediate")
    if difficulty not in DIFFICULTIES:
        raise ConfigError(f"{name!r}: difficulty must be one of {sorted(DIFFICULTIES)}")

    module_ids = cfg.get("modules") or cfg.get("module_ids") or []
    if not module_ids:
        raise ConfigError(f"{name!r}: a scenario needs at least one module")

    unknown = [m for m in module_ids if m not in modules_by_id]
    if unknown:
        raise ConfigError(f"{name!r}: unknown module id(s): {unknown}")
    unsigned = [m for m in module_ids if modules_by_id[m].get("signed") is False]
    if unsigned:
        raise ConfigError(
            f"{name!r}: these modules are unsigned and must be reviewed and signed "
            f"before a scenario can use them: {unsigned}")

    mods = [modules_by_id[m] for m in module_ids]

    techniques = cfg.get("technique_ids")
    if not techniques:
        seen, techniques = set(), []
        for m in mods:
            for t in m.get("technique_ids", []):
                if t not in seen:
                    seen.add(t)
                    techniques.append(t)

    topology = cfg.get("topology_id") or (
        "TOPO-DOCKER" if any(m.get("platform") == "docker" for m in mods) else "TOPO-STD5")

    safety = cfg.get("safety_class") or max(
        (m.get("safety_class", "S0") for m in mods),
        key=lambda s: _SAFETY_ORDER.index(s) if s in _SAFETY_ORDER else 0)

    if cfg.get("objectives"):
        obj_cfg = cfg["objectives"]
        objectives = ([{"role": r, **v} for r, v in obj_cfg.items()]
                      if isinstance(obj_cfg, dict) else obj_cfg)
    else:
        objectives = _DEFAULT_OBJECTIVES[mode]

    sid = cfg.get("id") or f"CR-CUSTOM-{_slug(name)}"
    if sid in used_ids or sid in existing_ids:
        n = 2
        while f"{sid}-{n}" in used_ids or f"{sid}-{n}" in existing_ids:
            n += 1
        sid = f"{sid}-{n}"
    used_ids.add(sid)

    return {
        "id": sid,
        "name": name,
        "version": cfg.get("version", "0.1.0"),
        "mode": mode,
        "difficulty": difficulty,
        "duration_min": cfg.get("duration_min", [60, 90]),
        "topology_id": topology,
        "team_objective": cfg.get("team_objective", f"Authored scenario: {name}."),
        "technique_ids": techniques,
        "module_ids": list(module_ids),
        "objectives": objectives,
        "injects": cfg.get("injects", []),
        "expected_evidence": cfg.get("expected_evidence", []),
        "safety_class": safety,
        "custom": True,
    }
