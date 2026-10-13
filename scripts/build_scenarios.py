#!/usr/bin/env python3
"""Build CyberRange scenarios from compact TTP configs.

A scenario is a curated selection of modules plus a story - objectives, mode,
difficulty. Authoring one by hand means a lot of JSON; this turns a short config
into a full, validated scenario, so a catalog can grow from a handful to a
hundred by writing configs rather than scenario JSON. It is also the format a
customer uses to author their own.

A config is YAML or JSON. The minimum is a name, a mode, and the modules the
scenario runs:

    name: Linux web-to-root
    mode: red-blue            # red-blue | solo | purple
    difficulty: intermediate  # introductory | intermediate | advanced
    modules:
      - CR-MOD-RECON-001
      - CR-MOD-WEBAPP-001
      - CR-MOD-PRIVESC-LNX-001

Everything else is optional and defaulted: id (generated from the name),
technique_ids (the union of the modules'), topology, safety class (the highest
of the modules'), duration, and per-role objectives. Provide any of them to
override:

    id: CR-CUSTOM-WEB-001
    duration_min: [60, 90]
    objectives:
      red:  {text: "Reach root on the web host.", points: 40}
      blue: {text: "Detect the web exploit and the privesc.", points: 60}

Validation is the safety boundary: every referenced module must exist AND be
signed. A scenario cannot be built on unsigned/imported modules, so a customer
authoring scenarios can only compose content a reviewer already trusted.

Usage:
    python3 scripts/build_scenarios.py path/to/config.yaml
    python3 scripts/build_scenarios.py path/to/configs/           # a directory
    python3 scripts/build_scenarios.py configs/ --merge           # add to existing

Output goes to backend/cyberrange/seed/scenarios.staged.json, which the catalog
loads alongside the curated seed. YAML configs need PyYAML (see docs/IMPORTING.md
for the venv); JSON configs need nothing.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "backend"))
from cyberrange import catalog  # noqa: E402

DEFAULT_OUT = pathlib.Path(__file__).resolve().parents[1] / \
    "backend/cyberrange/seed/scenarios.staged.json"

MODES = {"red-blue", "solo", "purple"}
DIFFICULTIES = {"introductory", "intermediate", "advanced"}
_SAFETY_ORDER = ["S0", "S1", "S2"]

# Default objectives per mode, used when a config does not supply its own.
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


def _load_config(path: pathlib.Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise ConfigError(
                f"{path.name} is YAML, which needs PyYAML. Either convert it to "
                f".json or install PyYAML in a venv (see docs/IMPORTING.md).")
        return yaml.safe_load(text) or {}
    return json.loads(text)


def build_one(cfg: dict, modules_by_id: dict[str, dict], used_ids: set[str]) -> dict:
    name = (cfg.get("name") or "").strip()
    if not name:
        raise ConfigError("every scenario needs a 'name'")

    mode = cfg.get("mode", "red-blue")
    if mode not in MODES:
        raise ConfigError(f"{name!r}: mode must be one of {sorted(MODES)}, got {mode!r}")

    difficulty = cfg.get("difficulty", "intermediate")
    if difficulty not in DIFFICULTIES:
        raise ConfigError(f"{name!r}: difficulty must be one of {sorted(DIFFICULTIES)}")

    module_ids = cfg.get("modules") or []
    if not module_ids:
        raise ConfigError(f"{name!r}: a scenario needs at least one module")

    # The safety boundary: every module must exist and be signed. A scenario
    # built on unsigned/imported content would be a way around module review.
    unknown = [m for m in module_ids if m not in modules_by_id]
    if unknown:
        raise ConfigError(f"{name!r}: unknown module id(s): {unknown}")
    unsigned = [m for m in module_ids if modules_by_id[m].get("signed") is False]
    if unsigned:
        raise ConfigError(
            f"{name!r}: these modules are unsigned and must be reviewed and signed "
            f"before a scenario can use them: {unsigned}")

    mods = [modules_by_id[m] for m in module_ids]

    # Derive technique_ids (union, order-preserving) unless overridden.
    techniques = cfg.get("technique_ids")
    if not techniques:
        seen, techniques = set(), []
        for m in mods:
            for t in m.get("technique_ids", []):
                if t not in seen:
                    seen.add(t)
                    techniques.append(t)

    # Topology: a Docker scenario if any module is docker, else the standard range.
    topology = cfg.get("topology_id") or (
        "TOPO-DOCKER" if any(m.get("platform") == "docker" for m in mods) else "TOPO-STD5")

    # Safety class: the highest (most restrictive) of the modules'.
    safety = cfg.get("safety_class") or max(
        (m.get("safety_class", "S0") for m in mods),
        key=lambda s: _SAFETY_ORDER.index(s) if s in _SAFETY_ORDER else 0)

    # Objectives: author-supplied, or a sensible default for the mode.
    if cfg.get("objectives"):
        obj_cfg = cfg["objectives"]
        if isinstance(obj_cfg, dict):  # {red: {...}, blue: {...}}
            objectives = [{"role": r, **v} for r, v in obj_cfg.items()]
        else:
            objectives = obj_cfg
    else:
        objectives = _DEFAULT_OBJECTIVES[mode]

    sid = cfg.get("id") or f"CR-CUSTOM-{_slug(name)}"
    if sid in used_ids or sid in {s["id"] for s in catalog.scenarios()}:
        # keep ids unique against both this batch and the existing catalog
        n = 2
        while f"{sid}-{n}" in used_ids:
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
        "team_objective": cfg.get("team_objective",
                                  f"Authored scenario: {name}."),
        "technique_ids": techniques,
        "module_ids": module_ids,
        "objectives": objectives,
        "injects": cfg.get("injects", []),
        "expected_evidence": cfg.get("expected_evidence", []),
        "safety_class": safety,
        # Marks this as authored rather than seed content, for the catalog badge.
        "custom": True,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src", help="a config file or a directory of them")
    ap.add_argument("--out", type=pathlib.Path, default=DEFAULT_OUT)
    ap.add_argument("--merge", action="store_true",
                    help="add to the existing staged scenarios instead of replacing")
    args = ap.parse_args()

    src = pathlib.Path(args.src)
    if src.is_dir():
        files = sorted(p for p in src.iterdir()
                       if p.suffix.lower() in (".yaml", ".yml", ".json"))
    elif src.exists():
        files = [src]
    else:
        print(f"Not found: {src}", file=sys.stderr)
        return 2
    if not files:
        print(f"No .yaml/.yml/.json configs in {src}", file=sys.stderr)
        return 1

    modules_by_id = {m["id"]: m for m in catalog.modules()}
    used_ids: set[str] = set()
    built, errors = [], []
    for path in files:
        try:
            cfg = _load_config(path)
            for one in (cfg if isinstance(cfg, list) else [cfg]):
                built.append(build_one(one, modules_by_id, used_ids))
        except (ConfigError, json.JSONDecodeError) as exc:
            errors.append(f"  {path.name}: {exc}")

    if errors:
        print("Some configs were rejected:\n" + "\n".join(errors), file=sys.stderr)
    if not built:
        print("No scenarios built.", file=sys.stderr)
        return 1

    if args.merge and args.out.exists():
        existing = json.loads(args.out.read_text())
        have = {s["id"] for s in existing}
        built = existing + [s for s in built if s["id"] not in have]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(built, indent=2) + "\n")

    from collections import Counter
    modes = Counter(s["mode"] for s in built)
    print(f"\n  Built {len(built)} scenario(s): {dict(modes)}")
    print(f"  Total catalog scenarios after restart: "
          f"{len(catalog._load('scenarios')) + len(built)}")
    if errors:
        print(f"  {len(errors)} config(s) rejected (above).")
    print(f"  Wrote {args.out}")
    print("  They appear in the catalog on the next server start, marked custom.")
    print("  Each runs signed modules only, so no separate review is needed.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
