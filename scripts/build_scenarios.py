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
from cyberrange.authoring import build_scenario, ConfigError  # noqa: E402

DEFAULT_OUT = pathlib.Path(__file__).resolve().parents[1] / \
    "backend/cyberrange/seed/scenarios.staged.json"


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
                built.append(build_scenario(one, modules_by_id, used_ids,
                                            {s["id"] for s in catalog.scenarios()}))
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
