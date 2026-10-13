#!/usr/bin/env python3
"""Import external ATT&CK test content into the CyberRange catalog.

Converts Atomic Red Team atomics and CALDERA abilities into CyberRange module
JSON. This is how the catalog reaches CALDERA-scale volume: you import a
library rather than author it by hand.

Safety is the whole point of this tool, so read this before running it:

  * Every imported module is written **signed: false**. The service refuses to
    execute any unsigned module, so nothing an import produces can run until a
    human reviews it, assigns a real safety class, and signs it. Importing is
    not the same as trusting.
  * The raw command is recorded faithfully but these are REAL techniques - many
    download tools or change real state. The review step is not a formality.
  * Output goes to a staging file (modules.staged.json), kept separate from the
    curated, signed seed catalog (modules.json). Staged modules show in the
    catalog marked unsigned and cannot be launched.

It also prints a review report flagging the risky commands (downloads,
destructive operations, credential access, persistence) so a reviewer knows
where to look first.

Usage:
    # Atomic Red Team (clone https://github.com/redcanaryco/atomic-red-team)
    python3 scripts/import_atomics.py --format atomic --src path/to/atomics

    # CALDERA abilities (clone https://github.com/mitre/caldera)
    python3 scripts/import_atomics.py --format caldera --src path/to/abilities

    # limit, and write somewhere other than the default staging file
    python3 scripts/import_atomics.py --format atomic --src atomics --limit 200 \
        --out backend/cyberrange/seed/modules.staged.json

Needs PyYAML (pip install pyyaml). The importer is an offline ops tool; the
control plane itself stays standard-library only and only ever reads the JSON
this produces.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

DEFAULT_OUT = pathlib.Path(__file__).resolve().parents[1] / \
    "backend/cyberrange/seed/modules.staged.json"

# Shell executors we can run for real in a Linux container; anything else
# (powershell, command_prompt, manual) is recorded but left to simulate.
_LINUX_EXECUTORS = {"sh", "bash"}

# Risk signals, surfaced in the review report. Not a security control - the
# control is signed: false - but it tells a reviewer which imports to read
# first. Matched case-insensitively against the command text.
_RISK = {
    "download": r"invoke-webrequest|iwr\b|downloadstring|bitsadmin|certutil|\bcurl\b|\bwget\b",
    "destructive": r"remove-item.*-recurse|rm\s+-rf|del\s+/[fsq]|format\s|mkfs|dd\s+if=",
    "credential": r"mimikatz|sekurlsa|lsass|/etc/shadow|hashdump|secretsdump",
    "persistence": r"reg\s+add|schtasks|new-service|crontab|/etc/init\.d|systemctl\s+enable",
    "privilege": r"runas|sudo\s|setuid|uac|token::|getsystem",
}


def _risk_flags(command: str) -> list[str]:
    low = command.lower()
    return sorted(k for k, rx in _RISK.items() if re.search(rx, low))


def _norm_platform(platforms: list[str]) -> str:
    # One platform per module; prefer the first we recognise.
    for p in platforms:
        pl = p.lower()
        if pl in ("windows", "linux"):
            return pl
        if pl in ("macos", "osx", "darwin"):
            return "macos"
    return (platforms[0].lower() if platforms else "unknown")


def _base_technique(tech: str) -> str:
    # T1059.001 -> T1059, so it matches the parent-level tactic/detection tables.
    return tech.split(".")[0].strip().upper()


def _module(*, mod_id, name, technique, platform, executor_name, command,
            cleanup, inputs, elevation, source, extra):
    base_tech = _base_technique(technique)
    runs_real = executor_name in _LINUX_EXECUTORS and platform == "linux"
    flags = _risk_flags(command or "")
    mod = {
        "id": mod_id,
        "name": name[:120],
        "version": "0.1.0",
        "technique_ids": [base_tech],
        "tactic": "imported",
        "platform": platform,
        # Conservative default: anything needing elevation or flagged risky is
        # proposed S2; the reviewer sets the real class. Irrelevant to execution
        # while unsigned, but it is the starting point for review.
        "safety_class": "S2" if (elevation or flags) else "S1",
        "approval": "PENDING REVIEW - imported, not yet classified",
        "inputs": inputs,
        "preconditions": ["Imported content - review before enabling"],
        "timeout_seconds": 120,
        "expected_telemetry": [],
        "cleanup": (cleanup or "").strip()[:500] or "Review and define cleanup.",
        "detection_notes": f"Imported from {source}. Review before relying on detection.",
        # Signed is the hard gate. Imports are never trusted automatically.
        "signed": False,
        "_import": {
            "source": source,
            "attack_technique": technique,
            "executor": executor_name,
            "elevation_required": bool(elevation),
            "risk_flags": flags,
            "suggested_class": "S2" if (elevation or flags) else "S1",
            **extra,
        },
    }
    # A real execution spec only for shell executors on Linux. Everything else
    # is recorded (in _import) but will simulate, so Windows/macOS atomics do
    # not silently look runnable.
    if runs_real and command:
        mod["execution"] = {
            "adapter": "docker",
            "image": "alpine:3.19",
            "network": "none",
            "cmd": ["sh", "-c", command],
        }
    else:
        mod["_import"]["candidate_command"] = command
    return mod


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40]


def import_atomic(src: pathlib.Path, limit: int) -> list[dict]:
    import yaml
    mods, seen = [], set()
    files = sorted(src.rglob("T*.yaml")) + sorted(src.rglob("T*.yml"))
    for path in files:
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as exc:  # noqa: BLE001 - skip a malformed file, note it
            print(f"  ! skipped {path.name}: {exc}", file=sys.stderr)
            continue
        technique = str(doc.get("attack_technique", "")).strip()
        for i, test in enumerate(doc.get("atomic_tests", [])):
            ex = test.get("executor") or {}
            ex_name = str(ex.get("name", "")).lower()
            command = ex.get("command")
            if ex_name == "manual" or not command:
                continue  # nothing to run
            platform = _norm_platform(test.get("supported_platforms", []))
            inputs = {k: (v.get("type", "string"))
                      for k, v in (test.get("input_arguments") or {}).items()}
            guid = test.get("auto_generated_guid", "")
            mod_id = f"CR-ATOMIC-{technique}-{i:02d}".replace(".", "_")
            if mod_id in seen:
                continue
            seen.add(mod_id)
            mods.append(_module(
                mod_id=mod_id, name=test.get("name", mod_id), technique=technique,
                platform=platform, executor_name=ex_name, command=command,
                cleanup=ex.get("cleanup_command"), inputs=inputs,
                elevation=ex.get("elevation_required", False),
                source="atomic-red-team",
                extra={"guid": guid, "supported_platforms": test.get("supported_platforms", [])},
            ))
            if len(mods) >= limit:
                return mods
    return mods


def import_caldera(src: pathlib.Path, limit: int) -> list[dict]:
    import yaml
    mods, seen = [], set()
    for path in sorted(src.rglob("*.yml")) + sorted(src.rglob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            print(f"  ! skipped {path.name}: {exc}", file=sys.stderr)
            continue
        # A CALDERA ability file is a list of one ability dict.
        for ability in (doc if isinstance(doc, list) else [doc]):
            if not isinstance(ability, dict):
                continue
            technique = str(ability.get("technique_id", "")).strip()
            name = ability.get("name", "")
            for ex in ability.get("executors", []):
                command = ex.get("command")
                if not command:
                    continue
                ex_platform = str(ex.get("platform", "")).lower()
                ex_name = str(ex.get("name", "")).lower()
                platform = {"darwin": "macos"}.get(ex_platform, ex_platform) or "unknown"
                # CALDERA's "sh" executor on linux maps to our real tier.
                executor = "sh" if ex_name in ("sh", "bash") else ex_name
                ability_id = ability.get("ability_id", _slug(name))
                mod_id = f"CR-CALDERA-{technique}-{_slug(ability_id)[:12]}".replace(".", "_")
                if mod_id in seen:
                    continue
                seen.add(mod_id)
                mods.append(_module(
                    mod_id=mod_id, name=name or mod_id, technique=technique,
                    platform=platform, executor_name=executor, command=command,
                    cleanup=ex.get("cleanup"), inputs={},
                    elevation="elevated" in str(ability.get("privilege", "")).lower(),
                    source="caldera",
                    extra={"ability_id": ability_id, "tactic": ability.get("tactic", "")},
                ))
                if len(mods) >= limit:
                    return mods
    return mods


def report(mods: list[dict]) -> None:
    from collections import Counter
    plat = Counter(m["platform"] for m in mods)
    real = sum(1 for m in mods if "execution" in m)
    flagged = [m for m in mods if m["_import"]["risk_flags"]]
    flag_counts = Counter(f for m in mods for f in m["_import"]["risk_flags"])
    print(f"\n  Imported {len(mods)} module(s), all signed: false (not runnable until reviewed).")
    print(f"  Platforms:        {dict(plat)}")
    print(f"  Real-capable now: {real} (Linux shell); the rest simulate until the VM tier.")
    print(f"  Risk-flagged:     {len(flagged)} module(s)")
    for flag, n in flag_counts.most_common():
        print(f"      {flag:<12} {n}")
    print("\n  Next: review the flagged modules first, set a real safety_class,")
    print("  and sign the ones you want runnable. Nothing runs while signed: false.\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--format", required=True, choices=["atomic", "caldera"])
    ap.add_argument("--src", required=True, help="directory of atomic/ability files")
    ap.add_argument("--limit", type=int, default=100000)
    ap.add_argument("--out", type=pathlib.Path, default=DEFAULT_OUT)
    ap.add_argument("--merge", action="store_true",
                    help="append to the existing staging file instead of replacing it")
    args = ap.parse_args()

    try:
        import yaml  # noqa: F401
    except ImportError:
        print("This importer needs PyYAML:  pip install pyyaml", file=sys.stderr)
        return 2

    src = pathlib.Path(args.src)
    if not src.exists():
        print(f"Source not found: {src}", file=sys.stderr)
        return 2

    mods = (import_atomic if args.format == "atomic" else import_caldera)(src, args.limit)
    if not mods:
        print("No importable tests found (no shell/command executors with commands).",
              file=sys.stderr)
        return 1

    if args.merge and args.out.exists():
        existing = json.loads(args.out.read_text())
        have = {m["id"] for m in existing}
        mods = existing + [m for m in mods if m["id"] not in have]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(mods, indent=2) + "\n")
    report(mods)
    print(f"  Wrote {len(mods)} module(s) to {args.out}")
    print("  They appear in the catalog marked unsigned; the control plane will")
    print("  refuse to execute them until you sign them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
