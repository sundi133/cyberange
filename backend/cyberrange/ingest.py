"""In-product import of external ATT&CK content (Atomic Red Team / CALDERA).

This is the package-embedded counterpart to scripts/import_atomics.py. The pure
conversion functions take already-parsed dicts and are standard-library only, so
they are unit-tested without PyYAML. The directory importers (import_atomic_dir
/ import_caldera_dir) parse YAML lazily and are used by the
`python -m cyberrange import-atomics` CLI.

Safety contract (identical to the ops script): every imported module is written
`signed: false`. The service refuses to execute unsigned modules, so nothing an
import produces can run until a human reviews, classifies, and signs it. Only
Linux shell executors get a real execution spec; everything else is recorded and
left to simulate.
"""

from __future__ import annotations

import re

_LINUX_EXECUTORS = {"sh", "bash"}

_RISK = {
    "download": r"invoke-webrequest|iwr\b|downloadstring|bitsadmin|certutil|\bcurl\b|\bwget\b",
    "destructive": r"remove-item.*-recurse|rm\s+-rf|del\s+/[fsq]|format\s|mkfs|dd\s+if=",
    "credential": r"mimikatz|sekurlsa|lsass|/etc/shadow|hashdump|secretsdump",
    "persistence": r"reg\s+add|schtasks|new-service|crontab|/etc/init\.d|systemctl\s+enable",
    "privilege": r"runas|sudo\s|setuid|uac|token::|getsystem",
}


def risk_flags(command: str) -> list[str]:
    low = (command or "").lower()
    return sorted(k for k, rx in _RISK.items() if re.search(rx, low))


def base_technique(tech: str) -> str:
    """T1059.004 -> T1059, to match the parent-level tactic/detection tables."""
    return (tech or "").split(".")[0].strip().upper()


def norm_platform(platforms) -> str:
    for p in platforms or []:
        pl = str(p).lower()
        if pl in ("windows", "linux"):
            return pl
        if pl in ("macos", "osx", "darwin"):
            return "macos"
    return (str(platforms[0]).lower() if platforms else "unknown")


def make_module(*, mod_id, name, technique, platform, executor_name, command,
                cleanup, inputs, elevation, source, extra) -> dict:
    tech = base_technique(technique)
    runs_real = executor_name in _LINUX_EXECUTORS and platform == "linux"
    flags = risk_flags(command or "")
    mod = {
        "id": mod_id,
        "name": (name or mod_id)[:120],
        "version": "0.1.0",
        "technique_ids": [tech] if tech else [],
        "tactic": "imported",
        "platform": platform,
        "safety_class": "S2" if (elevation or flags) else "S1",
        "approval": "PENDING REVIEW - imported, not yet classified",
        "inputs": inputs or {},
        "preconditions": ["Imported content - review before enabling"],
        "timeout_seconds": 120,
        "expected_telemetry": [],
        "cleanup": (cleanup or "").strip()[:500] or "Review and define cleanup.",
        "detection_notes": f"Imported from {source}. Review before relying on detection.",
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


def atomic_doc_to_modules(doc: dict) -> list[dict]:
    """Convert one parsed Atomic Red Team YAML doc into CyberRange modules."""
    technique = str(doc.get("attack_technique", "")).strip()
    out, seen = [], set()
    for i, test in enumerate(doc.get("atomic_tests", []) or []):
        ex = test.get("executor") or {}
        ex_name = str(ex.get("name", "")).lower()
        command = ex.get("command")
        if ex_name == "manual" or not command:
            continue
        platform = norm_platform(test.get("supported_platforms", []))
        inputs = {k: (v.get("type", "string") if isinstance(v, dict) else "string")
                  for k, v in (test.get("input_arguments") or {}).items()}
        mod_id = f"CR-ATOMIC-{technique}-{i:02d}".replace(".", "_")
        if mod_id in seen:
            continue
        seen.add(mod_id)
        out.append(make_module(
            mod_id=mod_id, name=test.get("name", mod_id), technique=technique,
            platform=platform, executor_name=ex_name, command=command,
            cleanup=ex.get("cleanup_command"), inputs=inputs,
            elevation=ex.get("elevation_required", False), source="atomic-red-team",
            extra={"guid": test.get("auto_generated_guid", ""),
                   "supported_platforms": test.get("supported_platforms", [])}))
    return out


def caldera_doc_to_modules(doc) -> list[dict]:
    """Convert one parsed CALDERA ability doc (list of one ability) to modules."""
    out, seen = [], set()
    for ability in (doc if isinstance(doc, list) else [doc]):
        if not isinstance(ability, dict):
            continue
        technique = str(ability.get("technique_id", "")).strip()
        name = ability.get("name", "")
        for ex in ability.get("executors", []) or []:
            command = ex.get("command")
            if not command:
                continue
            platform = norm_platform([ex.get("platform", "")])
            ex_name = str(ex.get("name", ex.get("executor", ""))).lower()
            mod_id = f"CR-CALDERA-{technique}-{len(out):02d}".replace(".", "_")
            if mod_id in seen:
                continue
            seen.add(mod_id)
            out.append(make_module(
                mod_id=mod_id, name=name, technique=technique, platform=platform,
                executor_name=ex_name, command=command,
                cleanup=ex.get("cleanup"), inputs={},
                elevation=False, source="caldera",
                extra={"ability_id": ability.get("ability_id", "")}))
    return out


def import_atomic_dir(src, limit: int = 1000) -> list[dict]:
    """Walk an Atomic Red Team checkout and convert its atomics (needs PyYAML)."""
    import pathlib
    import yaml
    src = pathlib.Path(src)
    mods = []
    files = sorted(src.rglob("T*.yaml")) + sorted(src.rglob("T*.yml"))
    for path in files:
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        for mod in atomic_doc_to_modules(doc):
            mods.append(mod)
            if len(mods) >= limit:
                return mods
    return mods


def import_summary(modules: list[dict]) -> dict:
    """Review report: counts by platform, real-capable, and risk flags."""
    by_platform: dict[str, int] = {}
    real = flagged = 0
    for m in modules:
        by_platform[m["platform"]] = by_platform.get(m["platform"], 0) + 1
        if m.get("execution"):
            real += 1
        if m.get("_import", {}).get("risk_flags"):
            flagged += 1
    return {"total": len(modules), "by_platform": by_platform,
            "real_capable": real, "risk_flagged": flagged}
