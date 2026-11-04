"""Practice-lab generator.

Builds a large library of self-contained, gradeable CTF-style labs directly
from the shipping catalog - behavior modules, detection rules, and the ATT&CK
framework crosswalk - so every lab is grounded in real platform content and has
a deterministic, verifiable answer (no hand-written filler). The output feeds
the competition engine as a standing "Practice Arena".

Lab families:
  A. SOC triage      - an alert fired; name the ATT&CK technique       (blue)
  B. Adversary map   - a module emulates X; name its technique         (red)
  C. Framework map   - a technique belongs to which ATT&CK tactic      (defense)
  D. IOC hunt        - a literal indicator a detection rule matches     (forensics)
"""

from __future__ import annotations

import re

from . import catalog

_SEV_POINTS = {"critical": 300, "high": 250, "medium": 150, "low": 100}
_SAFETY_POINTS = {"S0": 100, "S1": 150, "S2": 250}
_SEV_DIFFICULTY = {"critical": "hard", "high": "hard", "medium": "medium", "low": "easy"}

# A clean literal is something a player could realistically type back: word
# chars plus a few shell/path symbols, no regex metacharacters.
_CLEAN_LITERAL = re.compile(r"^[\w=()/.:\-]+$")


def _literal_from_regex(line_regex: str) -> str | None:
    """Extract one typeable literal alternative from a detection's line_regex."""
    if not line_regex:
        return None
    for alt in line_regex.split("|"):
        token = alt.replace("\\.", ".").replace("\\", "").strip()
        if len(token) >= 4 and _CLEAN_LITERAL.match(token) and not token.isdigit():
            return token
    return None


def generate_labs() -> list[dict]:
    """Return a list of challenge dicts ready for Competitions.add_challenge."""
    labs: list[dict] = []
    seen_titles: set[str] = set()

    def add(title, flag, *, category, points, difficulty, technique_id="",
            prompt="", hint=""):
        if not title or not flag or title in seen_titles:
            return
        seen_titles.add(title)
        labs.append({
            "title": title, "flag": str(flag), "category": category,
            "points": points, "difficulty": difficulty,
            "technique_id": technique_id, "prompt": prompt, "hint": hint,
        })

    # ---- Family A: SOC triage from detection rules ----
    for d in catalog.detection_rules():
        tid = d.get("technique_id")
        if not tid:
            continue
        sev = (d.get("severity") or "medium").lower()
        add(f"Triage: {d.get('title', d['id'])}", tid,
            category="detection", points=_SEV_POINTS.get(sev, 150),
            difficulty=_SEV_DIFFICULTY.get(sev, "medium"), technique_id=tid,
            prompt=(f"A {sev}-severity alert fired: \"{d.get('title','')}\". "
                    f"{d.get('description','')} Identify the ATT&CK technique and "
                    f"submit its ID (e.g. T1059)."),
            hint="Think about what the attacker was doing, then map it to ATT&CK.")

    # ---- Family D: IOC hunt from detection match patterns ----
    for d in catalog.detection_rules():
        match = d.get("match") or {}
        literal = _literal_from_regex(match.get("line_regex", ""))
        if not literal:
            continue
        add(f"IOC hunt: {d.get('title', d['id'])}", literal,
            category="forensics", points=200, difficulty="medium",
            technique_id=d.get("technique_id", ""),
            prompt=(f"The rule \"{d.get('title','')}\" hunts process/host output "
                    f"for a known indicator. Submit one literal string it matches."),
            hint="Look for the tell-tale artifact an operator would grep for.")

    # ---- Family B: adversary emulation from modules ----
    for m in catalog.modules():
        tids = m.get("technique_ids") or []
        if not tids:
            continue
        tid = tids[0]
        safety = m.get("safety_class", "S1")
        add(f"Emulation: {m.get('name', m['id'])}", tid,
            category="adversary", points=_SAFETY_POINTS.get(safety, 150),
            difficulty="medium" if safety != "S2" else "hard", technique_id=tid,
            prompt=(f"Behavior module \"{m.get('name','')}\" ({m.get('platform','')}, "
                    f"{safety}) emulates activity in the \"{m.get('tactic','')}\" "
                    f"tactic. Submit its primary ATT&CK technique ID."),
            hint=f"It runs on {m.get('platform','the target')} and is classed {safety}.")

    # ---- Family C: framework / tactic mapping ----
    fw = catalog.frameworks().get("techniques", {})
    for tid, meta in fw.items():
        tactic = meta.get("tactic")
        if not tactic:
            continue
        add(f"Map the tactic: {tid}", tactic,
            category="threat-intel", points=150, difficulty="easy",
            technique_id=tid,
            prompt=(f"ATT&CK technique {tid} belongs to which Enterprise tactic? "
                    f"Submit the tactic name exactly as ATT&CK names it "
                    f"(e.g. Discovery)."),
            hint="Match the technique to its kill-chain phase.")

    return labs


def lab_summary() -> dict:
    """Counts by category, for docs and the CLI."""
    labs = generate_labs()
    by_cat: dict[str, int] = {}
    for lab in labs:
        by_cat[lab["category"]] = by_cat.get(lab["category"], 0) + 1
    return {"total": len(labs), "by_category": by_cat}
