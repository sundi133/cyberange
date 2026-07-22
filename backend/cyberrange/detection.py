"""Detection-rule engine (FR-08).

Evaluates versioned, Sigma-like rules against the exercise timeline - including
the *real* container output captured by the Docker execution adapter - and
produces automatic, evidence-backed detection verdicts. This replaces the
manual "type a verdict" flow: a detection fires because a rule matched real
telemetry, and it records which rule, which line, and how long after the
activity it triggered (detection latency / MTTD).

Two match bases:
- `log`   - a regex matched a real log line (high fidelity).
- `technique` - the technique was observed in the range (coverage rule; used
  for behaviors that are simulated rather than executed in a container).

Kernel-level runtime detection (Falco) is the Phase-2 sensor; this engine is
its portable analog over collected telemetry, which is how a SIEM operates.
"""

from __future__ import annotations

import re
from datetime import datetime


def _event_text(event: dict) -> str:
    payload = event.get("payload") or {}
    return payload.get("line") or payload.get("stderr") or ""


def rule_basis(rule: dict, event: dict) -> str | None:
    """Return 'log' or 'technique' if the rule matches this event, else None."""
    match = rule.get("match", {})
    kinds = match.get("kinds")
    if kinds and event.get("kind") not in kinds:
        return None

    has_technique = "technique" in match
    has_regex = "line_regex" in match
    if not has_technique and not has_regex:
        return None

    if has_technique and event.get("technique_id") != match["technique"]:
        return None
    if has_regex:
        text = _event_text(event)
        if not text or not re.search(match["line_regex"], text, re.IGNORECASE):
            return None
        return "log"
    return "technique"


def _parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def evaluate(rules: list[dict], events: list[dict], *,
             now: datetime, already_fired: set[str] | None = None) -> list[dict]:
    """Fire each not-yet-fired rule against the earliest matching event.

    Returns a list of detection hits with the matched rule, evidence line,
    and latency (seconds from the matched event to `now`).
    """
    already_fired = already_fired or set()
    hits: list[dict] = []
    for rule in rules:
        if rule["id"] in already_fired:
            continue
        for event in events:  # events are time-ordered ascending
            basis = rule_basis(rule, event)
            if not basis:
                continue
            event_dt = _parse_ts(event.get("ts_utc", ""))
            latency = 0.0
            if event_dt is not None:
                latency = max(0.0, round((now - event_dt).total_seconds(), 3))
            hits.append({
                "rule_id": rule["id"],
                "technique_id": rule["technique_id"],
                "rule_version": rule.get("rule_version", "v1"),
                "severity": rule.get("severity", "medium"),
                "title": rule.get("title", rule["id"]),
                "basis": basis,
                "matched_event_id": event.get("id"),
                "evidence": (_event_text(event) or event.get("kind", ""))[:200],
                "latency_s": latency,
            })
            break  # first match only per rule
    return hits
