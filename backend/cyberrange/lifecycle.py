"""Range lifecycle state machine (spec section 6, FR-03).

REQUESTED -> PREFLIGHT -> PROVISIONING -> SEEDING -> READY
-> RUNNING <-> PAUSED -> COMPLETING -> EVIDENCE_LOCKED -> ARCHIVED -> DESTROYED

Any anomalous workload transitions to QUARANTINED; only an administrator
may release (to EVIDENCE_LOCKED) or DESTROY it.
"""

from __future__ import annotations


class LifecycleError(Exception):
    """Raised on an illegal lifecycle transition."""


# Allowed forward/backward transitions between states.
TRANSITIONS: dict[str, set[str]] = {
    "REQUESTED": {"PREFLIGHT", "DESTROYED"},
    "PREFLIGHT": {"PROVISIONING", "QUARANTINED", "DESTROYED"},
    "PROVISIONING": {"SEEDING", "QUARANTINED", "DESTROYED"},
    "SEEDING": {"READY", "QUARANTINED", "DESTROYED"},
    "READY": {"RUNNING", "QUARANTINED", "ARCHIVED", "DESTROYED"},
    "RUNNING": {"PAUSED", "COMPLETING", "QUARANTINED"},
    "PAUSED": {"RUNNING", "COMPLETING", "QUARANTINED"},
    "COMPLETING": {"EVIDENCE_LOCKED", "QUARANTINED"},
    "EVIDENCE_LOCKED": {"ARCHIVED", "DESTROYED"},
    "ARCHIVED": {"DESTROYED"},
    # Terminal / special
    "QUARANTINED": {"EVIDENCE_LOCKED", "DESTROYED"},  # admin-only release
    "DESTROYED": set(),
}

INITIAL_STATE = "REQUESTED"
TERMINAL_STATES = {"DESTROYED"}

# Transitions that require an administrator actor.
ADMIN_ONLY = {
    ("QUARANTINED", "EVIDENCE_LOCKED"),
    ("QUARANTINED", "DESTROYED"),
}

# Map high-level lifecycle actions (FR-03) to their target state given a source.
ACTION_TARGET: dict[str, str] = {
    "preflight": "PREFLIGHT",
    "provision": "PROVISIONING",
    "seed": "SEEDING",
    "ready": "READY",
    "start": "RUNNING",
    "pause": "PAUSED",
    "resume": "RUNNING",
    "complete": "COMPLETING",
    "lock_evidence": "EVIDENCE_LOCKED",
    "archive": "ARCHIVED",
    "quarantine": "QUARANTINED",
    "destroy": "DESTROYED",
}


def can_transition(src: str, dst: str) -> bool:
    return dst in TRANSITIONS.get(src, set())


def validate_transition(src: str, dst: str, *, is_admin: bool = False) -> None:
    """Raise LifecycleError if src->dst is not permitted for this actor."""
    if src not in TRANSITIONS:
        raise LifecycleError(f"Unknown state: {src}")
    if dst not in TRANSITIONS:
        raise LifecycleError(f"Unknown target state: {dst}")
    if not can_transition(src, dst):
        raise LifecycleError(f"Illegal transition {src} -> {dst}")
    if (src, dst) in ADMIN_ONLY and not is_admin:
        raise LifecycleError(f"Transition {src} -> {dst} requires an administrator")


def apply_action(src: str, action: str, *, is_admin: bool = False) -> str:
    """Resolve a lifecycle action to a target state and validate it."""
    if action not in ACTION_TARGET:
        raise LifecycleError(f"Unknown lifecycle action: {action}")
    dst = ACTION_TARGET[action]
    validate_transition(src, dst, is_admin=is_admin)
    return dst


def is_terminal(state: str) -> bool:
    return state in TERMINAL_STATES
