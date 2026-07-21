"""Role-based access control (spec section 8, FR-12).

Simple capability model mapping roles to permission strings. Participant
accounts are scoped to a single exercise run; admins/instructors see all.
"""

from __future__ import annotations

ROLES = ["red", "blue", "purple", "instructor", "admin", "solo", "security_leader"]

# Permission catalog.
PERMISSIONS = {
    "catalog:read",
    "range:create", "range:read", "range:lifecycle", "range:destroy",
    "range:quarantine_release",
    "exercise:read", "exercise:participate", "exercise:submit_evidence",
    "exercise:inject", "exercise:score_override",
    "module:read", "module:execute", "module:approve",
    "scoring:read",
    "report:read",
    "cohort:manage", "assignment:manage", "gradebook:read", "learn:participate",
    "admin:manage_users", "admin:manage_images", "admin:audit", "admin:emergency",
}

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "red": {
        "catalog:read", "range:read", "exercise:read", "exercise:participate",
        "exercise:submit_evidence", "module:read", "module:execute", "report:read",
        "learn:participate",
    },
    "blue": {
        "catalog:read", "range:read", "exercise:read", "exercise:participate",
        "exercise:submit_evidence", "module:read", "report:read", "scoring:read",
        "learn:participate",
    },
    "purple": {
        "catalog:read", "range:read", "exercise:read", "exercise:participate",
        "module:read", "module:execute", "report:read", "scoring:read",
        "learn:participate",
    },
    "solo": {
        "catalog:read", "range:read", "range:create", "range:lifecycle",
        "exercise:read", "exercise:participate",
        "exercise:submit_evidence", "module:read", "module:execute", "report:read",
        "learn:participate",
    },
    "instructor": {
        "catalog:read", "range:create", "range:read", "range:lifecycle",
        "exercise:read", "exercise:inject", "exercise:score_override",
        "module:read", "module:execute", "report:read", "scoring:read",
        "cohort:manage", "assignment:manage", "gradebook:read",
    },
    "security_leader": {
        "catalog:read", "range:read", "exercise:read", "report:read", "scoring:read",
        "gradebook:read",
    },
    "admin": set(PERMISSIONS),  # full control plane
}


# Plain-English summary of what each role is allowed to do (for the admin
# panel and the in-app role matrix).
ROLE_SUMMARY: dict[str, str] = {
    "admin": "Full control plane. Provision users, manage images, run and destroy "
             "ranges, release quarantined ranges, drive any lifecycle step, execute "
             "any module (including S2), override scores, and read the audit ledger.",
    "instructor": "Deliver exercises and teach. Create ranges, drive the lifecycle, "
                  "launch exercises, publish injects, execute modules (including S2), "
                  "override scores, and run classes: create cohorts, import rosters, "
                  "assign lessons, and view the gradebook. Cannot manage users or "
                  "release a quarantined range (admin-only).",
    "red": "Attacker. Participate in a run, execute S0/S1 behavior modules (S2 is "
           "blocked), submit evidence, and read the catalog, ranges, and reports. "
           "Cannot create ranges, inject, or score.",
    "blue": "Defender. Participate, submit evidence, and read the catalog, ranges, "
            "scoring, and reports. Cannot execute attacker modules, create ranges, "
            "inject, or override scores.",
    "purple": "Replay & tuning. Participate, execute modules for deterministic "
              "replay, and read scoring and reports. Coordinates detection "
              "improvement between baseline and replay.",
    "solo": "Student / guided learner. Takes assigned lessons that walk through "
            "briefing, hands-on tasks on an auto-provisioned range, and a knowledge "
            "check — learning within the platform at their own pace.",
    "security_leader": "Read-only oversight. View the catalog, ranges, exercises, "
                       "scoring, and reports to assess readiness. Cannot change any "
                       "state.",
}

# Human labels for permission strings shown in the matrix.
PERMISSION_LABELS: dict[str, str] = {
    "catalog:read": "Browse scenario & module catalog",
    "range:create": "Create ranges",
    "range:read": "View ranges",
    "range:lifecycle": "Drive range lifecycle (provision, start, reset…)",
    "range:destroy": "Destroy ranges",
    "range:quarantine_release": "Release/destroy a quarantined range",
    "exercise:read": "View exercises",
    "exercise:participate": "Participate in an exercise",
    "exercise:submit_evidence": "Submit evidence",
    "exercise:inject": "Publish instructor injects",
    "exercise:score_override": "Override scores (audited)",
    "module:read": "View behavior modules",
    "module:execute": "Execute behavior modules",
    "module:approve": "Approve/sign modules",
    "scoring:read": "View scoring detail",
    "report:read": "View reports",
    "cohort:manage": "Create classes & manage rosters",
    "assignment:manage": "Assign lessons to a class",
    "gradebook:read": "View the class gradebook",
    "learn:participate": "Take guided lessons",
    "admin:manage_users": "Provision & manage user accounts",
    "admin:manage_images": "Manage VM/OCI images",
    "admin:audit": "Read the audit ledger",
    "admin:emergency": "Emergency pause / kill controls",
}


def role_matrix() -> list[dict]:
    """Structured role → capabilities view for UI and docs."""
    out = []
    for role in ROLES:
        perms = sorted(ROLE_PERMISSIONS.get(role, set()))
        out.append({
            "role": role,
            "summary": ROLE_SUMMARY.get(role, ""),
            "permissions": perms,
            "capabilities": [PERMISSION_LABELS.get(p, p) for p in perms],
        })
    return out


class AuthorizationError(Exception):
    """Raised when a role lacks the required permission."""


def permissions_for(role: str) -> set[str]:
    if role not in ROLE_PERMISSIONS:
        raise AuthorizationError(f"Unknown role: {role}")
    return ROLE_PERMISSIONS[role]


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


def require(role: str, permission: str) -> None:
    if not has_permission(role, permission):
        raise AuthorizationError(
            f"Role '{role}' is not permitted to perform '{permission}'"
        )


def is_admin(role: str) -> bool:
    return role == "admin"
