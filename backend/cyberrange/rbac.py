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
    "admin:manage_users", "admin:manage_images", "admin:audit", "admin:emergency",
}

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "red": {
        "catalog:read", "range:read", "exercise:read", "exercise:participate",
        "exercise:submit_evidence", "module:read", "module:execute", "report:read",
    },
    "blue": {
        "catalog:read", "range:read", "exercise:read", "exercise:participate",
        "exercise:submit_evidence", "module:read", "report:read", "scoring:read",
    },
    "purple": {
        "catalog:read", "range:read", "exercise:read", "exercise:participate",
        "module:read", "module:execute", "report:read", "scoring:read",
    },
    "solo": {
        "catalog:read", "range:read", "exercise:read", "exercise:participate",
        "exercise:submit_evidence", "module:read", "module:execute", "report:read",
    },
    "instructor": {
        "catalog:read", "range:create", "range:read", "range:lifecycle",
        "exercise:read", "exercise:inject", "exercise:score_override",
        "module:read", "module:execute", "report:read", "scoring:read",
    },
    "security_leader": {
        "catalog:read", "range:read", "exercise:read", "report:read", "scoring:read",
    },
    "admin": set(PERMISSIONS),  # full control plane
}


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
