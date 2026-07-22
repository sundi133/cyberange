"""Password hashing and session tokens (stdlib only).

Passwords are stored as PBKDF2-HMAC-SHA256 with a per-user random salt - never
in plaintext. Session tokens are cryptographically random opaque strings.
This is the MVP stand-in for the SSO/OIDC identity described in spec section 6;
the RBAC layer downstream is identical either way.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_ITERATIONS = 120_000


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Return (hash_hex, salt_hex)."""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), _ITERATIONS
    )
    return dk.hex(), salt


def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    candidate, _ = hash_password(password, salt_hex)
    return hmac.compare_digest(candidate, expected_hash_hex)


def new_token() -> str:
    return secrets.token_urlsafe(32)
