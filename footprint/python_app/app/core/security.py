import re
import hashlib
import secrets
from typing import Set, Dict, Optional, Tuple
import argon2
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Argon2id password hasher with RFC 9106 recommended parameters
# Default time_cost=3, memory_cost=65536 (64 MiB), parallelism=4
_password_hasher = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=argon2.Type.ID
)


def hash_password(password: str) -> str:
    """Hashes a plaintext password using Argon2id."""
    if not password:
        raise ValueError("Password cannot be empty")
    return _password_hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against an Argon2id hash using constant-time comparison."""
    if not plain_password or not hashed_password:
        return False
    try:
        return _password_hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Enforces strict password complexity rules.

    Requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number or symbol
    """
    if not password or len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9\W_]", password):
        return False, "Password must contain at least one number or symbol."
    return True, ""


def is_safe_redirect_url(target: Optional[str]) -> bool:
    """Validates that a redirection URL is safe, local, and relative (prevents open redirects)."""
    if not target or not isinstance(target, str):
        return False
    target_clean = target.strip()
    # Must start with exactly one leading slash
    if not target_clean.startswith("/") or target_clean.startswith("//") or target_clean.startswith("/\\"):
        return False
    # Reject backslashes and carriage returns / control characters
    if "\\" in target_clean or "\r" in target_clean or "\n" in target_clean:
        return False
    # Reject scheme prefixes (e.g., http:, javascript:, data:)
    path_part = target_clean.split("?")[0]
    if ":" in path_part:
        return False
    return True


def generate_session_token() -> str:
    """Generates a high-entropy, cryptographically secure session token (256 bits)."""
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    """Hashes session token with SHA-256 for safe database indexing and storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_csrf_token() -> str:
    """Generates a high-entropy CSRF protection token."""
    return secrets.token_urlsafe(32)


def normalize_identifier(identifier: str) -> str:
    """Normalizes usernames and email addresses (trimmed lowercase)."""
    if not identifier:
        return ""
    return identifier.strip().lower()



# =============================================================================
# Role-Based Access Control (RBAC) & Preparatory Permissions
# =============================================================================

ROLE_ADMINISTRATOR = "administrator"
ROLE_ANALYST = "analyst"
ROLE_VIEWER = "viewer"

VALID_ROLES = {ROLE_ADMINISTRATOR, ROLE_ANALYST, ROLE_VIEWER}

# Preparatory permissions as specified in Section 10 of Phase 3
ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    ROLE_ADMINISTRATOR: {
        "investigation.create",
        "investigation.view",
        "report.view",
        "report.export",
        "user.manage",
        "scope.manage",
        "audit.view",
        "config.manage",
        "recon.passive",
        "recon.active",
        "vulnerability.scan"
    },
    ROLE_ANALYST: {
        "investigation.create",
        "investigation.view",
        "report.view",
        "report.export",
        "scope.manage",
        "recon.passive"
    },
    ROLE_VIEWER: {
        "investigation.view",
        "report.view"
    }
}


def get_role_permissions(role: str) -> Set[str]:
    """Returns the set of permissions associated with a given role."""
    return ROLE_PERMISSIONS.get(role, set())


def has_permission(role: str, permission: str) -> bool:
    """Evaluates whether a given role holds the specified permission."""
    perms = get_role_permissions(role)
    return permission in perms
