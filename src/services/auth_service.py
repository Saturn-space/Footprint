"""
FootprintIQ - Authentication and Role-Based Access Control (RBAC) Service
Provides bcrypt password hashing, JWT session token generation and verification,
and strict server-side role enforcement (admin vs investigator).
"""

import os
import secrets
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from fastapi import Request
from src.db.repository import FootprintIQRepository, DatabaseIntegrityError
from src.services.rbac_service import (
    ROLE_ADMIN,
    ROLE_INVESTIGATOR,
    VALID_ROLES,
    normalize_role,
    record_security_audit,
)

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "FootprintIQ-SuperSecretKey-2026-ProductionSafe")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DEFAULT_DEMO_ACCOUNTS = (
    ("admin", "admin@footprintiq.internal", "AdminPass2026!", "admin", True),
    ("investigator1", "investigator1@footprintiq.internal", "Investigator1Pass2026!", "investigator", True),
    ("investigator2", "investigator2@footprintiq.internal", "Investigator2Pass2026!", "investigator", True),
)


def hash_password(password: str) -> str:
    """Hashes a plaintext password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Creates a signed JWT session token with expiration."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None


class AuthService:
    def __init__(self, repo: Optional[FootprintIQRepository] = None):
        self.repo = repo or FootprintIQRepository()
        self._ensure_default_accounts()

    def _ensure_default_accounts(self):
        """Initializes default demo administrator and investigator accounts idempotently."""
        for username, email, plain_password, role, is_approved in DEFAULT_DEMO_ACCOUNTS:
            existing = self.repo.get_user_by_username(username)
            if not existing:
                try:
                    self.repo.create_user(
                        username=username,
                        email=email,
                        hashed_password=hash_password(plain_password),
                        role=role,
                        is_approved=is_approved,
                    )
                except DatabaseIntegrityError:
                    # Another worker created the same seeded account concurrently on startup
                    pass

    def _ensure_default_admin(self):
        """Backward-compatible helper delegating to default demo account seeding."""
        self._ensure_default_accounts()

    def register(
        self,
        username: str,
        email: str,
        password: str,
        role: str = "investigator",
        request: Optional[Request] = None,
    ) -> Dict[str, Any]:
        """
        Registers a new investigator account.
        Self-registration ALWAYS assigns role='investigator' with is_approved=False.
        Any attempt to self-register as 'admin' or an invalid role is denied and audited.
        """
        clean_username = (username or "").strip()
        clean_email = (email or "").strip().lower()
        if not clean_username or len(clean_username) < 3:
            raise ValueError("Username must be at least 3 characters.")
        if not clean_email or "@" not in clean_email:
            raise ValueError("A valid email address is required.")
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")

        requested_role = (role or ROLE_INVESTIGATOR).strip().lower()
        if requested_role != ROLE_INVESTIGATOR:
            record_security_audit(
                self.repo,
                user=None,
                actor_role="anonymous",
                action="PRIVILEGE_ESCALATION_ATTEMPT",
                target_resource=clean_username,
                details={"requested_role": requested_role, "reason": "self_register_role_forbidden"},
                outcome="DENIED",
                request=request,
            )
            raise PermissionError("Self-registration is limited to investigator accounts pending administrator approval.")

        existing = self.repo.get_user_by_username(clean_username)
        if existing:
            raise ValueError(f"Username '{clean_username}' is already registered.")

        try:
            user = self.repo.create_user(
                username=clean_username,
                email=clean_email,
                hashed_password=hash_password(password),
                role=ROLE_INVESTIGATOR,
                is_approved=False
            )
        except DatabaseIntegrityError as e:
            raise ValueError(str(e))

        record_security_audit(
            self.repo,
            user=user,
            actor_role=ROLE_INVESTIGATOR,
            action="USER_REGISTERED",
            target_resource=clean_username,
            details={"role": ROLE_INVESTIGATOR, "is_approved": False},
            outcome="SUCCESS",
            request=request,
        )
        return user

    def authenticate(
        self,
        username: str,
        password: str,
        request: Optional[Request] = None,
    ) -> Optional[Dict[str, Any]]:
        """Authenticates a user and returns a session JWT token and bound CSRF token."""
        user = self.repo.get_user_by_username(username)
        if not user:
            record_security_audit(
                self.repo,
                user=None,
                actor_role="anonymous",
                action="LOGIN_FAILED",
                target_resource=username,
                details={"reason": "unknown_user"},
                outcome="FAILED",
                request=request,
            )
            return None

        if not verify_password(password, user["hashed_password"]):
            record_security_audit(
                self.repo,
                user=user,
                action="LOGIN_FAILED",
                target_resource=username,
                details={"reason": "invalid_credentials"},
                outcome="FAILED",
                request=request,
            )
            return None

        role = normalize_role(user.get("role"))
        if role is None:
            record_security_audit(
                self.repo,
                user=user,
                actor_role=str(user.get("role") or "unknown"),
                action="LOGIN_DENIED",
                target_resource=username,
                details={"reason": "invalid_role"},
                outcome="DENIED",
                request=request,
            )
            raise PermissionError("Account role is invalid. Contact an administrator.")

        if not user.get("is_active", True):
            record_security_audit(
                self.repo,
                user=user,
                action="LOGIN_DENIED",
                target_resource=username,
                details={"reason": "account_suspended"},
                outcome="DENIED",
                request=request,
            )
            raise PermissionError("Account is inactive.")

        if not user.get("is_approved", True):
            record_security_audit(
                self.repo,
                user=user,
                action="LOGIN_DENIED",
                target_resource=username,
                details={"reason": "pending_approval"},
                outcome="DENIED",
                request=request,
            )
            raise PermissionError("Account registration is pending administrator approval.")

        self.repo.record_user_login(user["username"])
        refreshed = self.repo.get_user_by_username(user["username"]) or user
        token_version = int(refreshed.get("token_version", 1) or 1)

        csrf_token = secrets.token_urlsafe(32)
        token = create_access_token({
            "sub": user["username"],
            "user_id": user["id"],
            "role": role,
            "csrf": csrf_token,
            "tv": token_version,
        })

        record_security_audit(
            self.repo,
            user=user,
            action="LOGIN_SUCCESS",
            target_resource=username,
            details={"role": role, "token_version": token_version},
            outcome="SUCCESS",
            request=request,
        )

        return {
            "access_token": token,
            "token_type": "bearer",
            "csrf_token": csrf_token,
            "username": user["username"],
            "role": role,
            "user_id": user["id"]
        }

    def change_own_password(
        self,
        actor_user: Dict[str, Any],
        current_password: str,
        new_password: str,
        request: Optional[Request] = None,
    ) -> Dict[str, Any]:
        """Verifies current password, enforces length rules, updates bcrypt hash, and invalidates prior sessions."""
        username = str(actor_user.get("username") or "").strip()
        live_user = self.repo.get_user_by_username(username)
        if not live_user:
            raise ValueError("Authenticated user account was not found.")
        if not current_password or not verify_password(current_password, live_user.get("hashed_password") or ""):
            record_security_audit(
                self.repo,
                user=actor_user,
                action="PASSWORD_CHANGE_FAILED",
                target_resource=username,
                details={"reason": "invalid_current_password"},
                outcome="FAILED",
                request=request,
            )
            raise PermissionError("Current password is incorrect.")
        if not new_password or len(new_password) < 8:
            raise ValueError("New password must be at least 8 characters long.")
        if verify_password(new_password, live_user.get("hashed_password") or ""):
            raise ValueError("New password must differ from your current password.")

        updated = self.repo.update_user_password(
            username,
            hash_password(new_password),
            invalidate_sessions=True,
        )
        if not updated:
            raise ValueError("Unable to update password.")

        record_security_audit(
            self.repo,
            user=actor_user,
            action="PASSWORD_CHANGED",
            target_resource=username,
            details={"sessions_invalidated": True, "token_version": updated.get("token_version")},
            outcome="SUCCESS",
            request=request,
        )
        return updated

    def approve_investigator(
        self,
        admin_user: Dict[str, Any],
        target_username: str,
        request: Optional[Request] = None,
    ) -> bool:
        """Approves a pending investigator registration."""
        if normalize_role(admin_user.get("role")) != ROLE_ADMIN:
            raise PermissionError("Only administrators can approve registrations.")

        success = self.repo.approve_user(target_username)
        if success:
            record_security_audit(
                self.repo,
                user=admin_user,
                action="USER_APPROVED",
                target_resource=target_username,
                details={"target_username": target_username},
                outcome="SUCCESS",
                request=request,
            )
        return success

    def reject_investigator(
        self,
        admin_user: Dict[str, Any],
        target_username: str,
        request: Optional[Request] = None,
    ) -> bool:
        """Rejects/deactivates a pending user registration."""
        if normalize_role(admin_user.get("role")) != ROLE_ADMIN:
            raise PermissionError("Only administrators can reject registrations.")
        if target_username == admin_user.get("username"):
            raise PermissionError("Administrators cannot reject their own account.")
        success = self.repo.reject_user(target_username)
        if success:
            record_security_audit(
                self.repo,
                user=admin_user,
                action="USER_REJECTED",
                target_resource=target_username,
                details={"target_username": target_username},
                outcome="SUCCESS",
                request=request,
            )
        return success

    def update_user_status(
        self,
        admin_user: Dict[str, Any],
        target_username: str,
        is_active: bool,
        request: Optional[Request] = None,
    ) -> Optional[Dict[str, Any]]:
        """Activates or suspends a user account while preventing self-lockout and last-admin removal."""
        if normalize_role(admin_user.get("role")) != ROLE_ADMIN:
            raise PermissionError("Only administrators can update account status.")
        target = self.repo.get_user_by_username(target_username)
        if not target:
            return None
        if not is_active and target_username == admin_user.get("username"):
            raise PermissionError("Administrators cannot suspend their own account.")
        if not is_active and target.get("role") == ROLE_ADMIN:
            active_admins = [
                u for u in self.repo.list_users()
                if u.get("role") == ROLE_ADMIN and u.get("is_active") and u.get("is_approved")
            ]
            if len(active_admins) <= 1:
                raise ValueError("Cannot suspend the last active administrator.")

        updated = self.repo.set_user_active(target_username, is_active)
        if updated:
            record_security_audit(
                self.repo,
                user=admin_user,
                action="USER_STATUS_UPDATED",
                target_resource=target_username,
                details={"target_username": target_username, "is_active": bool(is_active)},
                outcome="SUCCESS",
                request=request,
            )
        return updated

    def assign_user_role(
        self,
        admin_user: Dict[str, Any],
        target_username: str,
        new_role: str,
        request: Optional[Request] = None,
    ) -> Optional[Dict[str, Any]]:
        """Assigns an explicit RBAC role while preventing self-role change and last-admin demotion."""
        if normalize_role(admin_user.get("role")) != ROLE_ADMIN:
            raise PermissionError("Only administrators can modify user roles.")
        normalized = normalize_role(new_role)
        if normalized not in VALID_ROLES:
            raise ValueError("Role must be strictly 'admin' or 'investigator'.")
        if target_username == admin_user.get("username"):
            raise PermissionError("Administrators cannot modify their own role.")
        target = self.repo.get_user_by_username(target_username)
        if not target:
            return None
        if target.get("role") == ROLE_ADMIN and normalized != ROLE_ADMIN:
            active_admins = [
                u for u in self.repo.list_users()
                if u.get("role") == ROLE_ADMIN and u.get("is_active") and u.get("is_approved")
            ]
            if len(active_admins) <= 1:
                raise ValueError("Cannot demote the last active administrator.")

        updated = self.repo.update_user_role(target_username, normalized)
        if updated:
            record_security_audit(
                self.repo,
                user=admin_user,
                action="USER_ROLE_CHANGED",
                target_resource=target_username,
                details={"target_username": target_username, "old_role": target.get("role"), "new_role": normalized},
                outcome="SUCCESS",
                request=request,
            )
        return updated

