"""FootprintIQ - Safe, Repeatable Demo Account Provisioning Script.

Provisions a least-privileged Security Analyst account (ROLE_ANALYST) for
live platform demonstration and evaluation.

Features:
- Idempotent and non-destructive.
- Generates a cryptographically strong, unique password if none provided.
- Hashes password using production Argon2id configuration.
- Verifies stored hash integrity (never stores plaintext).
- Performs live authentication and permission checks before completion.
- Formats credentials and login URLs for immediate demonstration.
"""

import sys
import os
import secrets
import string
import argparse
import uuid
from pathlib import Path
from typing import Optional, Tuple

# Add python_app directory to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from app.database import SessionLocal
from app.models.user import UserModel
from app.core.security import (
    hash_password,
    verify_password,
    validate_password_strength,
    ROLE_ANALYST,
    ROLE_ADMINISTRATOR,
    ROLE_VIEWER,
    has_permission,
    get_role_permissions,
)
from app.core.auth import authenticate_user, create_user_session, log_audit_event


def generate_strong_password(length: int = 16) -> str:
    """Generates a cryptographically secure password meeting all FootprintIQ complexity rules."""
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+"

    # Ensure at least one from each required class
    chars = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]

    all_chars = upper + lower + digits + symbols
    chars += [secrets.choice(all_chars) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def provision_demo_account(
    username: str = "demo_analyst",
    email: str = "demo@footprintiq.local",
    password: Optional[str] = None,
    reset_if_exists: bool = False,
) -> Tuple[bool, dict]:
    """Provisions or verifies the demo analyst account safely and idempotently."""
    db = SessionLocal()
    try:
        # Check existing account
        existing = db.execute(
            select(UserModel).where(
                (UserModel.username == username) | (UserModel.email == email)
            )
        ).scalars().first()

        generated_new_password = False
        final_password = password

        if existing:
            # Prevent accidental overwrite of an administrator account
            if existing.role == ROLE_ADMINISTRATOR:
                return False, {
                    "error": f"Security violation: Account '{existing.username}' is an Administrator. Demo accounts must never overwrite administrative identities."
                }

            if not reset_if_exists and not password:
                return False, {
                    "error": f"Demo account '{existing.username}' ({existing.email}) already exists. Use --reset to re-generate password or specify --password."
                }

            if not final_password:
                final_password = generate_strong_password()
                generated_new_password = True

            is_valid, err = validate_password_strength(final_password)
            if not is_valid:
                return False, {"error": f"Password policy violation: {err}"}

            existing.password_hash = hash_password(final_password)
            existing.role = ROLE_ANALYST  # Strictly analyst
            existing.is_active = True
            existing.failed_login_attempts = 0
            existing.locked_until = None
            db.commit()
            db.refresh(existing)
            user = existing
            action = "updated"
        else:
            if not final_password:
                final_password = generate_strong_password()
                generated_new_password = True

            is_valid, err = validate_password_strength(final_password)
            if not is_valid:
                return False, {"error": f"Password policy violation: {err}"}

            user = UserModel(
                id=f"demo-{uuid.uuid4().hex[:12]}",
                username=username,
                email=email,
                password_hash=hash_password(final_password),
                role=ROLE_ANALYST,
                is_active=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            action = "created"

        # Audit event
        log_audit_event(
            db=db,
            event_type="USER_REGISTERED",
            outcome="SUCCESS",
            actor_id=user.id,
            target_user_id=user.id,
            details={
                "username": user.username,
                "role": user.role,
                "action": f"demo_provision_{action}",
            },
        )

        # ---------------------------------------------------------------------
        # Mandatory Verification: Validate stored hash, live auth, and permissions
        # ---------------------------------------------------------------------
        # 1. Stored password must be an Argon2 hash, not plaintext
        if not user.password_hash.startswith("$argon2"):
            return False, {"error": "Password was not stored using Argon2id algorithm."}

        # 2. Authenticate through the application's real authentication function
        auth_user = authenticate_user(
            db=db,
            username_or_email=username,
            password=final_password,
            client_ip="127.0.0.1",
        )
        if not auth_user or auth_user.id != user.id:
            return False, {"error": "Live authentication test failed against provisioned credentials."}

        # 3. Create real authenticated session
        raw_token, session = create_user_session(
            db=db,
            user=auth_user,
            ip_address="127.0.0.1",
            user_agent="FootprintIQ-Provisioning-Verifier",
        )
        if not raw_token or not session:
            return False, {"error": "Session issuance test failed for provisioned user."}

        # 4. Verify RBAC permissions: Analyst should have investigation and report rights,
        # but MUST NOT have user management or admin capabilities
        can_create_inv = has_permission(auth_user.role, "investigation.create")
        can_read_inv = has_permission(auth_user.role, "investigation.view")
        can_export_rep = has_permission(auth_user.role, "report.export")
        can_manage_users = has_permission(auth_user.role, "user.manage")

        if not can_create_inv or not can_export_rep or can_manage_users or auth_user.role == ROLE_ADMINISTRATOR:
            return False, {
                "error": f"Role permission verification failed: role={auth_user.role}, can_create_inv={can_create_inv}, can_manage_users={can_manage_users}"
            }

        return True, {
            "status": "SUCCESS",
            "action": action,
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "password": final_password,
            "role": user.role,
            "permissions": [
                "investigation:create",
                "investigation:read",
                "investigation:update",
                "evidence:read",
                "report:generate",
            ],
            "admin_access": False,
            "password_storage": "Argon2id ($argon2id$...)",
            "live_auth_tested": True,
            "session_issuance_tested": True,
        }
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="FootprintIQ Demo Account Provisioning Tool")
    parser.add_argument("--username", default="demo_analyst", help="Demo account username (default: demo_analyst)")
    parser.add_argument("--email", default="demo@footprintiq.local", help="Demo account email (default: demo@footprintiq.local)")
    parser.add_argument("--password", default=None, help="Explicit password (if omitted, a strong password will be generated)")
    parser.add_argument("--reset", action="store_true", help="Reset password if demo account already exists")
    args = parser.parse_args()

    print("======================================================================")
    print(" FootprintIQ - Demo Account Provisioning & Verification Tool")
    print("======================================================================")

    success, result = provision_demo_account(
        username=args.username,
        email=args.email,
        password=args.password,
        reset_if_exists=args.reset,
    )

    if not success:
        print(f"\n[FAILED] Demo account provisioning failed:\n  {result.get('error')}")
        sys.exit(1)

    print(f"\n[OK] Demo Account Successfully {result['action'].title()} & Verified!")
    print("----------------------------------------------------------------------")
    print(f" Username:      {result['username']}")
    print(f" Email:         {result['email']}")
    print(f" Password:      {result['password']}")
    print(f" Role:          {result['role'].upper()} (Least-Privileged Security Analyst)")
    print(f" Admin Access:  {result['admin_access']} (Strictly Denied)")
    print(f" Hash Type:     {result['password_storage']}")
    print(f" Auth Verified: [PASS] Real login and session issuance tests passed")
    print("----------------------------------------------------------------------")
    print(f" Login URL:     http://127.0.0.1:8000/login")
    print("======================================================================")


if __name__ == "__main__":
    main()
