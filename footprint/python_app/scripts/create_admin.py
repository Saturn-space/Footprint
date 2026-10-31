"""Safe initial administrator provisioning script.

Supports interactive input via getpass as well as non-interactive execution
via CLI arguments or environment variables for CI/automated testing.
"""

import sys
import os
import re
import getpass
import argparse
import uuid
from typing import Optional, Any
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import SessionLocal
from app.models.user import UserModel
from app.core.security import (
    hash_password,
    normalize_identifier,
    ROLE_ADMINISTRATOR,
)
from app.core.auth import log_audit_event


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Enforces strict password complexity rules."""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9\W_]", password):
        return False, "Password must contain at least one number or symbol."
    return True, ""


def provision_admin(
    username: str,
    email: str,
    password: str,
    non_interactive: bool = False,
    db: Optional[Any] = None,
) -> bool:
    """Provisions or updates an administrator account safely."""
    username = normalize_identifier(username)
    email = normalize_identifier(email)

    if not username or len(username) < 3:
        print("[ERROR] Username must be at least 3 characters long.", file=sys.stderr)
        return False

    if not email or "@" not in email:
        print("[ERROR] A valid email address is required.", file=sys.stderr)
        return False

    is_strong, err_msg = validate_password_strength(password)
    if not is_strong:
        print(f"[ERROR] {err_msg}", file=sys.stderr)
        return False

    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True
    try:
        from sqlalchemy import select

        existing_user = db.scalar(
            select(UserModel).where((UserModel.username == username) | (UserModel.email == email))
        )

        if existing_user:
            if existing_user.role == ROLE_ADMINISTRATOR:
                print(
                    f"[INFO] Administrator account '{existing_user.username}' ({existing_user.email}) already exists."
                )
                if non_interactive:
                    print("[INFO] Updating password for existing administrator.")
                else:
                    confirm = input("Reset password for this administrator? (y/N): ").strip().lower()
                    if confirm != "y":
                        print("[INFO] No changes made. Exiting safely.")
                        return True

                existing_user.password_hash = hash_password(password)
                existing_user.is_active = True
                existing_user.failed_login_attempts = 0
                existing_user.locked_until = None
                db.commit()

                log_audit_event(
                    db=db,
                    event_type="ADMIN_PASSWORD_RESET",
                    outcome="SUCCESS",
                    actor_id="cli-operator",
                    target_user_id=existing_user.id,
                    details={"username": existing_user.username},
                )
                print(f"[SUCCESS] Administrator '{existing_user.username}' password successfully updated.")
                return True
            else:
                print(
                    f"[WARNING] User '{existing_user.username}' exists with role '{existing_user.role}'."
                )
                if not non_interactive:
                    confirm = input("Promote this user to Administrator and update password? (y/N): ").strip().lower()
                    if confirm != "y":
                        print("[INFO] No changes made. Exiting safely.")
                        return False

                existing_user.role = ROLE_ADMINISTRATOR
                existing_user.password_hash = hash_password(password)
                existing_user.is_active = True
                db.commit()

                log_audit_event(
                    db=db,
                    event_type="ROLE_CHANGED",
                    outcome="SUCCESS",
                    actor_id="cli-operator",
                    target_user_id=existing_user.id,
                    details={"new_role": ROLE_ADMINISTRATOR},
                )
                print(f"[SUCCESS] User '{existing_user.username}' promoted to Administrator.")
                return True

        # Create brand new administrator
        admin_user = UserModel(
            id=f"usr-{uuid.uuid4().hex[:12]}",
            username=username,
            email=email,
            password_hash=hash_password(password),
            role=ROLE_ADMINISTRATOR,
            is_active=True,
        )
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)

        log_audit_event(
            db=db,
            event_type="ADMIN_PROVISIONED",
            outcome="SUCCESS",
            actor_id="cli-operator",
            target_user_id=admin_user.id,
            details={"username": admin_user.username, "email": admin_user.email},
        )

        print(f"[SUCCESS] Administrator '{admin_user.username}' ({admin_user.email}) successfully provisioned!")
        print(f"[SUCCESS] User ID: {admin_user.id}")
        return True

    finally:
        if close_db:
            db.close()


def main():
    parser = argparse.ArgumentParser(description="Provision the initial FootprintIQ administrator account.")
    parser.add_argument("--username", help="Administrator username (min 3 characters)")
    parser.add_argument("--email", help="Administrator email address")
    parser.add_argument("--password", help="Administrator password (min 12 chars, mixed case, number/symbol)")
    parser.add_argument("--non-interactive", action="store_true", help="Run without interactive prompts")

    args = parser.parse_args()

    # Check environment variables if arguments not provided
    username = args.username or os.getenv("INITIAL_ADMIN_USERNAME")
    email = args.email or os.getenv("INITIAL_ADMIN_EMAIL")
    password = args.password or os.getenv("INITIAL_ADMIN_PASSWORD")

    if not username:
        username = input("Enter Administrator Username: ").strip()

    if not email:
        email = input("Enter Administrator Email: ").strip()

    if not password:
        password = getpass.getpass("Enter Administrator Password (min 12 chars, upper/lower/symbols): ")
        confirm_password = getpass.getpass("Confirm Administrator Password: ")
        if password != confirm_password:
            print("[ERROR] Passwords do not match.", file=sys.stderr)
            sys.exit(1)

    success = provision_admin(
        username=username,
        email=email,
        password=password,
        non_interactive=args.non_interactive or bool(args.password or os.getenv("INITIAL_ADMIN_PASSWORD")),
    )

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
