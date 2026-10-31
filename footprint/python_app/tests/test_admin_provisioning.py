"""Automated tests for initial administrator provisioning script and password rules."""

import pytest
from sqlalchemy.orm import Session
from sqlalchemy import select

from scripts.create_admin import provision_admin, validate_password_strength
from app.models.user import UserModel
from app.core.security import ROLE_ADMINISTRATOR, verify_password


def test_password_strength_validation():
    """Verify password complexity rules."""
    # Too short (<12)
    ok, err = validate_password_strength("Short1!Aa")
    assert ok is False
    assert "at least 12 characters" in err

    # Missing uppercase
    ok, err = validate_password_strength("lowercaseonly123456!")
    assert ok is False
    assert "uppercase" in err

    # Missing lowercase
    ok, err = validate_password_strength("UPPERCASEONLY123456!")
    assert ok is False
    assert "lowercase" in err

    # Missing number/symbol
    ok, err = validate_password_strength("NoNumbersOrSymbolsHere")
    assert ok is False
    assert "number or symbol" in err

    # Valid strong password
    ok, _ = validate_password_strength("NorthStarAnalytics2026!#")
    assert ok is True


def test_provision_admin_creates_new_administrator(db_session: Session):
    """Verify provision_admin creates a valid administrator account in database."""
    username = "new_cli_admin"
    email = "cli_admin@lab.example"
    password = "AdminProvisioned2026!#"

    success = provision_admin(
        username=username,
        email=email,
        password=password,
        non_interactive=True,
        db=db_session,
    )
    assert success is True

    user = db_session.scalar(select(UserModel).where(UserModel.username == username))
    assert user is not None
    assert user.role == ROLE_ADMINISTRATOR
    assert user.email == email
    assert verify_password(password, user.password_hash) is True


def test_provision_admin_repeat_execution_is_safe(db_session: Session):
    """Verify repeat execution updates existing admin without duplicate key errors."""
    username = "repeat_admin"
    email = "repeat@lab.example"
    initial_pass = "InitialPass2026!#"
    new_pass = "UpdatedPass2026!#"

    # 1. Initial provision
    res1 = provision_admin(username, email, initial_pass, non_interactive=True, db=db_session)
    assert res1 is True

    # 2. Second execution with updated password
    res2 = provision_admin(username, email, new_pass, non_interactive=True, db=db_session)
    assert res2 is True

    user = db_session.scalar(select(UserModel).where(UserModel.username == username))
    assert verify_password(new_pass, user.password_hash) is True
