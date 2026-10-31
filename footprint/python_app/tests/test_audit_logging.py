"""Automated tests for security audit logging and credential redaction."""

import pytest
from starlette.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.models.user import UserModel
from app.models.audit import AuditLogModel


def test_audit_logs_record_login_success_and_failures(
    client: TestClient, db_session: Session, analyst_user: UserModel
):
    """Verify LOGIN_SUCCESS and LOGIN_FAILED are recorded in audit logs."""
    # 1. Failed login attempt
    client.post("/api/v1/auth/login", json={
        "username_or_email": analyst_user.username,
        "password": "BadPassword123!"
    })

    # 2. Successful login attempt
    client.post("/api/v1/auth/login", json={
        "username_or_email": analyst_user.username,
        "password": "AnalystSecure123!#"
    })

    # Query audit logs
    stmt = select(AuditLogModel).order_by(AuditLogModel.timestamp.desc())
    logs = db_session.scalars(stmt).all()

    event_types = [l.event_type for l in logs]
    assert "LOGIN_FAILED" in event_types
    assert "LOGIN_SUCCESS" in event_types


def test_audit_records_never_store_passwords_or_tokens(
    client: TestClient, db_session: Session, admin_headers: dict
):
    """Verify that audit records strictly sanitize and exclude passwords and tokens."""
    # Create a user to generate audit records
    client.post("/api/v1/users", headers=admin_headers, json={
        "username": "audited_user_01",
        "email": "audit@lab.example",
        "password": "SuperSecretPass123!#",
        "role": "analyst"
    })

    # Retrieve all audit logs from database
    stmt = select(AuditLogModel)
    all_logs = db_session.scalars(stmt).all()

    for entry in all_logs:
        details_str = str(entry.details).lower()
        assert "supersecretpass123!#" not in details_str
        assert "adminsecure123!#" not in details_str
        assert "password" not in entry.details
        assert "token" not in entry.details


def test_permission_denied_audit_event_logged(
    client: TestClient, db_session: Session, viewer_headers: dict
):
    """Verify unauthorized attempts generate PERMISSION_DENIED audit events."""
    # Viewer tries to access admin-only users endpoint
    res = client.get("/api/v1/users", headers=viewer_headers)
    assert res.status_code == 403

    stmt = select(AuditLogModel).where(AuditLogModel.event_type == "PERMISSION_DENIED")
    denied_events = db_session.scalars(stmt).all()
    assert len(denied_events) > 0
    latest = denied_events[-1]
    assert latest.outcome == "FAILURE"
    assert latest.details.get("path") == "/api/v1/users"
