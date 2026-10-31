"""Automated tests for CSRF defense, cookie security, HTTP headers, and account lockout."""

import pytest
from starlette.testclient import TestClient
from sqlalchemy.orm import Session
from app.models.user import UserModel
from app.core.security import generate_csrf_token


def test_browser_security_headers_present_on_all_responses(client: TestClient):
    """Verify security headers (nosniff, DENY, etc.) are attached to HTTP responses."""
    res = client.get("/health/live")
    assert res.status_code == 200
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert res.headers["X-XSS-Protection"] == "1; mode=block"
    assert res.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_csrf_rejected_when_cookie_authenticated_without_token(
    client: TestClient, admin_user: UserModel, admin_token: str
):
    """Verify cookie-authenticated state-changing POST without CSRF token is rejected with 403."""
    res = client.post(
        "/api/v1/auth/logout",
        cookies={"footprintiq_session": admin_token}
    )
    assert res.status_code == 403
    assert "CSRF validation failed" in res.json()["error"]["message"]


def test_csrf_rejected_when_token_mismatches(
    client: TestClient, admin_user: UserModel, admin_token: str
):
    """Verify cookie-authenticated request with mismatched CSRF token returns 403."""
    res = client.post(
        "/api/v1/auth/logout",
        headers={"X-CSRF-Token": "invalid-spoofed-token-12345"},
        cookies={
            "footprintiq_session": admin_token,
            "footprintiq_csrf": "legitimate-token-67890"
        }
    )
    assert res.status_code == 403
    assert "CSRF validation failed" in res.json()["error"]["message"]


def test_csrf_succeeds_when_tokens_match(
    client: TestClient, admin_user: UserModel, admin_token: str
):
    """Verify cookie-authenticated request with matching CSRF token is accepted."""
    valid_csrf = generate_csrf_token()
    res = client.post(
        "/api/v1/auth/logout",
        headers={"X-CSRF-Token": valid_csrf},
        cookies={
            "footprintiq_session": admin_token,
            "footprintiq_csrf": valid_csrf
        }
    )
    assert res.status_code == 200
    assert "logged out successfully" in res.json()["message"].lower()


def test_bearer_token_api_requests_are_exempt_from_csrf(
    client: TestClient, admin_user: UserModel, admin_token: str
):
    """Verify API clients with Authorization: Bearer header do not require CSRF token."""
    res = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res.status_code == 200


def test_account_lockout_after_maximum_failed_attempts(
    client: TestClient, db_session: Session, admin_user: UserModel
):
    """Verify account is temporarily locked after 5 consecutive failed login attempts."""
    # Attempt 5 consecutive invalid passwords
    for i in range(5):
        res = client.post("/api/v1/auth/login", json={
            "username_or_email": admin_user.username,
            "password": f"WrongAttempt{i}!#"
        })
        assert res.status_code == 401

    # Verify user state in database
    db_session.refresh(admin_user)
    assert admin_user.failed_login_attempts >= 5
    assert admin_user.is_locked() is True

    # 6th attempt with CORRECT password must now be rejected because account is locked!
    locked_res = client.post("/api/v1/auth/login", json={
        "username_or_email": admin_user.username,
        "password": "AdminSecure123!#"
    })
    assert locked_res.status_code == 401
    assert locked_res.json()["error"]["message"] == "Invalid username or password"
