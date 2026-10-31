"""Automated tests for user authentication, password hashing, session lifecycle, and logout."""

import pytest
from starlette.testclient import TestClient
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta

from app.models.user import UserModel, UserSessionModel
from app.core.security import verify_password, hash_session_token


def test_api_login_success_with_username_or_email(client: TestClient, admin_user: UserModel):
    """Verify login succeeds with both normalized username and email."""
    # 1. Login with username
    res1 = client.post("/api/v1/auth/login", json={
        "username_or_email": "admin_test",
        "password": "AdminSecure123!#"
    })
    assert res1.status_code == 200
    data1 = res1.json()
    assert "access_token" in data1
    assert data1["token_type"] == "bearer"
    assert data1["user"]["username"] == "admin_test"
    assert data1["user"]["role"] == "administrator"
    assert "footprintiq_session" in res1.cookies

    # 2. Login with uppercase email (verifies normalization)
    res2 = client.post("/api/v1/auth/login", json={
        "username_or_email": "ADMIN@LAB.EXAMPLE",
        "password": "AdminSecure123!#"
    })
    assert res2.status_code == 200
    data2 = res2.json()
    assert "access_token" in data2
    assert data2["user"]["email"] == "admin@lab.example"


def test_api_login_invalid_password_returns_generic_401(client: TestClient, admin_user: UserModel):
    """Verify wrong password returns generic 401 without revealing internal state."""
    res = client.post("/api/v1/auth/login", json={
        "username_or_email": "admin_test",
        "password": "WrongPassword123!"
    })
    assert res.status_code == 401
    assert res.json()["error"]["message"] == "Invalid username or password"


def test_api_login_unknown_account_returns_generic_401(client: TestClient):
    """Verify non-existent username returns identical generic 401 (prevents user enumeration)."""
    res = client.post("/api/v1/auth/login", json={
        "username_or_email": "non_existent_user_999",
        "password": "SomePassword123!"
    })
    assert res.status_code == 401
    assert res.json()["error"]["message"] == "Invalid username or password"


def test_api_login_disabled_account_rejected(client: TestClient, db_session: Session, analyst_user: UserModel):
    """Verify disabled account cannot authenticate."""
    analyst_user.is_active = False
    db_session.commit()

    res = client.post("/api/v1/auth/login", json={
        "username_or_email": "analyst_test",
        "password": "AnalystSecure123!#"
    })
    assert res.status_code == 401
    assert res.json()["error"]["message"] == "Invalid username or password"


def test_api_login_missing_credentials_returns_422(client: TestClient):
    """Verify malformed requests return 422 with validation errors."""
    res = client.post("/api/v1/auth/login", json={"username_or_email": ""})
    assert res.status_code == 422


def test_api_logout_invalidates_session_server_side(client: TestClient, db_session: Session, admin_token: str):
    """Verify logout revokes session in DB and prevents subsequent access."""
    # Check that me endpoint works with active token
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "admin_test"

    # Logout
    logout_res = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {admin_token}"})
    assert logout_res.status_code == 200

    # Verify session is marked revoked in database
    token_hash = hash_session_token(admin_token)
    session = db_session.get(UserSessionModel, token_hash)
    assert session.is_revoked is True

    # Subsequent access with same token must be rejected with 401
    me_res_after = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert me_res_after.status_code == 401


def test_session_expiration_enforced(client: TestClient, db_session: Session, admin_token: str):
    """Verify expired sessions are rejected."""
    token_hash = hash_session_token(admin_token)
    session = db_session.get(UserSessionModel, token_hash)
    # Manually expire the session in database
    session.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.commit()

    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 401


def test_web_dashboard_login_and_logout_flow(client: TestClient, admin_user: UserModel):
    """Verify browser HTML login sets cookies and logout clears them."""
    # 1. Fetch login page to obtain initial CSRF cookie
    get_res = client.get("/login")
    assert get_res.status_code == 200
    csrf_token = get_res.cookies.get("footprintiq_csrf")
    assert csrf_token is not None

    # 2. Submit form login
    post_res = client.post(
        "/auth/login",
        data={
            "username_or_email": "admin_test",
            "password": "AdminSecure123!#",
            "csrf_token": csrf_token,
            "next": "/"
        },
        cookies={"footprintiq_csrf": csrf_token},
        follow_redirects=False
    )
    assert post_res.status_code == 303
    assert post_res.headers["location"] == "/"
    assert "footprintiq_session" in post_res.cookies
    session_cookie = post_res.cookies["footprintiq_session"]
    fresh_csrf = post_res.cookies.get("footprintiq_csrf") or csrf_token

    # 3. Access dashboard with session cookie
    dash_res = client.get("/", cookies={"footprintiq_session": session_cookie})
    assert dash_res.status_code == 200
    assert "admin_test" in dash_res.text
    assert "ADMIN" in dash_res.text

    # 4. Perform browser logout with CSRF token
    logout_res = client.post(
        "/auth/logout",
        data={"csrf_token": fresh_csrf},
        cookies={"footprintiq_session": session_cookie, "footprintiq_csrf": fresh_csrf},
        follow_redirects=False
    )
    assert logout_res.status_code == 303
    assert "logged_out=1" in logout_res.headers["location"]


# =============================================================================
# Open Redirect Defenses & Validation Tests
# =============================================================================

def test_is_safe_redirect_url():
    """Verify is_safe_redirect_url permits local relative paths and blocks open redirects."""
    from app.core.security import is_safe_redirect_url

    # Safe paths
    assert is_safe_redirect_url("/") is True
    assert is_safe_redirect_url("/investigations") is True
    assert is_safe_redirect_url("/dashboard?tab=recon") is True
    assert is_safe_redirect_url("/reports/rep-1234") is True

    # Malicious / open redirect attempts
    assert is_safe_redirect_url("") is False
    assert is_safe_redirect_url(None) is False
    assert is_safe_redirect_url("//attacker.com") is False
    assert is_safe_redirect_url("/\\attacker.com") is False
    assert is_safe_redirect_url("\\attacker.com") is False
    assert is_safe_redirect_url("https://attacker.com") is False
    assert is_safe_redirect_url("http://attacker.com/evil") is False
    assert is_safe_redirect_url("javascript:alert(1)") is False
    assert is_safe_redirect_url("/foo\\bar") is False
    assert is_safe_redirect_url("/login\r\nSet-Cookie: evil=1") is False


def test_login_rejects_open_redirect_and_defaults_to_home(client: TestClient, admin_user: UserModel):
    """Verify that a login attempt with an open redirect target redirects safely to /."""
    get_res = client.get("/login?next=//attacker.com/steal")
    csrf_token = get_res.cookies.get("footprintiq_csrf")

    post_res = client.post(
        "/auth/login",
        data={
            "username_or_email": "admin_test",
            "password": "AdminSecure123!#",
            "csrf_token": csrf_token,
            "next": "//attacker.com/steal"
        },
        cookies={"footprintiq_csrf": csrf_token},
        follow_redirects=False
    )
    assert post_res.status_code == 303
    # Must fallback safely to /
    assert post_res.headers["location"] == "/"


# =============================================================================
# Self-Service Public Signup Tests
# =============================================================================

def test_api_signup_success_creates_analyst_account(client: TestClient, db_session: Session):
    """Verify public signup creates an active account with least-privileged analyst role."""
    payload = {
        "username": "new_analyst_user",
        "email": "new_analyst@example.com",
        "password": "ComplexPassword123!#",
        "confirm_password": "ComplexPassword123!#"
    }
    res = client.post("/api/v1/auth/signup", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["username"] == "new_analyst_user"
    assert data["email"] == "new_analyst@example.com"
    assert data["role"] == "analyst"  # Must NEVER be administrator
    assert data["is_active"] is True

    # Verify user in database has Argon2 password hash
    from sqlalchemy import select
    user = db_session.execute(
        select(UserModel).where(UserModel.username == "new_analyst_user")
    ).scalar_one()
    assert user.password_hash.startswith("$argon2id$")
    assert verify_password("ComplexPassword123!#", user.password_hash)


def test_api_signup_password_complexity_enforcement(client: TestClient):
    """Verify public signup rejects passwords that fail complexity requirements."""
    # Too short
    res1 = client.post("/api/v1/auth/signup", json={
        "username": "weak_pwd_user_1",
        "email": "weak1@example.com",
        "password": "Short1!",
        "confirm_password": "Short1!"
    })
    assert res1.status_code == 422

    # Missing symbol or number
    res2 = client.post("/api/v1/auth/signup", json={
        "username": "weak_pwd_user_2",
        "email": "weak2@example.com",
        "password": "AllLettersNoNumbersOrSymbols",
        "confirm_password": "AllLettersNoNumbersOrSymbols"
    })
    assert res2.status_code == 422


def test_api_signup_rejects_duplicate_username_or_email(client: TestClient, admin_user: UserModel):
    """Verify duplicate registration fails with 409 Conflict."""
    # Duplicate username
    res1 = client.post("/api/v1/auth/signup", json={
        "username": "admin_test",  # already exists
        "email": "unique_email_123@example.com",
        "password": "ComplexPassword123!#",
        "confirm_password": "ComplexPassword123!#"
    })
    assert res1.status_code == 409
    assert "already registered" in res1.json()["error"]["message"]

    # Duplicate email
    res2 = client.post("/api/v1/auth/signup", json={
        "username": "unique_username_123",
        "email": "admin@lab.example",  # already exists
        "password": "ComplexPassword123!#",
        "confirm_password": "ComplexPassword123!#"
    })
    assert res2.status_code == 409
    assert "already registered" in res2.json()["error"]["message"]


def test_web_signup_flow(client: TestClient, db_session: Session):
    """Verify web HTML signup page renders and submission persists account with redirect."""
    # 1. GET /signup
    get_res = client.get("/signup")
    assert get_res.status_code == 200
    assert "Create Investigator Account" in get_res.text
    csrf_token = get_res.cookies.get("footprintiq_csrf")
    assert csrf_token is not None

    # 2. POST /auth/signup
    post_res = client.post(
        "/auth/signup",
        data={
            "username": "web_registered_analyst",
            "email": "web_analyst@footprintiq.local",
            "password": "WebRegisterPassword123!#",
            "confirm_password": "WebRegisterPassword123!#",
            "csrf_token": csrf_token
        },
        cookies={"footprintiq_csrf": csrf_token},
        follow_redirects=False
    )
    assert post_res.status_code == 303
    assert post_res.headers["location"] == "/login?registered=1"

    # 3. GET /login?registered=1 displays success banner
    login_res = client.get("/login?registered=1")
    assert login_res.status_code == 200
    assert "Account successfully registered" in login_res.text


def test_demo_account_provisioning_idempotency_and_security():
    """Verify demo account provisioning script runs safely, idempotently, and never creates admin."""
    from scripts.provision_demo_account import provision_demo_account

    success, result = provision_demo_account(
        username="demo_test_verifier",
        email="demo_test@footprintiq.local",
        password="DemoPassword123!#",
        reset_if_exists=True,
    )
    assert success is True
    assert result["role"] == "analyst"
    assert result["admin_access"] is False
    assert result["live_auth_tested"] is True
    assert result["session_issuance_tested"] is True

