"""Automated tests for FootprintIQ Public Landing Page and Route Protection."""

import pytest
from starlette.testclient import TestClient
from sqlalchemy.orm import Session
from app.models.user import UserModel
from app.models.investigation import InvestigationModel
from app.config import get_settings


def test_public_landing_page_renders_successfully_without_auth(client: TestClient):
    """Verify the public homepage at / returns HTTP 200 without authentication."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    html = response.text

    # Branding & Core Identity
    assert "FootprintIQ" in html
    assert "Digital Footprint Investigator" in html

    # Exact required headline & supporting text
    assert "Understand Your Digital Footprint." in html
    assert "Investigate with Confidence." in html
    assert "FootprintIQ brings OSINT collection, authorized security assessments, evidence tracking, and investigation reporting into one organized workspace." in html


def test_landing_page_navigation_and_anchor_links(client: TestClient):
    """Verify navigation links point to the correct sections and routes."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    # Section Anchors
    assert 'href="#hero"' in html
    assert 'href="#features"' in html
    assert 'href="#how-it-works"' in html
    assert 'href="#security"' in html

    # Auth Routes
    assert 'href="/login"' in html
    assert "Sign In" in html


def test_landing_page_features_section_truthful_representation(client: TestClient):
    """Verify all real capabilities are represented accurately with honest caveats."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    # Real Features
    assert "Passive Reconnaissance" in html
    assert "DNS &amp; Domain Intelligence" in html
    assert "Network Assessment (Nmap)" in html
    assert "Vulnerability Assessment" in html
    assert "Evidence Management" in html
    assert "Investigation Reports" in html

    # Honest Caveats & Scope Gating
    assert "AUTHORIZED TARGETS ONLY" in html
    assert "REQUIRES GVM DAEMON" in html
    assert "CRYPTOGRAPHICALLY VERIFIED" in html
    assert "PDF &amp; GRAPHML SUPPORTED" in html


def test_landing_page_how_it_works_workflow(client: TestClient):
    """Verify the 3-step workflow and target authorization notice."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    assert "How FootprintIQ Works" in html
    assert "Define Target Scope" in html
    assert "Execute Permitted Assessments" in html
    assert "Review Evidence &amp; Report" in html
    assert "Authorization Enforcement" in html
    assert "All active scanning requires explicit target authorization records" in html


def test_landing_page_security_principles(client: TestClient):
    """Verify security & governance principles section."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    assert "Security &amp; Responsible Use Principles" in html
    assert "Role-Based Access Control" in html
    assert "Target-Scope Boundaries" in html
    assert "Evidence Provenance &amp; Auditing" in html
    assert "Cryptographic Protections" in html
    assert "Responsible Use Standard" in html


def test_landing_page_footer_and_responsible_use_statement(client: TestClient):
    """Verify footer contains responsible-use statement, version, and navigation."""
    settings = get_settings()
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    assert "FootprintIQ is an authorized cybersecurity reconnaissance" in html
    assert f"Version {settings.APP_VERSION}" in html
    assert f"Environment: {settings.APP_ENV}" in html


def test_landing_page_cta_when_public_signup_enabled(client: TestClient):
    """Verify Get Started button routes to /signup when public signup is enabled."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    assert 'href="/signup"' in html
    assert "Get Started" in html


def test_landing_page_cta_when_public_signup_disabled(client: TestClient, monkeypatch):
    """Verify Get Started button safely routes to /login when public signup is disabled."""
    monkeypatch.setattr("app.api.web_dashboard.settings.ALLOW_PUBLIC_SIGNUP", False)

    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    # When signup is disabled, public signup link should not be present
    assert 'href="/signup"' not in html
    assert 'href="/login"' in html


def test_public_landing_does_not_leak_private_investigations(client: TestClient, db_session: Session):
    """Verify that unauthenticated visitors to / cannot see private customer/investigation records."""
    secret_inv = InvestigationModel(
        id="inv-classified-999",
        name="Top Secret Client Assessment",
        organization_name="Confidential Defense Contractor",
        description="Highly sensitive engagement data.",
        lead_investigator="Director John",
        status="active",
        owned_domains=["defense.classified"],
    )
    db_session.add(secret_inv)
    db_session.commit()

    # Public landing page must NEVER disclose this
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    assert "Top Secret Client Assessment" not in html
    assert "Confidential Defense Contractor" not in html
    assert "inv-classified-999" not in html
    assert "defense.classified" not in html


def test_protected_dashboard_redirects_unauthenticated_visitor(client: TestClient):
    """Verify /dashboard requires authentication and redirects unauthenticated users."""
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 303
    assert "/login?next=/dashboard" in response.headers["location"]


def test_protected_apis_reject_unauthenticated_visitor(client: TestClient):
    """Verify private APIs reject unauthenticated requests with 401."""
    assert client.get("/api/v1/investigations").status_code == 401
    assert client.get("/api/v1/users").status_code == 401
    assert client.get("/api/v1/audit-logs").status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 401


def test_public_static_assets_load_correctly(client: TestClient):
    """Verify static assets like CSS and JS are publicly served."""
    css_res = client.get("/static/css/main.css")
    assert css_res.status_code == 200
    assert "text/css" in css_res.headers["content-type"]

    js_res = client.get("/static/js/htmx.min.js")
    assert js_res.status_code == 200

@pytest.mark.parametrize("path", [
    "/dashboard", "/investigations", "/investigations/example",
    "/findings", "/scans", "/evidence", "/audit",
    "/admin/authorizations", "/admin/tools",
])
def test_operational_pages_redirect_anonymous_users(client: TestClient, path: str):
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login?next=")


def test_unknown_page_remains_a_real_404(client: TestClient):
    response = client.get("/this-page-does-not-exist", follow_redirects=False)
    assert response.status_code == 404
