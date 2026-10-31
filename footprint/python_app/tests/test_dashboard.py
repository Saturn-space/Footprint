"""Tests for Jinja2 dashboard rendering and HTMX components."""

from starlette.testclient import TestClient
from sqlalchemy.orm import Session
from app.models.user import UserModel
from app.models.investigation import InvestigationModel
from app.core.auth import create_user_session


def test_dashboard_unauthenticated_redirects_to_login(client: TestClient):
    """Verify unauthenticated access to /dashboard is safely redirected to login."""
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 303
    assert "/login" in response.headers["location"]


def test_dashboard_renders_successfully(client: TestClient, db_session: Session, analyst_user: UserModel):
    """Requirement 5: Verify dashboard renders initial HTML shell with honest empty state for authenticated user."""
    raw_token, session = create_user_session(db=db_session, user=analyst_user)
    response = client.get("/dashboard", cookies={"footprintiq_session": raw_token})
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    html = response.text

    assert "FootprintIQ" in html
    assert "Total Investigations" in html
    assert "No Investigations Available" in html


def test_dashboard_displays_investigations_when_present(client: TestClient, db_session: Session, analyst_user: UserModel):
    """Verify dashboard table dynamically renders persisted investigation records."""
    raw_token, session = create_user_session(db=db_session, user=analyst_user)
    inv = InvestigationModel(
        id="inv-northstar-01",
        name="NorthStar Analytics Lab Audit",
        organization_name="NorthStar Analytics Lab",
        description="Authorized lab reconnaissance baseline.",
        lead_investigator="Asip Ali",
        team_members=["Mohan Prasad"],
        status="active",
        owned_domains=["lab.example"],
        approved_ips=["192.168.56.102"],
        approved_cidrs=["192.168.56.0/24"],
        active_targets=["192.168.56.102"]
    )
    db_session.add(inv)
    db_session.commit()

    response = client.get("/dashboard", cookies={"footprintiq_session": raw_token})
    assert response.status_code == 200
    html = response.text

    assert "inv-northstar-01" in html
    assert "NorthStar Analytics Lab Audit" in html
    assert "lab.example" in html
    assert "ACTIVE" in html


def test_htmx_health_badge_component(client: TestClient):
    """Verify HTMX endpoint returns HTML component with live database connectivity status."""
    response = client.get("/health/badge")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    html = response.text
    assert "Database Connected" in html
