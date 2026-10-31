"""Automated tests for Role-Based Access Control (RBAC) and permission boundaries."""

import pytest
from starlette.testclient import TestClient
from sqlalchemy.orm import Session
from app.models.user import UserModel
from app.models.investigation import InvestigationModel


def test_unauthenticated_api_access_rejected_401(client: TestClient):
    """Verify sensitive API endpoints reject unauthenticated requests with 401."""
    assert client.get("/api/v1/investigations").status_code == 401
    assert client.get("/api/v1/users").status_code == 401
    assert client.get("/api/v1/audit-logs").status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 401


def test_administrator_can_access_users_and_audit_logs(
    client: TestClient, admin_headers: dict
):
    """Verify administrator has full access to user management and audit logs."""
    # List users
    users_res = client.get("/api/v1/users", headers=admin_headers)
    assert users_res.status_code == 200
    assert isinstance(users_res.json(), list)

    # List audit logs
    audit_res = client.get("/api/v1/audit-logs", headers=admin_headers)
    assert audit_res.status_code == 200
    assert isinstance(audit_res.json(), list)


def test_analyst_cannot_access_user_management_or_audit_logs(
    client: TestClient, analyst_headers: dict
):
    """Verify security analyst is denied access (403) to administrator-only endpoints."""
    users_res = client.get("/api/v1/users", headers=analyst_headers)
    assert users_res.status_code == 403

    audit_res = client.get("/api/v1/audit-logs", headers=analyst_headers)
    assert audit_res.status_code == 403

    # Analyst cannot create users
    create_res = client.post("/api/v1/users", headers=analyst_headers, json={
        "username": "rogue_user",
        "email": "rogue@lab.example",
        "password": "Password123!#$",
        "role": "administrator"
    })
    assert create_res.status_code == 403


def test_viewer_cannot_create_investigations(
    client: TestClient, viewer_headers: dict
):
    """Verify read-only viewer cannot create investigations (403 Forbidden)."""
    payload = {
        "id": "inv-viewer-forbidden",
        "name": "Unauthorized Campaign",
        "organization_name": "Test Org",
        "description": "Attempted creation by viewer",
        "lead_investigator": "Viewer Lead",
        "team_members": [],
        "scope": {
            "owned_domains": ["viewer.example"],
            "approved_ips": [],
            "approved_cidrs": [],
            "active_targets": []
        }
    }
    res = client.post("/api/v1/investigations", headers=viewer_headers, json=payload)
    assert res.status_code == 403
    assert "investigation.create" in res.json()["error"]["message"]


def test_analyst_and_admin_can_create_investigations(
    client: TestClient, analyst_headers: dict, admin_headers: dict
):
    """Verify analyst and administrator can create investigations (201 Created)."""
    # 1. Analyst creates an investigation
    payload_analyst = {
        "id": "inv-analyst-permitted-01",
        "name": "Analyst Authorized Campaign",
        "organization_name": "Lab Defense",
        "description": "Legitimate investigation created by analyst",
        "lead_investigator": "Analyst Lead",
        "team_members": [],
        "scope": {
            "owned_domains": ["defense.example"],
            "approved_ips": ["10.0.0.1"],
            "approved_cidrs": [],
            "active_targets": ["defense.example"]
        }
    }
    res1 = client.post("/api/v1/investigations", headers=analyst_headers, json=payload_analyst)
    assert res1.status_code == 201
    assert res1.json()["id"] == "inv-analyst-permitted-01"

    # 2. Administrator creates an investigation
    payload_admin = {
        "id": "inv-admin-permitted-01",
        "name": "Admin Authorized Campaign",
        "organization_name": "Lab Executive",
        "description": "Investigation created by admin",
        "lead_investigator": "Admin Lead",
        "team_members": [],
        "scope": {
            "owned_domains": ["exec.example"],
            "approved_ips": [],
            "approved_cidrs": [],
            "active_targets": []
        }
    }
    res2 = client.post("/api/v1/investigations", headers=admin_headers, json=payload_admin)
    assert res2.status_code == 201
    assert res2.json()["id"] == "inv-admin-permitted-01"


def test_viewer_can_read_investigations(
    client: TestClient, viewer_headers: dict, db_session: Session
):
    """Verify read-only viewer can view investigation list and details."""
    inv = InvestigationModel(
        id="inv-readable-01",
        name="Readable Campaign",
        organization_name="Target Corp",
        description="Publicly visible inside team",
        lead_investigator="Lead",
        team_members=[],
        status="active",
        owned_domains=["target.example"],
        approved_ips=[],
        approved_cidrs=[],
        active_targets=[]
    )
    db_session.add(inv)
    db_session.commit()

    # List
    list_res = client.get("/api/v1/investigations", headers=viewer_headers)
    assert list_res.status_code == 200
    ids = [i["id"] for i in list_res.json()]
    assert "inv-readable-01" in ids

    # Detail
    detail_res = client.get("/api/v1/investigations/inv-readable-01", headers=viewer_headers)
    assert detail_res.status_code == 200
    assert detail_res.json()["name"] == "Readable Campaign"


def test_nonexistent_investigation_returns_404(
    client: TestClient, viewer_headers: dict
):
    """Verify querying non-existent investigation returns clean 404."""
    res = client.get("/api/v1/investigations/nonexistent-id-9999", headers=viewer_headers)
    assert res.status_code == 404
