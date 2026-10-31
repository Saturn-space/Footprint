"""Automated tests for administrative target authorization REST API endpoints."""

import pytest
from datetime import datetime, timezone, timedelta
from app.models.investigation import InvestigationModel


@pytest.fixture
def test_investigation(db_session):
    inv = InvestigationModel(
        id="inv-authz-api-test",
        name="Target Authz API Campaign",
        organization_name="Apex Corp",
        description="Testing authorization endpoints",
        lead_investigator="Lead",
        owned_domains=["apexcorp.com"],
        approved_ips=[],
        approved_cidrs=[],
        active_targets=["apexcorp.com"],
    )
    db_session.add(inv)
    db_session.commit()
    return inv


def test_create_target_authorization_endpoint(client, test_investigation, admin_headers):
    now = datetime.now(timezone.utc)
    valid_to = now + timedelta(days=60)

    payload = {
        "target": "apexcorp.com",
        "target_type": "DOMAIN",
        "allowed_operations": ["RECON_PASSIVE"],
        "authorization_reference": "REF-CISO-2026-009",
        "approved_by": "Chief Security Officer",
        "valid_to": valid_to.isoformat(),
        "notes": "Authorized passive reconnaissance campaign",
    }

    resp = client.post(
        f"/api/v1/investigations/{test_investigation.id}/authorizations",
        json=payload,
        headers=admin_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["target"] == "apexcorp.com"
    assert data["authorization_reference"] == "REF-CISO-2026-009"
    assert data["is_revoked"] is False
    authz_id = data["id"]

    # 2. List authorizations
    list_resp = client.get(
        f"/api/v1/investigations/{test_investigation.id}/authorizations",
        headers=admin_headers,
    )
    assert list_resp.status_code == 200
    authz_list = list_resp.json()
    assert len(authz_list) >= 1
    assert any(a["id"] == authz_id for a in authz_list)

    # 3. Revoke authorization
    del_resp = client.delete(
        f"/api/v1/investigations/{test_investigation.id}/authorizations/{authz_id}",
        headers=admin_headers,
    )
    assert del_resp.status_code == 200

    # 4. Verify status is revoked in subsequent list
    list_resp2 = client.get(
        f"/api/v1/investigations/{test_investigation.id}/authorizations",
        headers=admin_headers,
    )
    revoked_rec = [a for a in list_resp2.json() if a["id"] == authz_id][0]
    assert revoked_rec["is_revoked"] is True


def test_viewer_cannot_create_target_authorization(client, test_investigation, viewer_headers):
    now = datetime.now(timezone.utc)
    payload = {
        "target": "apexcorp.com",
        "target_type": "DOMAIN",
        "allowed_operations": ["RECON_PASSIVE"],
        "authorization_reference": "REF-UNAUTH",
        "valid_to": (now + timedelta(days=10)).isoformat(),
    }
    resp = client.post(
        f"/api/v1/investigations/{test_investigation.id}/authorizations",
        json=payload,
        headers=viewer_headers,
    )
    # Viewers do not hold scope.manage permission -> 403 Forbidden
    assert resp.status_code == 403
