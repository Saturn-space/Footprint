"""Integration tests for Nmap REST API endpoints and RBAC enforcement."""

import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.recon import TargetAuthorizationModel, EvidenceModel
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel, ScanFindingPortModel
from app.services.active.runner import NmapRunner


def test_get_nmap_status_unauthenticated(client):
    """Status endpoint rejects unauthenticated access with 401."""
    resp = client.get("/api/v1/tools/nmap/status")
    assert resp.status_code == 401


def test_get_nmap_status_authenticated(client, viewer_headers):
    """Status endpoint returns tool availability to authenticated users."""
    with patch("app.services.active.nmap_detector.NmapDetector.check_availability") as mock_check:
        mock_check.return_value = {
            "is_available": True,
            "version": "7.98",
            "platform": "windows",
            "binary_name": "nmap.exe",
            "diagnostic_code": "READY",
            "message": "Nmap ready",
            "capabilities": ["tcp_connect_scan"],
            "error": None,
        }
        resp = client.get("/api/v1/tools/nmap/status", headers=viewer_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_available"] is True
        assert data["version"] == "7.98"
        assert data["diagnostic_code"] == "READY"


def test_get_nmap_profiles_authenticated(client, viewer_headers):
    """Profiles endpoint returns vetted scan profiles."""
    resp = client.get("/api/v1/nmap/profiles", headers=viewer_headers)
    assert resp.status_code == 200
    profiles = resp.json()
    assert len(profiles) >= 3
    profile_ids = [p["id"] for p in profiles]
    assert "basic_tcp" in profile_ids
    assert "service_inventory" in profile_ids
    assert "quick_ping" in profile_ids


def test_dispatch_scan_analyst_forbidden(client, analyst_headers, db_session: Session):
    """Users without recon.active (e.g. analyst) are rejected with 403."""
    inv = InvestigationModel(
        id=f"inv-rbac-{uuid.uuid4().hex[:8]}",
        name="RBAC Test Campaign",
        description="Test campaign description",
        organization_name="Test Org",
        lead_investigator="Analyst",
        status="active",
        active_scanning_enabled=True,
    )
    db_session.add(inv)
    db_session.commit()

    resp = client.post(
        f"/api/v1/investigations/{inv.id}/nmap-scans",
        json={"target": "127.0.0.1", "profile_id": "basic_tcp"},
        headers=analyst_headers,
    )
    assert resp.status_code == 403


def test_dispatch_scan_missing_authorization(client, admin_headers, db_session: Session):
    """Scan request on target without authorization is rejected with 403."""
    inv = InvestigationModel(
        id=f"inv-unauth-{uuid.uuid4().hex[:8]}",
        name="No Authz Campaign",
        description="Test campaign description",
        organization_name="Test Org",
        lead_investigator="Admin",
        status="active",
        active_targets=["127.0.0.1"],
        active_scanning_enabled=True,
    )
    db_session.add(inv)
    db_session.commit()

    resp = client.post(
        f"/api/v1/investigations/{inv.id}/nmap-scans",
        json={"target": "127.0.0.1", "profile_id": "basic_tcp"},
        headers=admin_headers,
    )
    assert resp.status_code == 403


def test_dispatch_scan_disabled_investigation(client, admin_headers, db_session: Session):
    """Scan request rejected if investigation active_scanning_enabled is False."""
    inv = InvestigationModel(
        id=f"inv-dis-{uuid.uuid4().hex[:8]}",
        name="Disabled Active Scanning",
        description="Test campaign description",
        organization_name="Test Org",
        lead_investigator="Admin",
        status="active",
        active_targets=["127.0.0.1"],
        active_scanning_enabled=False,  # Disabled
    )
    db_session.add(inv)
    db_session.commit()

    resp = client.post(
        f"/api/v1/investigations/{inv.id}/nmap-scans",
        json={"target": "127.0.0.1", "profile_id": "basic_tcp"},
        headers=admin_headers,
    )
    assert resp.status_code == 403


def test_dispatch_scan_successful(client, admin_headers, db_session: Session):
    """Administrator dispatches scan against authorized target successfully."""
    inv = InvestigationModel(
        id=f"inv-succ-{uuid.uuid4().hex[:8]}",
        name="Authorized Scan Campaign",
        description="Test campaign description",
        organization_name="Test Org",
        lead_investigator="Admin",
        status="active",
        active_targets=["127.0.0.1"],
        active_scanning_enabled=True,
    )
    db_session.add(inv)

    now = datetime.now(timezone.utc)
    authz = TargetAuthorizationModel(
        id=f"authz-{uuid.uuid4().hex[:8]}",
        investigation_id=inv.id,
        target="127.0.0.1",
        target_type="IP",
        allowed_operations=["SCAN_ACTIVE"],
        authorization_reference="AUTH-DISPATCH-01",
        approved_by="SecurityOfficer",
        valid_from=now - timedelta(hours=1),
        valid_to=now + timedelta(hours=24),
        is_revoked=False,
    )
    db_session.add(authz)
    db_session.commit()

    with patch("asyncio.create_task") as mock_task:
        resp = client.post(
            f"/api/v1/investigations/{inv.id}/nmap-scans",
            json={"target": "127.0.0.1", "profile_id": "basic_tcp"},
            headers=admin_headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["target"] == "127.0.0.1"
        assert data["scan_profile"] == "basic_tcp"
        assert data["status"] == "QUEUED"
        mock_task.assert_called_once()


def test_list_and_get_scan_job(client, viewer_headers, db_session: Session):
    """Viewer can list and retrieve scan job metadata."""
    inv = InvestigationModel(
        id=f"inv-list-{uuid.uuid4().hex[:8]}",
        name="List Test Campaign",
        description="Test campaign description",
        organization_name="Test Org",
        lead_investigator="Viewer",
        status="active",
    )
    db_session.add(inv)

    job = ActiveScanJobModel(
        id=f"scan-{uuid.uuid4().hex[:8]}",
        investigation_id=inv.id,
        requested_by="admin",
        target="127.0.0.1",
        resolved_ips=["127.0.0.1"],
        scan_profile="basic_tcp",
        status="COMPLETED",
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(job)
    db_session.commit()

    # List
    list_resp = client.get(f"/api/v1/investigations/{inv.id}/nmap-scans", headers=viewer_headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1

    # Get by ID
    get_resp = client.get(f"/api/v1/nmap-scans/{job.id}", headers=viewer_headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == job.id


def test_get_scan_results(client, viewer_headers, db_session: Session):
    """Retrieve normalized findings (hosts and ports) for a completed scan."""
    inv = InvestigationModel(
        id=f"inv-res-{uuid.uuid4().hex[:8]}",
        name="Results Campaign",
        description="Test campaign description",
        organization_name="Test Org",
        lead_investigator="Viewer",
        status="active",
    )
    db_session.add(inv)

    job = ActiveScanJobModel(
        id=f"scan-res-{uuid.uuid4().hex[:8]}",
        investigation_id=inv.id,
        requested_by="admin",
        target="127.0.0.1",
        resolved_ips=["127.0.0.1"],
        scan_profile="basic_tcp",
        status="COMPLETED",
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(job)

    host = ScanFindingHostModel(
        id=f"host-{uuid.uuid4().hex[:8]}",
        investigation_id=inv.id,
        job_id=job.id,
        address="127.0.0.1",
        address_type="ipv4",
        status="up",
        hostname="localhost",
    )
    db_session.add(host)

    port = ScanFindingPortModel(
        id=f"port-{uuid.uuid4().hex[:8]}",
        host_id=host.id,
        job_id=job.id,
        protocol="tcp",
        port_number=80,
        state="open",
        service_name="http",
    )
    db_session.add(port)
    db_session.commit()

    resp = client.get(f"/api/v1/nmap-scans/{job.id}/results", headers=viewer_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_hosts"] == 1
    assert data["total_ports"] == 1
    assert data["hosts"][0]["address"] == "127.0.0.1"
    assert data["hosts"][0]["ports"][0]["port_number"] == 80


def test_cancel_scan_job_api(client, admin_headers, db_session: Session):
    """Cancel a running scan job via API."""
    inv = InvestigationModel(
        id=f"inv-canc-{uuid.uuid4().hex[:8]}",
        name="Cancel Campaign",
        description="Test campaign description",
        organization_name="Test Org",
        lead_investigator="Admin",
        status="active",
    )
    db_session.add(inv)

    job = ActiveScanJobModel(
        id=f"scan-canc-{uuid.uuid4().hex[:8]}",
        investigation_id=inv.id,
        requested_by="admin",
        target="127.0.0.1",
        resolved_ips=["127.0.0.1"],
        scan_profile="basic_tcp",
        status="RUNNING",
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(job)
    db_session.commit()

    resp = client.post(
        f"/api/v1/nmap-scans/{job.id}/cancel",
        json={"reason": "User abort requested"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "CANCELLED"
