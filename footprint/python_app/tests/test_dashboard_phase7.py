"""Comprehensive tests for Phase 7 Dashboard, Reporting, and Admin Workflows."""

from starlette.testclient import TestClient
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta

from app.models.investigation import InvestigationModel
from app.models.user import UserModel
from app.models.recon import TargetAuthorizationModel, EntityModel, EvidenceModel
from app.models.vulnerability import VulnerabilityFindingModel, VulnerabilityScanJobModel
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel, ScanFindingPortModel
from app.models.audit import AuditLogModel
from app.core.security import generate_csrf_token
from app.config import get_settings

settings = get_settings()


def test_dashboard_metrics_and_status(authenticated_client: TestClient, db_session: Session, analyst_user: UserModel):
    """Verify overview dashboard dynamically renders genuine database metrics."""
    from app.core.auth import create_user_session
    raw_token, session = create_user_session(db=db_session, user=analyst_user)

    inv = InvestigationModel(
        id="inv-dash-01",
        name="Dashboard Verification Lab",
        organization_name="NorthStar",
        description="Dashboard test campaign.",
        lead_investigator="Lead Analyst",
        status="active",
        owned_domains=["lab.example"],
    )
    db_session.add(inv)
    db_session.commit()

    response = authenticated_client.get("/dashboard", cookies={"footprintiq_session": raw_token})
    assert response.status_code == 200
    html = response.text
    assert "FootprintIQ" in html
    assert "Total Investigations" in html
    assert "Dashboard Verification Lab" in html
    assert "inv-dash-01" in html
    assert "ACTIVE" in html


def test_investigations_page_filtering(authenticated_client: TestClient, db_session: Session):
    """Verify investigations listing with keyword search and status filter."""
    inv1 = InvestigationModel(
        id="inv-filter-01",
        name="Alpha Scope Assessment",
        organization_name="Alpha Corp",
        description="First campaign.",
        lead_investigator="Alice",
        status="active",
    )
    inv2 = InvestigationModel(
        id="inv-filter-02",
        name="Beta Vulnerability Audit",
        organization_name="Beta Corp",
        description="Second campaign.",
        lead_investigator="Bob",
        status="completed",
    )
    db_session.add_all([inv1, inv2])
    db_session.commit()

    # Query all
    res_all = authenticated_client.get("/investigations")
    assert res_all.status_code == 200
    assert "Alpha Scope Assessment" in res_all.text
    assert "Beta Vulnerability Audit" in res_all.text

    # Search keyword
    res_search = authenticated_client.get("/investigations?q=Alpha")
    assert res_search.status_code == 200
    assert "Alpha Scope Assessment" in res_search.text
    assert "Beta Vulnerability Audit" not in res_search.text

    # Status filter
    res_status = authenticated_client.get("/investigations?status=completed")
    assert res_status.status_code == 200
    assert "Beta Vulnerability Audit" in res_status.text
    assert "Alpha Scope Assessment" not in res_status.text


def test_investigation_creation_form(authenticated_client: TestClient, db_session: Session):
    """Verify POST /investigations creates a new campaign with CSRF defense."""
    csrf_token = generate_csrf_token()
    authenticated_client.cookies.set(settings.CSRF_COOKIE_NAME, csrf_token)

    payload = {
        "name": "New Cyber Lab Audit",
        "organization_name": "Lab Organization",
        "description": "Comprehensive scope investigation.",
        "lead_investigator": "Security Researcher",
        "owned_domains": "lab.example, target.lab",
        "approved_ips": "192.168.56.102",
        "approved_cidrs": "192.168.56.0/24",
        "active_targets": "192.168.56.102",
        "active_scanning_enabled": "true",
        "authorization_reference": "TICKET-FORM-001",
        "csrf_token": csrf_token,
    }

    response = authenticated_client.post("/investigations", data=payload, follow_redirects=False)
    assert response.status_code == 303
    redirect_url = response.headers["location"]
    assert redirect_url.startswith("/investigations/inv-")

    # Verify record in DB
    created = db_session.query(InvestigationModel).filter_by(name="New Cyber Lab Audit").first()
    assert created is not None
    assert created.organization_name == "Lab Organization"
    assert "lab.example" in created.owned_domains
    assert created.active_scanning_enabled is True


def test_investigation_creation_csrf_rejection(authenticated_client: TestClient):
    """Verify investigation creation without valid CSRF is rejected."""
    payload = {
        "name": "Unauthorized Campaign",
        "organization_name": "Victim Org",
        "description": "Attempting CSRF bypass.",
        "lead_investigator": "Attacker",
        "csrf_token": "invalid-csrf-token",
    }
    response = authenticated_client.post("/investigations", data=payload)
    assert response.status_code == 403


def test_investigation_detail_workspace_renders(authenticated_client: TestClient, db_session: Session):
    """Verify investigation workspace renders with all tabs, entities, ports, and score."""
    inv = InvestigationModel(
        id="inv-detail-test",
        name="Detailed Workspace Test",
        organization_name="Test Org",
        description="Testing all tabs and components.",
        lead_investigator="Lead Analyst",
        status="active",
        owned_domains=["test.example"],
        active_targets=["10.0.0.5"],
    )
    db_session.add(inv)

    entity = EntityModel(
        id="ent-detail-01",
        investigation_id="inv-detail-test",
        entity_type="Subdomain",
        canonical_value="vpn.test.example",
        original_value="vpn.test.example",
        evidence_ids=[],
    )
    db_session.add(entity)

    vuln_job = VulnerabilityScanJobModel(
        id="gvm-detail-01",
        investigation_id="inv-detail-test",
        requested_by="usr-admin",
        target="10.0.0.5",
        profile_id="openvas-basic",
        scan_config_id="daba56c8-73ec-11df-a475-002264764ceb",
        status="COMPLETED",
    )
    db_session.add(vuln_job)

    vuln = VulnerabilityFindingModel(
        id="vf-detail-01",
        investigation_id="inv-detail-test",
        job_id="gvm-detail-01",
        host="10.0.0.5",
        port=443,
        name="Weak TLS 1.0 Cipher Suite",
        severity="medium",
        cvss_score=5.0,
        cve_references=["CVE-2015-4000"],
    )
    db_session.add(vuln)
    db_session.commit()

    response = authenticated_client.get(f"/investigations/{inv.id}")
    assert response.status_code == 200
    html = response.text

    assert "Detailed Workspace Test" in html
    assert "Overview &amp; Scope" in html
    assert "Target Authorizations" in html
    assert "Passive Recon &amp; Entities" in html
    assert "vpn.test.example" in html
    assert "Weak TLS 1.0 Cipher Suite" in html
    assert "Download PDF Dossier" in html


def test_findings_page_matrix(authenticated_client: TestClient, db_session: Session):
    """Verify unified findings matrix page filters by severity."""
    inv = InvestigationModel(
        id="inv-findings-01",
        name="Findings Test Campaign",
        organization_name="Findings Org",
        description="Findings matrix testing.",
        lead_investigator="Analyst",
        status="active",
    )
    db_session.add(inv)

    vuln_job = VulnerabilityScanJobModel(
        id="job-vuln-f01",
        investigation_id="inv-findings-01",
        requested_by="admin",
        target="192.168.1.1",
        profile_id="openvas-basic",
        scan_config_id="config-uuid",
        status="COMPLETED",
    )
    db_session.add(vuln_job)

    v1 = VulnerabilityFindingModel(
        id="vf-crit-01",
        investigation_id="inv-findings-01",
        job_id="job-vuln-f01",
        host="192.168.1.1",
        name="Critical Remote Code Execution",
        severity="critical",
        cvss_score=9.8,
    )
    v2 = VulnerabilityFindingModel(
        id="vf-low-01",
        investigation_id="inv-findings-01",
        job_id="job-vuln-f01",
        host="192.168.1.1",
        name="ICMP Timestamp Disclosure",
        severity="low",
        cvss_score=2.0,
    )
    db_session.add_all([v1, v2])
    db_session.commit()

    # Query all
    res_all = authenticated_client.get("/findings")
    assert res_all.status_code == 200
    assert "Critical Remote Code Execution" in res_all.text
    assert "ICMP Timestamp Disclosure" in res_all.text

    # Filter critical
    res_crit = authenticated_client.get("/findings?severity=critical")
    assert res_crit.status_code == 200
    assert "Critical Remote Code Execution" in res_crit.text
    assert "ICMP Timestamp Disclosure" not in res_crit.text


def test_scans_monitor_page(authenticated_client: TestClient, db_session: Session):
    """Verify scans monitor lists passive, active, and vulnerability jobs."""
    inv = InvestigationModel(
        id="inv-scans-mon-01",
        name="Scans Monitor Scope",
        organization_name="Org",
        description="Job monitoring test.",
        lead_investigator="Lead",
        status="active",
    )
    db_session.add(inv)

    vj = VulnerabilityScanJobModel(
        id="gvm-job-mon-01",
        investigation_id="inv-scans-mon-01",
        requested_by="admin",
        target="10.0.0.1",
        profile_id="openvas-basic",
        scan_config_id="config-uuid",
        status="RUNNING",
        progress=45,
    )
    db_session.add(vj)
    db_session.commit()

    response = authenticated_client.get("/scans")
    assert response.status_code == 200
    html = response.text
    assert "Reconnaissance &amp; Scan Execution Monitor" in html
    assert "gvm-job-mon-01" in html
    assert "45%" in html


def test_evidence_ledger_page(authenticated_client: TestClient, db_session: Session):
    """Verify forensic evidence page renders records with SHA-256 hashes."""
    inv = InvestigationModel(
        id="inv-ev-page-01",
        name="Evidence Page Scope",
        organization_name="Org",
        description="Evidence page test.",
        lead_investigator="Lead",
        status="active",
    )
    db_session.add(inv)

    ev = EvidenceModel(
        id="ev-sha-test-01",
        investigation_id="inv-ev-page-01",
        source_type="rdap_collector",
        source_name="RDAP Registrar Collector",
        target="lab.example",
        content_hash="3305ff336b1246457036e29c35fff93b0b5e8caff48542242f0ec298e6964a8f",
        content_size_bytes=4096,
    )
    db_session.add(ev)
    db_session.commit()

    response = authenticated_client.get("/evidence")
    assert response.status_code == 200
    html = response.text
    assert "Forensic Evidence Ledger" in html
    assert "ev-sha-test-01" in html
    assert "3305ff336b1246457036e29c35fff93b0b5e8caff48542242f0ec298e6964a8f" in html


def test_audit_trail_page(admin_client: TestClient, db_session: Session):
    """Verify security audit page renders chronological audit logs."""
    log = AuditLogModel(
        id="audit-log-01",
        event_type="TARGET_AUTHORIZATION_GRANTED",
        actor_id="sec-officer",
        outcome="SUCCESS",
        ip_address="127.0.0.1",
        details={"target": "10.0.0.1", "operation": "SCAN_VULN"},
    )
    db_session.add(log)
    db_session.commit()

    response = admin_client.get("/audit")
    assert response.status_code == 200
    html = response.text
    assert "Security &amp; Reconnaissance Audit Trail" in html
    assert "audit-log-01" in html
    assert "TARGET_AUTHORIZATION_GRANTED" in html
    assert "sec-officer" in html


def test_admin_authorizations_and_revocation(admin_client: TestClient, db_session: Session):
    """Verify target authorization admin page and revocation POST flow."""
    inv = InvestigationModel(
        id="inv-authz-admin-01",
        name="Authz Admin Test",
        organization_name="Test Corp",
        description="Testing authorization admin.",
        lead_investigator="Lead",
        status="active",
    )
    db_session.add(inv)

    now = datetime.now(timezone.utc)
    authz = TargetAuthorizationModel(
        id="authz-admin-01",
        investigation_id="inv-authz-admin-01",
        target="192.168.1.200",
        target_type="IP",
        allowed_operations=["SCAN_PORTS"],
        authorization_reference="AUTHZ-ADM-001",
        approved_by="Admin Officer",
        valid_from=now,
        valid_to=now + timedelta(days=30),
        is_revoked=False,
    )
    db_session.add(authz)
    db_session.commit()

    # View admin authorizations
    res = admin_client.get("/admin/authorizations")
    assert res.status_code == 200
    assert "192.168.1.200" in res.text
    assert "ACTIVE" in res.text

    # Revoke authorization with CSRF
    csrf_token = generate_csrf_token()
    admin_client.cookies.set(settings.CSRF_COOKIE_NAME, csrf_token)

    res_revoke = admin_client.post(
        f"/admin/authorizations/{authz.id}/revoke",
        data={"csrf_token": csrf_token},
        follow_redirects=True,
    )
    assert res_revoke.status_code == 200
    assert "REVOKED" in res_revoke.text

    # Confirm in DB
    refreshed = db_session.get(TargetAuthorizationModel, "authz-admin-01")
    assert refreshed.is_revoked is True


def test_admin_tools_page(admin_client: TestClient):
    """Verify scanner diagnostic page reports honest tool states."""
    response = admin_client.get("/admin/tools")
    assert response.status_code == 200
    html = response.text
    assert "Scanner &amp; Integration Diagnostics" in html
    assert "Greenbone Vulnerability Manager" in html
    assert "Active Nmap Reconnaissance Engine" in html
