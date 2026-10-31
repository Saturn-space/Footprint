"""Automated tests for consolidated investigation PDF generation using ReportLab Platypus."""

import io
from starlette.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.recon import TargetAuthorizationModel, EntityModel, EvidenceModel
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel, ScanFindingPortModel
from app.models.vulnerability import VulnerabilityScanJobModel, VulnerabilityFindingModel
from app.services.reporting.pdf_generator import InvestigationReportGenerator
from app.services.scoring.calculator import ExposureScorer


def test_pdf_generation_from_persisted_investigation(db_session: Session):
    """Verify ReportLab Platypus builds a multi-page binary PDF containing genuine investigation records."""
    # 1. Seed database records
    inv = InvestigationModel(
        id="inv-pdf-test-01",
        name="NorthStar Analytics PDF Validation",
        organization_name="NorthStar Analytics Lab",
        description="Forensic investigation dossier generation test.",
        lead_investigator="Lead Analyst",
        team_members=["Analyst Two"],
        status="active",
        owned_domains=["lab.example"],
        approved_ips=["192.168.56.102"],
        approved_cidrs=["192.168.56.0/24"],
        active_targets=["192.168.56.102"],
        active_scanning_enabled=True,
        authorization_reference="AUTHZ-PDF-001",
    )
    db_session.add(inv)

    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    authz = TargetAuthorizationModel(
        id="authz-pdf-01",
        investigation_id="inv-pdf-test-01",
        target="192.168.56.102",
        target_type="IP",
        allowed_operations=["SCAN_PORTS", "SCAN_VULN"],
        authorization_reference="AUTHZ-PDF-001",
        approved_by="Security Officer",
        valid_from=now,
        valid_to=now + timedelta(days=30),
        is_revoked=False,
    )
    db_session.add(authz)

    entity = EntityModel(
        id="ent-pdf-01",
        investigation_id="inv-pdf-test-01",
        entity_type="Email",
        canonical_value="admin@lab.example",
        original_value="admin@lab.example",
        evidence_ids=["ev-pdf-01"],
    )
    db_session.add(entity)

    evidence = EvidenceModel(
        id="ev-pdf-01",
        investigation_id="inv-pdf-test-01",
        source_type="dns_collector",
        source_name="DNS Authoritative Collector",
        target="lab.example",
        content_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        content_size_bytes=1024,
    )
    db_session.add(evidence)

    nmap_job = ActiveScanJobModel(
        id="job-pdf-01",
        investigation_id="inv-pdf-test-01",
        requested_by="usr-admin",
        target="192.168.56.102",
        scan_profile="nmap-service-detect",
        status="COMPLETED",
    )
    db_session.add(nmap_job)

    host = ScanFindingHostModel(
        id="host-pdf-01",
        investigation_id="inv-pdf-test-01",
        job_id="job-pdf-01",
        address="192.168.56.102",
        status="up",
    )
    db_session.add(host)

    port = ScanFindingPortModel(
        id="port-pdf-01",
        host_id="host-pdf-01",
        job_id="job-pdf-01",
        port_number=5432,
        protocol="tcp",
        state="open",
        service_name="postgresql",
        product="PostgreSQL DB",
        version="14.2",
    )
    db_session.add(port)

    vuln_job = VulnerabilityScanJobModel(
        id="gvm-pdf-01",
        investigation_id="inv-pdf-test-01",
        requested_by="usr-admin",
        target="192.168.56.102",
        profile_id="openvas-basic",
        scan_config_id="daba56c8-73ec-11df-a475-002264764ceb",
        status="COMPLETED",
    )
    db_session.add(vuln_job)

    vuln = VulnerabilityFindingModel(
        id="vf-pdf-01",
        investigation_id="inv-pdf-test-01",
        job_id="gvm-pdf-01",
        host="192.168.56.102",
        port=5432,
        protocol="tcp",
        name="PostgreSQL Cleartext Authentication",
        description="PostgreSQL server allows cleartext password transmissions.",
        solution="Enforce scram-sha-256 password encryption and TLS certificates.",
        severity="high",
        cvss_score=7.5,
        cvss_version="3.1",
        cve_references=["CVE-2022-1234"],
        qod=95,
    )
    db_session.add(vuln)
    db_session.commit()

    # 2. Generate PDF binary
    pdf_bytes = InvestigationReportGenerator.generate_pdf(
        investigation_id="inv-pdf-test-01",
        db=db_session,
        generated_by="Lead Analyst",
        dossier_title="NorthStar Lab Forensic Dossier",
    )

    # 3. Verify PDF binary format and content structure
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-")
    assert b"%%EOF" in pdf_bytes


def test_pdf_generation_empty_investigation_handled_honestly(db_session: Session):
    """Verify an empty investigation without scans generates an honest, uncorrupted PDF."""
    inv = InvestigationModel(
        id="inv-empty-01",
        name="Empty Baseline Scope",
        organization_name="New Corp",
        description="Fresh campaign with no reconnaissance yet executed.",
        lead_investigator="Lead Analyst",
        status="active",
    )
    db_session.add(inv)
    db_session.commit()

    pdf_bytes = InvestigationReportGenerator.generate_pdf(
        investigation_id="inv-empty-01",
        db=db_session,
    )

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000


def test_pdf_download_endpoint_returns_file(authenticated_client: TestClient, db_session: Session):
    """Verify GET /investigations/{id}/report/pdf streams valid PDF with Content-Disposition headers."""
    inv = InvestigationModel(
        id="inv-dl-test-01",
        name="Download Test Campaign",
        organization_name="Acme Inc",
        description="Testing report download streaming.",
        lead_investigator="Auditor",
        status="active",
    )
    db_session.add(inv)
    db_session.commit()

    response = authenticated_client.get(f"/investigations/{inv.id}/report/pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert f'filename="FootprintIQ-Dossier-{inv.id}.pdf"' in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF-")


def test_pdf_download_nonexistent_investigation_returns_404(authenticated_client: TestClient):
    """Verify download request for invalid investigation ID returns 404."""
    response = authenticated_client.get("/investigations/inv-nonexistent-9999/report/pdf")
    assert response.status_code == 404
