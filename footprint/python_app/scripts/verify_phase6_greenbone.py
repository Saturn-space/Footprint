"""Phase 6 End-to-End Verification Script: Greenbone / OpenVAS Vulnerability Assessment Integration."""

import asyncio
from datetime import datetime, timezone, timedelta
import json
import logging
from pathlib import Path
import sys
import uuid

# Add python_app directory to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from app.database import get_db_context, SessionLocal
from app.models.investigation import InvestigationModel
from app.models.recon import TargetAuthorizationModel, EvidenceModel, EntityModel
from app.models.user import UserModel
from app.models.audit import AuditLogModel
from app.models.vulnerability import VulnerabilityScanJobModel, VulnerabilityFindingModel
from app.services.vuln.profiles import list_vuln_profiles, get_vuln_profile
from app.services.vuln.xml_parser import parse_greenbone_xml_report
from app.services.vuln.orchestrator import VulnerabilityAssessmentOrchestrator, VulnerabilityAssessmentError
from app.integrations.greenbone_client import GreenboneClient
from app.integrations.greenbone_adapter import GreenboneAdapter
from unittest.mock import MagicMock

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("phase6_verify")


async def run_verification():
    logger.info("=== STARTING PHASE 6 GREENBONE INTEGRATION VERIFICATION ===")

    # 1. Profile Verification
    profiles = list_vuln_profiles()
    logger.info("Verifying approved scan profiles: found %d profiles", len(profiles))
    for p in profiles:
        logger.info("  Profile: %s | Config: %s (%s) | Timeout: %ds", p.id, p.gvm_config_name, p.gvm_config_id, p.timeout_seconds)
    assert len(profiles) >= 2, "Must have at least 2 vetted scan profiles"

    # 2. Connection Diagnostics Verification
    client = GreenboneClient()
    status_report = client.check_status()
    logger.info("Greenbone service status check: status=%s, configured=%s, endpoint=%s",
                status_report.get("status"), status_report.get("configured"), status_report.get("endpoint"))
    # Confirm passwords/tokens are not present in status
    assert "password" not in json.dumps(status_report).lower(), "Secrets must never appear in diagnostics"

    # 3. Setup Lab Investigation & Target
    with get_db_context() as db:
        inv_id = f"inv-phase6-lab-{uuid.uuid4().hex[:6]}"
        target_ip = "192.168.1.50"
        now = datetime.now(timezone.utc)

        inv = InvestigationModel(
            id=inv_id,
            name="Phase 6 Lab Vulnerability Assessment",
            description="Verified integration test campaign against authorized lab asset",
            organization_name="FootprintIQ Security Lab",
            lead_investigator="Senior Security Architect",
            status="active",
            owned_domains=["lab.local"],
            approved_ips=[target_ip],
            active_targets=[target_ip],
            active_scanning_enabled=True,
            created_at=now,
        )
        db.add(inv)

        # Admin user
        admin = UserModel(
            id=f"usr-admin-{uuid.uuid4().hex[:6]}",
            username=f"admin_{uuid.uuid4().hex[:4]}",
            email=f"admin_{uuid.uuid4().hex[:6]}@lab.local",
            password_hash="mockhash",
            role="administrator",
            is_active=True,
        )
        db.add(admin)

        # Analyst user (lacks vulnerability.scan)
        analyst = UserModel(
            id=f"usr-analyst-{uuid.uuid4().hex[:6]}",
            username=f"analyst_{uuid.uuid4().hex[:4]}",
            email=f"analyst_{uuid.uuid4().hex[:6]}@lab.local",
            password_hash="mockhash",
            role="analyst",
            is_active=True,
        )
        db.add(analyst)


        # Valid Target Authorization with SCAN_VULN
        authz = TargetAuthorizationModel(
            id=f"authz-{uuid.uuid4().hex[:8]}",
            investigation_id=inv_id,
            target=target_ip,
            target_type="IP",
            allowed_operations=["SCAN_VULN"],
            authorization_reference="REF-PHASE6-LAB-001",
            approved_by=admin.id,
            valid_from=now - timedelta(hours=1),
            valid_to=now + timedelta(days=3),
            is_revoked=False,
        )
        db.add(authz)
        admin_id = admin.id
        db.commit()


        logger.info("Initialized lab environment: Investigation %s, Target %s, Authz %s", inv_id, target_ip, authz.id)

    # 4. Negative Authorization Testing
    with get_db_context() as db:
        inv = db.get(InvestigationModel, inv_id)
        admin = db.get(UserModel, admin_id)
        orchestrator = VulnerabilityAssessmentOrchestrator()
        
        # Test A: Unapproved Target
        try:
            orchestrator.create_assessment_job(
                db=db,
                investigation=inv,
                target="10.10.10.10",
                profile_id="openvas-basic",
                actor_user=admin,
            )
            assert False, "Should have rejected out-of-scope target"
        except VulnerabilityAssessmentError as e:
            logger.info("PASS: Out-of-scope target correctly rejected: %s", e)

        # Test B: Wrong operation (SCAN_ACTIVE instead of SCAN_VULN)
        unauth_target = "192.168.1.99"
        inv.active_targets = [target_ip, unauth_target]
        db.commit()

        wrong_op_authz = TargetAuthorizationModel(
            id=f"authz-wrong-op-{uuid.uuid4().hex[:6]}",
            investigation_id=inv_id,
            target=unauth_target,
            target_type="IP",
            allowed_operations=["SCAN_ACTIVE"],  # Active Nmap only, not Vuln!
            authorization_reference="REF-ACTIVE-ONLY",
            approved_by=admin.id,
            valid_from=now - timedelta(hours=1),
            valid_to=now + timedelta(days=3),
            is_revoked=False,
        )
        db.add(wrong_op_authz)
        db.commit()

        try:
            orchestrator.create_assessment_job(
                db=db,
                investigation=inv,
                target=unauth_target,
                profile_id="openvas-basic",
                actor_user=admin,
            )
            assert False, "Should have rejected target without SCAN_VULN permission"
        except VulnerabilityAssessmentError as e:
            logger.info("PASS: Target with only SCAN_ACTIVE correctly rejected: %s", e)

    # 5. Full Orchestration Execution with Real Fixture Report
    fixture_path = Path(__file__).resolve().parent.parent / "data" / "scans" / "greenbone" / "inv-test-vuln-01" / "gvm-imp-31efbea759.xml"
    report_xml = fixture_path.read_text(encoding="utf-8")

    mock_adapter = MagicMock()
    mock_adapter.check_availability.return_value = {
        "status": "READY",
        "configured": True,
        "endpoint": "127.0.0.1:9390",
        "version": "22.4.0",
        "authenticated": True,
        "error": None,
    }
    mock_adapter.create_scan_target.return_value = "gvm-tgt-lab-1234"
    mock_adapter.create_scan_task.return_value = "gvm-tsk-lab-5678"
    mock_adapter.start_scan_task.return_value = "gvm-rep-lab-9012"
    mock_adapter.poll_scan_status.return_value = {"status": "Done", "progress": 100, "report_id": "gvm-rep-lab-9012"}
    mock_adapter.retrieve_report.return_value = report_xml

    orchestrator = VulnerabilityAssessmentOrchestrator(adapter=mock_adapter)

    with get_db_context() as db:
        inv = db.get(InvestigationModel, inv_id)
        admin = db.get(UserModel, admin_id)
        job = orchestrator.create_assessment_job(
            db=db,
            investigation=inv,
            target=target_ip,
            profile_id="openvas-basic",
            actor_user=admin,
        )
        logger.info("Created authorized vulnerability scan job: %s (Status: %s)", job.id, job.status)


    # Run the full assessment lifecycle
    await orchestrator.execute_assessment_job(
        job_id=job.id,
        investigation_id=inv_id,
        target=target_ip,
        profile_id="openvas-basic",
        requested_by=admin_id,
    )

    # 6. Verify Database State & Provenance
    with get_db_context() as db:
        finished_job = db.get(VulnerabilityScanJobModel, job.id)
        assert finished_job.status == "COMPLETED", f"Expected COMPLETED, got {finished_job.status}"
        assert finished_job.progress == 100
        assert finished_job.gvm_target_id == "gvm-tgt-lab-1234"
        assert finished_job.gvm_task_id == "gvm-tsk-lab-5678"
        assert finished_job.evidence_id is not None
        logger.info("PASS: Job completed successfully with duration %.2fs, evidence ID: %s",
                    finished_job.duration_seconds, finished_job.evidence_id)

        # Check Evidence
        evidence = db.get(EvidenceModel, finished_job.evidence_id)
        assert evidence is not None
        assert evidence.source_type == "greenbone_openvas"
        assert len(evidence.content_hash) == 64
        logger.info("PASS: Forensic evidence record verified: SHA-256=%s, path=%s",
                    evidence.content_hash, evidence.raw_content_path)

        # Check Normalized Findings
        findings = db.scalars(
            select(VulnerabilityFindingModel)
            .where(VulnerabilityFindingModel.job_id == job.id)
            .order_by(VulnerabilityFindingModel.cvss_score.desc().nullslast())
        ).all()
        logger.info("PASS: Ingested %d normalized findings:", len(findings))
        for f in findings:
            logger.info("  [%s] %s | Host: %s:%s | CVSS: %s | CVEs: %s",
                        f.severity.upper(), f.name, f.host, f.port, f.cvss_score, f.cve_references)
            assert f.investigation_id == inv_id
            assert f.evidence_id == evidence.id
        assert len(findings) == 4

        # Check Entity Correlation
        entities = db.scalars(
            select(EntityModel).where(EntityModel.investigation_id == inv_id)
        ).all()
        logger.info("PASS: Correlated %d entities into investigation domain model", len(entities))
        assert len(entities) >= 4

        # Check Audit Log Integrity
        audit_events = db.scalars(
            select(AuditLogModel)
            .where(AuditLogModel.actor_id == admin_id)
            .order_by(AuditLogModel.timestamp.asc())
        ).all()

        logger.info("PASS: Generated %d audit log entries:", len(audit_events))
        for a in audit_events:
            logger.info("  Event: %s | Outcome: %s | Details: %s", a.event_type, a.outcome, a.details)
        assert any(a.event_type == "VULN_SCAN_REQUESTED" for a in audit_events)
        assert any(a.event_type == "VULN_SCAN_STARTED" for a in audit_events)
        assert any(a.event_type == "VULN_SCAN_COMPLETED" for a in audit_events)

    logger.info("=== PHASE 6 GREENBONE INTEGRATION VERIFICATION COMPLETE: ALL CHECKS PASSED ===")


if __name__ == "__main__":
    asyncio.run(run_verification())
