"""Integration and unit tests for Nmap runner, authorization revalidation, and job lifecycle."""

import asyncio
import os
import tempfile
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.recon import TargetAuthorizationModel, EvidenceModel, EntityModel, utc_now
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel, ScanFindingPortModel
from app.models.user import UserModel
from app.services.active.profiles import get_scan_profile
from app.services.active.runner import NmapRunner, NmapExecutionError

SAMPLE_XML_OUTPUT = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -T3 --top-ports 100 -Pn 127.0.0.1" version="7.98">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="localhost" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.fixture
def mock_admin_user():
    return UserModel(
        id="usr-admin-test-01",
        username="admin_test",
        email="admin@test.local",
        password_hash="fakehash",
        role="administrator",
        is_active=True,
    )


@pytest.fixture
def mock_analyst_user():
    return UserModel(
        id="usr-analyst-test-01",
        username="analyst_test",
        email="analyst@test.local",
        password_hash="fakehash",
        role="analyst",
        is_active=True,
    )


@pytest.fixture
def active_scan_investigation(db_session: Session):
    inv = InvestigationModel(
        id=f"inv-scan-{uuid.uuid4().hex[:8]}",
        name="Active Recon Test Campaign",
        description="Active reconnaissance investigation test campaign",
        organization_name="Test Org",
        lead_investigator="Lead Agent",
        status="active",
        owned_domains=["testlab.local"],
        active_targets=["127.0.0.1", "192.168.1.100"],
        active_scanning_enabled=True,
    )
    db_session.add(inv)
    db_session.commit()
    db_session.refresh(inv)
    return inv


def test_target_authorization_missing(db_session: Session, active_scan_investigation, mock_admin_user):
    """Scan is rejected if no TargetAuthorization record exists."""
    runner = NmapRunner()
    profile = get_scan_profile("basic_tcp")
    is_valid, reason, ips = runner.resolve_and_revalidate_target(
        db=db_session,
        investigation=active_scan_investigation,
        target="127.0.0.1",
        profile=profile,
        actor_user=mock_admin_user,
    )
    assert is_valid is False
    assert "No valid administrative authorization record" in reason


def test_target_authorization_passive_only(db_session: Session, active_scan_investigation, mock_admin_user):
    """Scan is rejected if authorization permits only passive reconnaissance."""
    now = datetime.now(timezone.utc)
    authz = TargetAuthorizationModel(
        id=f"authz-{uuid.uuid4().hex[:8]}",
        investigation_id=active_scan_investigation.id,
        target="127.0.0.1",
        target_type="IP",
        allowed_operations=["PASSIVE_RECON"],  # Missing SCAN_ACTIVE
        authorization_reference="AUTH-PASSIVE-ONLY",
        approved_by="Admin",
        valid_from=now - timedelta(days=1),
        valid_to=now + timedelta(days=1),
        is_revoked=False,
    )
    db_session.add(authz)
    db_session.commit()

    runner = NmapRunner()
    profile = get_scan_profile("basic_tcp")
    is_valid, reason, ips = runner.resolve_and_revalidate_target(
        db=db_session,
        investigation=active_scan_investigation,
        target="127.0.0.1",
        profile=profile,
        actor_user=mock_admin_user,
    )
    assert is_valid is False
    assert "not permitted by authorization record" in reason


def test_target_authorization_expired(db_session: Session, active_scan_investigation, mock_admin_user):
    """Scan is rejected if authorization is expired."""
    now = datetime.now(timezone.utc)
    authz = TargetAuthorizationModel(
        id=f"authz-{uuid.uuid4().hex[:8]}",
        investigation_id=active_scan_investigation.id,
        target="127.0.0.1",
        target_type="IP",
        allowed_operations=["SCAN_ACTIVE"],
        authorization_reference="AUTH-EXPIRED",
        approved_by="Admin",
        valid_from=now - timedelta(days=5),
        valid_to=now - timedelta(days=1),  # Expired
        is_revoked=False,
    )
    db_session.add(authz)
    db_session.commit()

    runner = NmapRunner()
    profile = get_scan_profile("basic_tcp")
    is_valid, reason, ips = runner.resolve_and_revalidate_target(
        db=db_session,
        investigation=active_scan_investigation,
        target="127.0.0.1",
        profile=profile,
        actor_user=mock_admin_user,
    )
    assert is_valid is False
    assert "expired" in reason


def test_target_authorization_revoked(db_session: Session, active_scan_investigation, mock_admin_user):
    """Scan is rejected if authorization is revoked."""
    now = datetime.now(timezone.utc)
    authz = TargetAuthorizationModel(
        id=f"authz-{uuid.uuid4().hex[:8]}",
        investigation_id=active_scan_investigation.id,
        target="127.0.0.1",
        target_type="IP",
        allowed_operations=["SCAN_ACTIVE"],
        authorization_reference="AUTH-REVOKED",
        approved_by="Admin",
        valid_from=now - timedelta(days=1),
        valid_to=now + timedelta(days=1),
        is_revoked=True,
    )
    db_session.add(authz)
    db_session.commit()

    runner = NmapRunner()
    profile = get_scan_profile("basic_tcp")
    is_valid, reason, ips = runner.resolve_and_revalidate_target(
        db=db_session,
        investigation=active_scan_investigation,
        target="127.0.0.1",
        profile=profile,
        actor_user=mock_admin_user,
    )
    assert is_valid is False
    assert "revoked" in reason


def test_target_out_of_scope(db_session: Session, active_scan_investigation, mock_admin_user):
    """Scan is rejected if target is outside investigation scope."""
    now = datetime.now(timezone.utc)
    # Even if authorization record exists, target must be in investigation scope
    runner = NmapRunner()
    profile = get_scan_profile("basic_tcp")
    is_valid, reason, ips = runner.resolve_and_revalidate_target(
        db=db_session,
        investigation=active_scan_investigation,
        target="10.99.99.99",  # Not in owned_domains or active_targets
        profile=profile,
        actor_user=mock_admin_user,
    )
    assert is_valid is False
    assert "is not within approved investigation" in reason


@pytest.mark.asyncio
async def test_successful_scan_execution_and_persistence(db_session: Session, active_scan_investigation, mock_admin_user):
    """Verify end-to-end execution flow with mocked subprocess, writing XML and persisting findings."""
    now = datetime.now(timezone.utc)
    authz = TargetAuthorizationModel(
        id=f"authz-{uuid.uuid4().hex[:8]}",
        investigation_id=active_scan_investigation.id,
        target="127.0.0.1",
        target_type="IP",
        allowed_operations=["SCAN_ACTIVE"],
        authorization_reference="AUTH-LAB-VALID",
        approved_by="SecurityLead",
        valid_from=now - timedelta(hours=1),
        valid_to=now + timedelta(hours=24),
        is_revoked=False,
    )
    db_session.add(authz)
    db_session.commit()

    runner = NmapRunner()

    # Create scan job
    job = await runner.create_scan_job(
        db=db_session,
        investigation=active_scan_investigation,
        target="127.0.0.1",
        profile_id="basic_tcp",
        actor_user=mock_admin_user,
    )
    assert job.status == "QUEUED"
    assert job.scan_profile == "basic_tcp"

    # Mock subprocess execution
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(b"", b""))

    async def mock_subprocess_exec(*cmd, **kwargs):
        # cmd contains: [binary, profile_args..., "-oX", xml_path, target]
        if "-oX" in cmd:
            xml_path = Path(cmd[cmd.index("-oX") + 1])
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            xml_path.write_text(SAMPLE_XML_OUTPUT, encoding="utf-8")
        return mock_proc

    # Session factory for execute_scan
    class MockDbFactory:
        def __enter__(self):
            return db_session
        def __exit__(self, *args):
            pass

    with patch("app.services.active.runner.get_nmap_detector") as mock_det, \
         patch("asyncio.create_subprocess_exec", side_effect=mock_subprocess_exec):
        
        det_inst = MagicMock()
        det_inst.resolve_binary_path.return_value = "/usr/bin/nmap"
        mock_det.return_value = det_inst

        await runner.execute_scan(
            db_factory=MockDbFactory,
            job_id=job.id,
        )

    # Re-query job
    db_session.refresh(job)
    assert job.status == "COMPLETED"
    assert job.exit_code == 0
    assert job.evidence_id is not None
    assert job.duration_seconds is not None

    # Verify findings persisted
    hosts = db_session.scalars(
        select(ScanFindingHostModel).where(ScanFindingHostModel.job_id == job.id)
    ).all()
    assert len(hosts) == 1
    host = hosts[0]
    assert host.address == "127.0.0.1"
    assert host.hostname == "localhost"

    ports = db_session.scalars(
        select(ScanFindingPortModel).where(ScanFindingPortModel.job_id == job.id)
    ).all()
    assert len(ports) == 2
    open_port = next(p for p in ports if p.port_number == 80)
    assert open_port.state == "open"
    assert open_port.service_name == "http"

    # Verify entity persisted
    service_ent = db_session.scalars(
        select(EntityModel).where(
            EntityModel.investigation_id == active_scan_investigation.id,
            EntityModel.entity_type == "service",
        )
    ).first()
    assert service_ent is not None
    assert "127.0.0.1:80/tcp" in service_ent.canonical_value


@pytest.mark.asyncio
async def test_scan_execution_timeout(db_session: Session, active_scan_investigation, mock_admin_user):
    """Verify scan runner marks job as TIMED_OUT when subprocess exceeds timeout."""
    now = datetime.now(timezone.utc)
    authz = TargetAuthorizationModel(
        id=f"authz-{uuid.uuid4().hex[:8]}",
        investigation_id=active_scan_investigation.id,
        target="127.0.0.1",
        target_type="IP",
        allowed_operations=["SCAN_ACTIVE"],
        authorization_reference="AUTH-LAB-VALID",
        approved_by="SecurityLead",
        valid_from=now - timedelta(hours=1),
        valid_to=now + timedelta(hours=24),
        is_revoked=False,
    )
    db_session.add(authz)
    db_session.commit()

    runner = NmapRunner()
    job = await runner.create_scan_job(
        db=db_session,
        investigation=active_scan_investigation,
        target="127.0.0.1",
        profile_id="basic_tcp",
        actor_user=mock_admin_user,
    )

    class MockDbFactory:
        def __enter__(self):
            return db_session
        def __exit__(self, *args):
            pass

    mock_proc = MagicMock()
    mock_proc.kill = MagicMock()
    mock_proc.wait = AsyncMock()
    mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())

    with patch("app.services.active.runner.get_nmap_detector") as mock_det, \
         patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        
        det_inst = MagicMock()
        det_inst.resolve_binary_path.return_value = "/usr/bin/nmap"
        mock_det.return_value = det_inst

        await runner.execute_scan(
            db_factory=MockDbFactory,
            job_id=job.id,
        )

    db_session.refresh(job)
    assert job.status == "TIMED_OUT"
    assert job.error_category == "TIMEOUT"
    mock_proc.kill.assert_called_once()


@pytest.mark.asyncio
async def test_scan_execution_cancellation(db_session: Session, active_scan_investigation, mock_admin_user):
    """Verify scan cancellation updates job to CANCELLED state."""
    now = datetime.now(timezone.utc)
    authz = TargetAuthorizationModel(
        id=f"authz-{uuid.uuid4().hex[:8]}",
        investigation_id=active_scan_investigation.id,
        target="127.0.0.1",
        target_type="IP",
        allowed_operations=["SCAN_ACTIVE"],
        authorization_reference="AUTH-LAB-VALID",
        approved_by="SecurityLead",
        valid_from=now - timedelta(hours=1),
        valid_to=now + timedelta(hours=24),
        is_revoked=False,
    )
    db_session.add(authz)
    db_session.commit()

    runner = NmapRunner()
    job = await runner.create_scan_job(
        db=db_session,
        investigation=active_scan_investigation,
        target="127.0.0.1",
        profile_id="basic_tcp",
        actor_user=mock_admin_user,
    )

    cancelled = await runner.cancel_scan(
        db=db_session,
        job_id=job.id,
        actor_id=mock_admin_user.id,
        reason="Admin cancelled test",
    )
    assert cancelled is True
    db_session.refresh(job)
    assert job.status == "CANCELLED"
    assert job.cancellation_reason == "Admin cancelled test"
