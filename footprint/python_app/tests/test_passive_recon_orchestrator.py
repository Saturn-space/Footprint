"""End-to-end integration tests for passive reconnaissance orchestration, evidence storage, entity normalization, and API routes."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timezone, timedelta

from app.models.investigation import InvestigationModel
from app.models.recon import TargetAuthorizationModel, CollectionJobModel, EvidenceModel, EntityModel
from app.services.passive.orchestrator import PassiveReconOrchestrator
from app.services.collectors.base import CollectorResult, DiscoveredFinding


@pytest.fixture
def sample_investigation_and_auth(db_session):
    """Sets up an authorized investigation and target authorization record."""
    now = datetime.now(timezone.utc)
    inv = InvestigationModel(
        id="inv-e2e-recon",
        name="E2E Recon Investigation",
        organization_name="Target Corp",
        description="Passive recon test",
        lead_investigator="Lead",
        owned_domains=["targetcorp.com"],
        approved_ips=[],
        approved_cidrs=[],
        active_targets=["targetcorp.com"],
    )
    db_session.add(inv)

    auth_rec = TargetAuthorizationModel(
        id="auth-e2e-1",
        investigation_id=inv.id,
        target="targetcorp.com",
        target_type="DOMAIN",
        allowed_operations=["RECON_PASSIVE"],
        authorization_reference="AUTH-E2E-001",
        approved_by="Security Officer",
        valid_from=now - timedelta(days=1),
        valid_to=now + timedelta(days=30),
        is_revoked=False,
    )
    db_session.add(auth_rec)
    db_session.commit()
    return inv, auth_rec


@pytest.mark.asyncio
async def test_orchestrator_execution_and_entity_deduplication(db_session, sample_investigation_and_auth, analyst_user):
    inv, auth_rec = sample_investigation_and_auth

    orchestrator = PassiveReconOrchestrator(db=db_session, investigation_id=inv.id, actor_user=analyst_user)

    # Mock collectors to return controlled findings
    mock_rdap_res = CollectorResult(
        collector_name="rdap_whois_collector",
        source_type="RDAP",
        source_name="rdap.org",
        target="targetcorp.com",
        status="SUCCESS",
        raw_content={"domain": "targetcorp.com", "registrar": "GoDaddy"},
        content_format="json",
        findings=[
            DiscoveredFinding(entity_type="DOMAIN", raw_value="targetcorp.com"),
            DiscoveredFinding(entity_type="ORGANIZATION", raw_value="GoDaddy LLC"),
            DiscoveredFinding(entity_type="HOST", raw_value="ns1.targetcorp.com"),
        ],
    )

    mock_dns_res = CollectorResult(
        collector_name="dns_collector",
        source_type="DNS",
        source_name="dns_resolver",
        target="targetcorp.com",
        status="SUCCESS",
        raw_content={"A": ["198.51.100.10"]},
        content_format="json",
        findings=[
            DiscoveredFinding(entity_type="IP_ADDRESS", raw_value="198.51.100.10"),
            # Duplicate host discovered by DNS as well
            DiscoveredFinding(entity_type="HOST", raw_value="ns1.targetcorp.com"),
        ],
    )

    mock_crtsh_res = CollectorResult(
        collector_name="crtsh_collector",
        source_type="CERTIFICATE_TRANSPARENCY",
        source_name="crt.sh",
        target="targetcorp.com",
        status="SUCCESS",
        raw_content=[{"id": 12345}],
        content_format="json",
        findings=[
            DiscoveredFinding(entity_type="SUBDOMAIN", raw_value="api.targetcorp.com"),
        ],
    )

    with patch.object(orchestrator, "_get_registered_collectors") as mock_collectors:
        c1 = MagicMock()
        c1.name = "rdap_whois_collector"
        c1.source_type = "RDAP"
        c1.collect = AsyncMock(return_value=mock_rdap_res)

        c2 = MagicMock()
        c2.name = "dns_collector"
        c2.source_type = "DNS"
        c2.collect = AsyncMock(return_value=mock_dns_res)

        c3 = MagicMock()
        c3.name = "crtsh_collector"
        c3.source_type = "CERTIFICATE_TRANSPARENCY"
        c3.collect = AsyncMock(return_value=mock_crtsh_res)

        mock_collectors.return_value = {"rdap": c1, "dns": c2, "crtsh": c3}

        result = await orchestrator.run(target="targetcorp.com")

        assert result["status"] == "COMPLETED"
        assert len(result["collectors"]) == 3
        assert result["evidence_collected"] == 3

        # Verify entity deduplication: ns1.targetcorp.com was discovered by both RDAP and DNS
        ns1_entity = db_session.query(EntityModel).filter_by(
            investigation_id=inv.id, canonical_value="ns1.targetcorp.com"
        ).first()
        assert ns1_entity is not None
        assert len(ns1_entity.evidence_ids) == 2


@pytest.mark.asyncio
async def test_orchestrator_failure_isolation(db_session, sample_investigation_and_auth, analyst_user):
    """Ensures that one failing collector does not prevent other collectors from succeeding."""
    inv, auth_rec = sample_investigation_and_auth

    orchestrator = PassiveReconOrchestrator(db=db_session, investigation_id=inv.id, actor_user=analyst_user)

    c_success = MagicMock()
    c_success.name = "dns_collector"
    c_success.source_type = "DNS"
    c_success.collect = AsyncMock(
        return_value=CollectorResult(
            collector_name="dns_collector",
            source_type="DNS",
            source_name="dns",
            target="targetcorp.com",
            status="SUCCESS",
            raw_content={"A": ["1.2.3.4"]},
            content_format="json",
            findings=[DiscoveredFinding(entity_type="IP_ADDRESS", raw_value="1.2.3.4")],
        )
    )

    c_fail = MagicMock()
    c_fail.name = "failing_collector"
    c_fail.source_type = "CRASH"
    # Simulates an unhandled network error
    c_fail.collect = AsyncMock(side_effect=RuntimeError("Third-party API crashed"))

    with patch.object(orchestrator, "_get_registered_collectors", return_value={"dns": c_success, "fail": c_fail}):
        result = await orchestrator.run(target="targetcorp.com")

        assert result["status"] == "PARTIAL"
        jobs = result["collectors"]
        statuses = {j["collector_name"]: j["status"] for j in jobs}
        assert statuses["dns_collector"] == "SUCCESS"
        assert statuses["failing_collector"] == "FAILED"


def test_api_trigger_passive_recon_unauthorized_user_rejected(client, sample_investigation_and_auth, viewer_headers):
    inv, _ = sample_investigation_and_auth

    resp = client.post(
        f"/api/v1/investigations/{inv.id}/passive-recon",
        json={"target": "targetcorp.com"},
        headers=viewer_headers,
    )
    # Viewer does not hold recon.passive permission -> HTTP 403
    assert resp.status_code == 403


def test_api_trigger_passive_recon_unauthorized_target_rejected(client, sample_investigation_and_auth, analyst_headers):
    inv, _ = sample_investigation_and_auth

    resp = client.post(
        f"/api/v1/investigations/{inv.id}/passive-recon",
        json={"target": "unauthorized-domain.com"},
        headers=analyst_headers,
    )
    assert resp.status_code == 403
    err_body = resp.json().get("error", {})
    err_msg = err_body.get("message", resp.text)
    assert "scope" in err_msg.lower()


def test_api_passive_recon_end_to_end_flow(client, sample_investigation_and_auth, analyst_headers):
    inv, _ = sample_investigation_and_auth

    # 1. Trigger passive recon with mocked collector
    mock_res = CollectorResult(
        collector_name="mock_collector",
        source_type="MOCK",
        source_name="mock_source",
        target="targetcorp.com",
        status="SUCCESS",
        raw_content={"test": "content", "target": "targetcorp.com"},
        content_format="json",
        findings=[
            DiscoveredFinding(entity_type="DOMAIN", raw_value="targetcorp.com"),
            DiscoveredFinding(entity_type="EMAIL", raw_value="admin@targetcorp.com"),
        ],
    )

    with patch("app.services.passive.orchestrator.PassiveReconOrchestrator._get_registered_collectors") as mock_c:
        mock_coll = MagicMock()
        mock_coll.name = "mock_collector"
        mock_coll.source_type = "MOCK"
        mock_coll.collect = AsyncMock(return_value=mock_res)
        mock_c.return_value = {"mock": mock_coll}

        resp = client.post(
            f"/api/v1/investigations/{inv.id}/passive-recon",
            json={"target": "targetcorp.com"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "COMPLETED"
        assert data["evidence_collected"] >= 1

    # 2. List collection jobs
    resp = client.get(f"/api/v1/investigations/{inv.id}/passive-recon", headers=analyst_headers)
    assert resp.status_code == 200
    jobs = resp.json()
    assert len(jobs) >= 1
    assert jobs[0]["collector_name"] == "mock_collector"

    # 3. List normalized entities
    resp = client.get(f"/api/v1/investigations/{inv.id}/entities", headers=analyst_headers)
    assert resp.status_code == 200
    entities = resp.json()
    assert len(entities) >= 2
    canonical_values = [e["canonical_value"] for e in entities]
    assert "targetcorp.com" in canonical_values
    assert "admin@targetcorp.com" in canonical_values

    # 4. List evidence records
    resp = client.get(f"/api/v1/investigations/{inv.id}/evidence", headers=analyst_headers)
    assert resp.status_code == 200
    evidence_list = resp.json()
    assert len(evidence_list) >= 1
    evidence_id = evidence_list[0]["id"]
    content_hash = evidence_list[0]["content_hash"]

    # 5. Fetch raw evidence with SHA-256 header verification
    resp = client.get(f"/api/v1/investigations/{inv.id}/evidence/{evidence_id}/raw", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.headers.get("X-Content-SHA256") == content_hash
    assert resp.headers.get("X-Evidence-Integrity") == "VERIFIED"
    assert b"targetcorp.com" in resp.content
