"""Tests for GraphML XML knowledge graph generation and export endpoints."""

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import pytest
from starlette.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.recon import EntityModel
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel, ScanFindingPortModel
from app.models.vulnerability import VulnerabilityScanJobModel, VulnerabilityFindingModel
from app.services.reporting.graphml_generator import GraphMLExporter
from app.models.user import UserModel
from app.core.security import ROLE_ANALYST, hash_password


def test_graphml_generation_structure(db_session: Session):
    """Verifies that GraphMLExporter produces valid, well-formed GraphML XML from persisted records."""
    inv = InvestigationModel(
        id="inv-gml-01",
        name="GraphML Target Lab",
        organization_name="NorthStar Analytics",
        description="Testing GraphML exports",
        owned_domains=["lab.example"],
        active_targets=["192.168.56.102"],
        lead_investigator="SecAnalyst",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(inv)

    ent = EntityModel(
        id="ent-gml-01",
        investigation_id="inv-gml-01",
        entity_type="SUBDOMAIN",
        canonical_value="api.lab.example",
        original_value="api.lab.example via DNS A record",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    db_session.add(ent)

    nmap_job = ActiveScanJobModel(
        id="job-nmap-01",
        investigation_id="inv-gml-01",
        requested_by="SecAnalyst",
        target="192.168.56.102",
        scan_profile="quick_discovery",
        status="COMPLETED",
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(nmap_job)

    vuln_job = VulnerabilityScanJobModel(
        id="job-vuln-01",
        investigation_id="inv-gml-01",
        requested_by="SecAnalyst",
        target="192.168.56.102",
        profile_id="fast_assessment",
        scan_config_id="cfg-fast-01",
        status="COMPLETED",
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(vuln_job)

    host = ScanFindingHostModel(
        id="host-gml-01",
        investigation_id="inv-gml-01",
        job_id="job-nmap-01",
        address="192.168.56.102",
        hostname="lab.example",
        status="up",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(host)

    port = ScanFindingPortModel(
        id="port-gml-01",
        host_id="host-gml-01",
        job_id="job-nmap-01",
        port_number=443,
        protocol="tcp",
        state="open",
        service_name="https",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(port)

    vuln = VulnerabilityFindingModel(
        id="vuln-gml-01",
        investigation_id="inv-gml-01",
        job_id="job-vuln-01",
        host="192.168.56.102",
        name="TLS Deprecated Cipher Suite",
        cve_references=["CVE-2023-9999"],
        severity="medium",
        cvss_score=5.4,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    db_session.add(vuln)
    db_session.commit()

    # Generate XML
    xml_str = GraphMLExporter.generate_graphml("inv-gml-01", db=db_session)
    assert xml_str.startswith('<?xml version="1.0" encoding="UTF-8"?>')

    # Parse XML to verify well-formedness
    root = ET.fromstring(xml_str)
    assert "graphml" in root.tag

    # Verify nodes and edges
    ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
    nodes = root.findall(".//g:node", ns)
    edges = root.findall(".//g:edge", ns)

    node_ids = [n.get("id") for n in nodes]
    assert "inv_inv-gml-01" in node_ids
    assert "entity_ent-gml-01" in node_ids
    assert "host_host-gml-01" in node_ids
    assert "port_port-gml-01" in node_ids
    assert "vuln_vuln-gml-01" in node_ids

    assert len(edges) >= 4


def test_graphml_xml_escaping(db_session: Session):
    """Verifies that special XML characters in entity names/details are escaped safely."""
    inv = InvestigationModel(
        id="inv-gml-escape",
        name="Lab & Research <Testing> \"Quotes\"",
        organization_name="Org & Partners",
        description="Testing XML escaping <>&'\"",
        owned_domains=["escape.example"],
        lead_investigator="Analyst",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(inv)

    ent = EntityModel(
        id="ent-gml-escape",
        investigation_id="inv-gml-escape",
        entity_type="DISCLOSURE",
        canonical_value="admin<script>alert(1)</script>&foo=bar",
        original_value="Dangerous text: <>&'\"",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    db_session.add(ent)
    db_session.commit()

    xml_str = GraphMLExporter.generate_graphml("inv-gml-escape", db=db_session)
    # If not escaped, ET.fromstring would raise ParseError
    root = ET.fromstring(xml_str)
    assert root is not None
    assert "<script>" not in xml_str  # must be &lt;script&gt;
    assert "&lt;script&gt;" in xml_str


def test_graphml_empty_investigation(db_session: Session):
    """Verifies that an investigation with zero findings still generates valid GraphML."""
    inv = InvestigationModel(
        id="inv-gml-empty",
        name="Empty Lab",
        organization_name="Isolated Corp",
        description="Empty investigation testing",
        owned_domains=["empty.example"],
        lead_investigator="Analyst",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(inv)
    db_session.commit()

    xml_str = GraphMLExporter.generate_graphml("inv-gml-empty", db=db_session)
    root = ET.fromstring(xml_str)
    ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
    nodes = root.findall(".//g:node", ns)
    assert len(nodes) == 1
    assert nodes[0].get("id") == "inv_inv-gml-empty"


def test_web_graphml_download_success(authenticated_client: TestClient, db_session: Session):
    """Verifies that the web dashboard GraphML download route streams XML with attachment headers."""
    inv = InvestigationModel(
        id="inv-web-gml",
        name="Web GraphML Lab",
        organization_name="TestOrg",
        description="Web GraphML download testing",
        owned_domains=["webgml.example"],
        lead_investigator="Analyst",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(inv)
    db_session.commit()

    response = authenticated_client.get("/investigations/inv-web-gml/report/graphml")
    assert response.status_code == 200
    assert "application/xml" in response.headers["Content-Type"]
    assert 'attachment; filename="FootprintIQ-KnowledgeGraph-inv-web-gml.graphml"' in response.headers["Content-Disposition"]
    assert "<?xml version=" in response.text


def test_api_graphml_download_unauthorized(client: TestClient, db_session: Session):
    """Verifies that the REST API GraphML export endpoint rejects unauthenticated requests."""
    inv = InvestigationModel(
        id="inv-api-gml",
        name="API GraphML Lab",
        organization_name="TestOrg",
        description="API GraphML testing",
        owned_domains=["apigml.example"],
        lead_investigator="Analyst",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(inv)
    db_session.commit()

    response = client.get("/api/v1/investigations/inv-api-gml/export/graphml")
    assert response.status_code == 401


def test_api_graphml_download_authorized(client: TestClient, db_session: Session):
    """Verifies that authenticated analysts can export GraphML via the REST API."""
    user = UserModel(
        id="usr-gml-analyst",
        username="gml_analyst",
        email="gml@example.com",
        password_hash=hash_password("Pass12345678#Secure"),
        role=ROLE_ANALYST,
        is_active=True,
    )
    db_session.add(user)

    inv = InvestigationModel(
        id="inv-api-gml-auth",
        name="API GraphML Auth Lab",
        organization_name="TestOrg",
        description="API GraphML Auth testing",
        owned_domains=["authgml.example"],
        lead_investigator="Analyst",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(inv)
    db_session.commit()

    # Log in via API to get session/cookie
    login_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": "gml_analyst",
        "password": "Pass12345678#Secure",
    })
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    # Request GraphML export with Bearer token
    response = client.get(
        "/api/v1/investigations/inv-api-gml-auth/export/graphml",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert "application/xml" in response.headers["Content-Type"]
    assert "knowledge_graph_inv-api-gml-auth.graphml" in response.headers["Content-Disposition"]
    assert "<graphml" in response.text
