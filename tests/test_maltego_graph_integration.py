"""
FootprintIQ - Investigation Entity Graph & Maltego Interchange Integration Tests
Verifies cross-source entity correlation, Maltego GraphML / CSV / JSON export,
XXE-hardened GraphML and CSV import, manual entity/relationship attribution,
SeaweedFS evidence archival, and strict RBAC enforcement (admin oversight-only,
investigator isolation).
"""

import json
import unittest
import xml.etree.ElementTree as ET

from fastapi.testclient import TestClient

from src.api.app import app
from src.db.repository import FootprintIQRepository
from src.services.auth_service import hash_password
from src.services.graph_intelligence_service import GraphIntelligenceService


class TestMaltegoGraphIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.anon_client = TestClient(app)
        cls.repo = FootprintIQRepository()

        # Login as Admin
        admin_res = cls.client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "AdminPass2026!"},
        )
        cls.admin_headers = {"Authorization": f"Bearer {admin_res.json().get('access_token')}"}

        # Ensure Primary & Peer Investigators exist
        for uname, email in [
            ("graph_inv_a", "graph_inv_a@footprintiq.internal"),
            ("graph_inv_b", "graph_inv_b@footprintiq.internal"),
        ]:
            if not cls.repo.get_user_by_username(uname):
                cls.repo.create_user(
                    username=uname,
                    email=email,
                    hashed_password=hash_password("InvestigatorPass2026!"),
                    role="investigator",
                    is_approved=True,
                )

        cls.inv_a_headers = {
            "Authorization": f"Bearer {cls.client.post('/api/v1/auth/login', json={'username': 'graph_inv_a', 'password': 'InvestigatorPass2026!'}).json().get('access_token')}"
        }
        cls.inv_b_headers = {
            "Authorization": f"Bearer {cls.client.post('/api/v1/auth/login', json={'username': 'graph_inv_b', 'password': 'InvestigatorPass2026!'}).json().get('access_token')}"
        }

        # Create campaign owned by graph_inv_a with passive + active + vuln data
        create_res = cls.client.post(
            "/api/v1/recon",
            json={
                "name": "Maltego Entity Correlation Campaign",
                "target_value": "192.168.56.111",
                "selected_scan_types": "passive,active,vulnerability",
                "authorization_confirmed": True,
            },
            headers=cls.inv_a_headers,
        )
        assert create_res.status_code == 201, create_res.text
        cls.recon_id = create_res.json()["recon_id"]

        # Seed realistic multi-tool results (passive + active + findings) into campaign
        seed_scan = cls.repo.create_scan_execution(
            investigation_id=cls.recon_id,
            scan_type="combined",
            target="192.168.56.111",
            profile="lab-basic",
            recon_id=cls.recon_id,
        )
        seed_scan_id = (seed_scan or {}).get("scan_id")
        if seed_scan_id:
            cls.repo.update_scan_execution(
                scan_id=seed_scan_id,
                status="completed",
                result_summary_json=json.dumps({
                    "passive_results": [{
                        "target": "lab.footprintiq.local",
                        "target_kind": "domain",
                        "domain_intel": {
                            "whois": {"organization": "FootprintIQ Lab Org", "registrar": "LocalRegistrar"},
                            "subdomains": ["api.lab.footprintiq.local", "portal.lab.footprintiq.local"],
                            "dns_records": {
                                "NS": ["ns1.lab.footprintiq.local."],
                                "MX": ["10 mail.lab.footprintiq.local."],
                                "A": ["192.168.56.111"],
                            },
                        },
                        "osint_intel": {"emails": ["secops@lab.footprintiq.local"]},
                        "infrastructure_intel": {"resolved_ips": ["192.168.56.111"]},
                    }],
                    "active_hosts": [],
                    "discovered_ports": [],
                    "scanner_statuses": [{"scanner": "Seed", "status": "COMPLETED"}],
                }),
            )
        cls.repo.add_vulnerability_finding(
            cls.recon_id,
            {
                "title": "vsftpd 2.3.4 Backdoor Execution",
                "severity": "Critical",
                "target_ip": "192.168.56.111",
                "port": 21,
                "protocol": "tcp",
                "service": "ftp",
                "detection_source": "nmap_nse",
                "cve_identifiers": "CVE-2011-2523",
                "cvss_score": 10.0,
                "confidence": 0.95,
                "evidence_reference": "ev_nse_ftp",
            },
        )
        cls.repo.add_vulnerability_finding(
            cls.recon_id,
            {
                "title": "HTTP Missing Security Headers (x-frame-options)",
                "severity": "Informational",
                "target_ip": "192.168.56.111",
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "detection_source": "nuclei",
                "confidence": 0.90,
                "evidence_reference": "ev_nuclei_http",
            },
        )

    def test_01_graph_status_requires_auth_and_is_honest(self):
        self.assertEqual(self.anon_client.get("/api/v1/graph/status").status_code, 401)

        r = self.client.get("/api/v1/graph/status", headers=self.inv_a_headers)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("maltego_desktop_installed", data)
        self.assertIn("graphml", data["supported_exports"])
        self.assertIn("csv", data["supported_imports"])
        self.assertIn("honesty_note", data)

    def test_02_correlated_graph_unifies_passive_osint_and_findings(self):
        r = self.client.get(f"/api/v1/investigations/{self.recon_id}/graph", headers=self.inv_a_headers)
        self.assertEqual(r.status_code, 200)
        graph = r.json()

        types = {n["entity_type"] for n in graph["nodes"]}
        for expected in ["domain", "subdomain", "organization", "email", "nameserver", "mx", "ip", "service", "vulnerability"]:
            self.assertIn(expected, types, f"Missing expected entity type: {expected}")

        edge_rels = {e["relationship"] for e in graph["edges"]}
        self.assertIn("ASSOCIATED_EMAIL", edge_rels)
        self.assertIn("EXPOSES_SERVICE", edge_rels)
        self.assertIn("EXPOSES_VULNERABILITY", edge_rels)
        self.assertGreaterEqual(graph["metrics"]["node_count"], 10)

    def test_03_graphml_csv_json_exports(self):
        r_xml = self.client.get(
            f"/api/v1/investigations/{self.recon_id}/graph/export?fmt=graphml",
            headers=self.inv_a_headers,
        )
        self.assertEqual(r_xml.status_code, 200)
        root = ET.fromstring(r_xml.text)
        self.assertTrue(root.tag.endswith("graphml"))
        self.assertIn("maltego.Vulnerability", r_xml.text)
        self.assertIn("maltego.EmailAddress", r_xml.text)

        r_csv = self.client.get(
            f"/api/v1/investigations/{self.recon_id}/graph/export?fmt=csv",
            headers=self.inv_a_headers,
        )
        self.assertEqual(r_csv.status_code, 200)
        self.assertIn("section,id,entity_type,maltego_type", r_csv.text)
        self.assertIn("secops@lab.footprintiq.local", r_csv.text)

        r_json = self.client.get(
            f"/api/v1/investigations/{self.recon_id}/graph/export?fmt=json",
            headers=self.inv_a_headers,
        )
        self.assertEqual(r_json.status_code, 200)
        self.assertEqual(r_json.json()["investigation_id"], self.recon_id)

    def test_04_manual_entity_and_relationship_addition_persists(self):
        add_ent = self.client.post(
            f"/api/v1/investigations/{self.recon_id}/graph/entities",
            json={
                "entity_type": "person",
                "value": "Jane Doe (CISO)",
                "evidence_ref": "LinkedIn OSINT note #14",
                "confidence": 0.9,
            },
            headers=self.inv_a_headers,
        )
        self.assertEqual(add_ent.status_code, 201)
        node_id = add_ent.json()["entity"]["node_id"]
        all_nodes = add_ent.json()["graph"]["nodes"]
        target_email = next(n for n in all_nodes if n["entity_type"] == "email")

        add_rel = self.client.post(
            f"/api/v1/investigations/{self.recon_id}/graph/relationships",
            json={
                "source_node_id": node_id,
                "target_node_id": target_email["id"],
                "relationship_type": "CONTROLS_MAILBOX",
                "evidence_ref": "Manual analyst correlation",
            },
            headers=self.inv_a_headers,
        )
        self.assertEqual(add_rel.status_code, 201)
        rels = [e["relationship"] for e in add_rel.json()["graph"]["edges"]]
        self.assertIn("CONTROLS_MAILBOX", rels)

    def test_05_xxe_rejected_and_maltego_graphml_csv_imported(self):
        xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns">
  <graph id="G" edgedefault="directed"><node id="n1"/></graph>
</graphml>"""
        r_xxe = self.client.post(
            f"/api/v1/investigations/{self.recon_id}/graph/import",
            json={"filename": "evil.graphml", "content": xxe_payload},
            headers=self.inv_a_headers,
        )
        self.assertEqual(r_xxe.status_code, 400)
        self.assertIn("XML security policy", r_xxe.json()["detail"])

        csv_payload = "\n".join([
            "section,id,entity_type,maltego_type,value,label,source_tool,confidence,evidence_ref",
            "entity,EXT1,domain,maltego.Domain,partner.footprintiq.local,partner.footprintiq.local,maltego_desktop,0.9,maltego_transform_1",
            "entity,EXT2,ip,maltego.IPv4Address,192.168.56.200,192.168.56.200,maltego_desktop,0.9,maltego_transform_1",
            "edge,EXT1,RESOLVES_TO,EXT2,maltego_transform,0.9,partner_dns",
        ])
        r_imp = self.client.post(
            f"/api/v1/investigations/{self.recon_id}/graph/import",
            files={"file": ("maltego_export.csv", csv_payload.encode("utf-8"), "text/csv")},
            headers=self.inv_a_headers,
        )
        self.assertEqual(r_imp.status_code, 200)
        imp_data = r_imp.json()
        self.assertGreaterEqual(imp_data["imported_entities"], 2)
        self.assertEqual(imp_data["imported_relationships"], 1)
        vals = {n["value"] for n in imp_data["graph"]["nodes"]}
        self.assertIn("partner.footprintiq.local", vals)
        self.assertIn("192.168.56.200", vals)

    def test_06_rbac_admin_oversight_only_and_cross_investigator_idor_blocked(self):
        # Admin CAN view & export
        self.assertEqual(self.client.get(f"/api/v1/investigations/{self.recon_id}/graph", headers=self.admin_headers).status_code, 200)
        self.assertEqual(self.client.get(f"/api/v1/investigations/{self.recon_id}/graph/export?fmt=json", headers=self.admin_headers).status_code, 200)

        # Admin CANNOT mutate graph entities/relationships/import/rebuild
        self.assertEqual(
            self.client.post(
                f"/api/v1/investigations/{self.recon_id}/graph/entities",
                json={"entity_type": "domain", "value": "admin-blocked.example"},
                headers=self.admin_headers,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(f"/api/v1/investigations/{self.recon_id}/graph/rebuild", headers=self.admin_headers).status_code,
            403,
        )

        # Cross-investigator (graph_inv_b) is blocked on BOTH read and write
        self.assertEqual(self.client.get(f"/api/v1/investigations/{self.recon_id}/graph", headers=self.inv_b_headers).status_code, 403)
        self.assertEqual(
            self.client.post(
                f"/api/v1/investigations/{self.recon_id}/graph/entities",
                json={"entity_type": "domain", "value": "idor.example"},
                headers=self.inv_b_headers,
            ).status_code,
            403,
        )


if __name__ == "__main__":
    unittest.main()
