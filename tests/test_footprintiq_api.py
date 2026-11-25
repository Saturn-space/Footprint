"""
FootprintIQ - Unit Tests for FastAPI Application and API Routers
"""

import unittest
from fastapi.testclient import TestClient
from src.api.app import app


class TestFootprintIQAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        # Authenticate approved investigator
        resp = cls.client.post("/api/v1/auth/login", json={"username": "investigator1", "password": "Investigator1Pass2026!"})
        cls.token = resp.json().get("access_token")
        cls.headers = {"Authorization": f"Bearer {cls.token}"}

    def test_health_endpoint(self):
        resp = self.client.get("/api/v1/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["platform"], "FootprintIQ")
        self.assertIn("database", data)
        self.assertIn("object_storage", data)
        self.assertIn("network_scanner", data)

    def test_investigations_lifecycle(self):
        # Create
        create_resp = self.client.post(
            "/api/v1/investigations",
            json={"title": "Automated Unit Test Investigation", "description": "CI test run"},
            headers=self.headers
        )
        self.assertEqual(create_resp.status_code, 201)
        inv = create_resp.json()
        inv_id = inv["investigation_id"]
        self.assertTrue(inv_id.startswith("INV-"))

        # List
        list_resp = self.client.get("/api/v1/investigations", headers=self.headers)
        self.assertEqual(list_resp.status_code, 200)
        self.assertTrue(any(i["investigation_id"] == inv_id for i in list_resp.json()))

        # Get details
        get_resp = self.client.get(f"/api/v1/investigations/{inv_id}", headers=self.headers)
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.json()["title"], "Automated Unit Test Investigation")

    def test_targets_endpoint(self):
        inv_resp = self.client.post(
            "/api/v1/investigations",
            json={"title": "Targets Unit Investigation", "description": "Scope setup"},
            headers=self.headers
        )
        self.assertEqual(inv_resp.status_code, 201)
        inv_id = inv_resp.json()["investigation_id"]

        # Add target
        target_resp = self.client.post(
            "/api/v1/targets",
            json={
                "investigation_id": inv_id,
                "target": "192.168.56.111",
                "name": "Metasploitable2 VM",
                "scope": "192.168.56.0/24"
            },
            headers=self.headers
        )
        self.assertEqual(target_resp.status_code, 201)
        self.assertEqual(target_resp.json()["target"], "192.168.56.111")

        # List targets
        list_resp = self.client.get("/api/v1/targets", headers=self.headers)
        self.assertEqual(list_resp.status_code, 200)
        self.assertTrue(any(t["target"] == "192.168.56.111" for t in list_resp.json()))

    def test_scan_unauthorized_target_rejection(self):
        inv_resp = self.client.post(
            "/api/v1/investigations",
            json={"title": "Unauthorized Target Reject Inv", "description": "Scope check"},
            headers=self.headers
        )
        self.assertEqual(inv_resp.status_code, 201)
        inv_id = inv_resp.json()["investigation_id"]

        resp = self.client.post(
            "/api/v1/scans",
            json={
                "investigation_id": inv_id,
                "scan_type": "nmap_nse",
                "target": "8.8.8.8"
            },
            headers=self.headers
        )
        self.assertEqual(resp.status_code, 403)

    def test_scan_investigation_scope_authorization(self):
        # 1. Create investigation
        inv_resp = self.client.post(
            "/api/v1/investigations",
            json={"title": "Scoped Scan Investigation", "description": "Testing scope containment"},
            headers=self.headers
        )
        self.assertEqual(inv_resp.status_code, 201)
        inv_id = inv_resp.json()["investigation_id"]

        # 2. Scanning 192.168.56.111 before it's registered under inv_id should fail with 403
        scan_resp_unregistered = self.client.post(
            "/api/v1/scans",
            json={
                "investigation_id": inv_id,
                "scan_type": "network_discovery",
                "target": "192.168.56.111"
            },
            headers=self.headers
        )
        self.assertEqual(scan_resp_unregistered.status_code, 403)
        self.assertIn("NOT registered as an authorized target", scan_resp_unregistered.json()["detail"])

        # 3. Add target to this investigation
        tgt_resp = self.client.post(
            "/api/v1/targets",
            json={
                "investigation_id": inv_id,
                "target": "192.168.56.111",
                "name": "Metasploitable2",
                "scope": "Lab Subnet",
                "permitted_profiles": "lab-basic,default"
            },
            headers=self.headers
        )
        self.assertEqual(tgt_resp.status_code, 201)

        # 4. Now scan should be accepted and execute
        scan_resp_ok = self.client.post(
            "/api/v1/scans",
            json={
                "investigation_id": inv_id,
                "scan_type": "network_discovery",
                "target": "192.168.56.111",
                "profile": "default"
            },
            headers=self.headers
        )
        self.assertEqual(scan_resp_ok.status_code, 200)
        self.assertEqual(scan_resp_ok.json()["status"], "COMPLETED")

    def test_reports_security_and_traversal_prevention(self):
        # Test path traversal prevention
        trav_resp = self.client.get("/api/v1/reports/..%2F..%2Fetc%2Fpasswd/download")
        self.assertIn(trav_resp.status_code, [400, 403, 404])

        # Test listing reports
        list_resp = self.client.get("/api/v1/reports")
        self.assertEqual(list_resp.status_code, 200)
        self.assertIsInstance(list_resp.json(), list)

    def test_dashboard_ui_html_response(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("FootprintIQ", resp.text)
        self.assertIn("Investigation Intelligence Dashboard", resp.text)
        self.assertIn("Scope Authorized", resp.text)

    def test_all_ui_views_and_static_assets(self):
        # 1. Investigations view
        inv_ui = self.client.get("/investigations")
        self.assertEqual(inv_ui.status_code, 200)
        self.assertIn("Investigations &amp; Scope Containment", inv_ui.text)

        # 2. Scans view
        scans_ui = self.client.get("/scans")
        self.assertEqual(scans_ui.status_code, 200)
        self.assertIn("Reconnaissance &amp; Vulnerability Scans", scans_ui.text)

        # 3. Findings view
        findings_ui = self.client.get("/findings")
        self.assertEqual(findings_ui.status_code, 200)
        self.assertIn("Vulnerability Findings &amp; Correlation", findings_ui.text)

        # 4. Evidence view
        evidence_ui = self.client.get("/evidence")
        self.assertEqual(evidence_ui.status_code, 200)
        self.assertIn("SeaweedFS Cryptographic Evidence Catalog", evidence_ui.text)

        # 5. Reports view
        reports_ui = self.client.get("/reports")
        self.assertEqual(reports_ui.status_code, 200)
        self.assertIn("Security Reports &amp; Executive Deliverables", reports_ui.text)

        # 6. Static CSS asset
        css_resp = self.client.get("/static/css/app.css")
        self.assertEqual(css_resp.status_code, 200)
        self.assertIn("prefers-reduced-motion", css_resp.text)
        self.assertIn("reveal-on-scroll", css_resp.text)

        # 7. Static JS asset
        js_resp = self.client.get("/static/js/app.js")
        self.assertEqual(js_resp.status_code, 200)
        self.assertIn("IntersectionObserver", js_resp.text)

    def test_reports_generation_and_download(self):
        # 1. Nonexistent investigation must yield 404
        bad_resp = self.client.post(
            "/api/v1/reports/generate",
            json={"investigation_id": "INV-NONEXISTENT-999"},
            headers=self.headers
        )
        self.assertEqual(bad_resp.status_code, 404)

        # 2. Create valid investigation
        inv_resp = self.client.post(
            "/api/v1/investigations",
            json={"title": "Report Testing Investigation", "description": "Unit test report generation"},
            headers=self.headers
        )
        self.assertEqual(inv_resp.status_code, 201)
        inv_id = inv_resp.json()["investigation_id"]

        # 3. Generate report
        gen_resp = self.client.post(
            "/api/v1/reports/generate",
            json={"investigation_id": inv_id},
            headers=self.headers
        )
        self.assertEqual(gen_resp.status_code, 201)
        self.assertTrue(gen_resp.json()["pdf_report_path"].endswith(".pdf"))

        # 4. Download latest report
        dl_resp = self.client.get("/api/v1/reports/download")
        self.assertEqual(dl_resp.status_code, 200)
        self.assertEqual(dl_resp.headers["content-type"], "application/pdf")
        self.assertGreater(len(dl_resp.content), 1000)


if __name__ == "__main__":
    unittest.main()

