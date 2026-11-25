"""
FootprintIQ - Comprehensive Unit & Integration Tests for Recon Campaigns Platform
"""

import unittest
import re
import os
from fastapi.testclient import TestClient
from src.api.app import app
from src.db.repository import FootprintIQRepository


class TestReconCampaigns(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        # Authenticate approved investigator
        login_resp = cls.client.post("/api/v1/auth/login", json={"username": "investigator1", "password": "Investigator1Pass2026!"})
        cls.token = login_resp.json().get("access_token")
        cls.headers = {"Authorization": f"Bearer {cls.token}"}
        cls.repo = FootprintIQRepository()

    def test_01_create_recon_campaign_success(self):
        resp = self.client.post(
            "/api/v1/recon",
            json={
                "name": "Perimeter Audit Metasploitable2",
                "target_value": "192.168.56.111",
                "target_type": "ipv4",
                "purpose": "Security Audit",
                "scope_description": "Local Lab Authorized Target",
                "allowed_ports": "21,22,80,443",
                "selected_scan_types": "combined"
            },
            headers=self.headers
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertIn("recon_id", data)
        self.assertTrue(re.match(r"^FIQ-REC-\d{8}-[A-F0-9]{4}$", data["recon_id"]))
        self.assertEqual(data["target_value"], "192.168.56.111")
        self.assertIn(data["status"], ["Authorized", "Pending"])

    def test_02_create_recon_campaign_unauthorized_target(self):
        # Fail-closed check against unauthorized public IP
        resp = self.client.post(
            "/api/v1/recon",
            json={
                "name": "Unauthorized Public IP Scan",
                "target_value": "8.8.8.8",
                "target_type": "ipv4"
            },
            headers=self.headers
        )
        self.assertEqual(resp.status_code, 403)

    def test_03_list_and_get_recon_campaigns(self):
        # Create campaign
        create_resp = self.client.post(
            "/api/v1/recon",
            json={
                "name": "Lookup Test Campaign",
                "target_value": "192.168.56.111",
                "target_type": "ipv4",
                "purpose": "Verification"
            },
            headers=self.headers
        )
        recon_id = create_resp.json()["recon_id"]

        # List
        list_resp = self.client.get("/api/v1/recon", headers=self.headers)
        self.assertEqual(list_resp.status_code, 200)
        camps = list_resp.json()
        self.assertTrue(any(c["recon_id"] == recon_id for c in camps))

        # Get details
        detail_resp = self.client.get(f"/api/v1/recon/{recon_id}", headers=self.headers)
        self.assertEqual(detail_resp.status_code, 200)
        detail = detail_resp.json()
        self.assertEqual(detail["recon_id"], recon_id)
        self.assertEqual(detail["name"], "Lookup Test Campaign")
        self.assertIn("targets", detail)
        self.assertIn("scans", detail)

    def test_04_saved_profiles(self):
        # List built-in profiles
        resp = self.client.get("/api/v1/recon/profiles", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        profiles = resp.json()
        self.assertTrue(len(profiles) >= 5)
        names = [p["name"] for p in profiles]
        self.assertIn("Quick Demo", names)
        self.assertIn("Basic Discovery", names)

        # Create custom profile
        post_prof = self.client.post(
            "/api/v1/recon/profiles",
            json={
                "name": "Custom Web API Audit",
                "description": "Port 8000 and 8080 checks",
                "category": "web",
                "config_json": '{"ports": "8000,8080"}'
            },
            headers=self.headers
        )
        self.assertEqual(post_prof.status_code, 201)

    def test_05_remediation_tracking(self):
        # Create campaign
        create_resp = self.client.post(
            "/api/v1/recon",
            json={"name": "Remediation Campaign", "target_value": "192.168.56.111"},
            headers=self.headers
        )
        recon_id = create_resp.json()["recon_id"]

        # Insert finding into repo under recon_id
        finding = self.repo.add_vulnerability_finding(
            investigation_id=recon_id,
            finding_dict={
                "title": "vsftpd 2.3.4 Backdoor Execution",
                "severity": "Critical",
                "description": "Remote backdoor on port 21",
                "cve_identifiers": "CVE-2011-2523",
                "cvss_score": 9.8,
                "target_ip": "192.168.56.111",
                "port": 21,
                "detection_source": "nmap_nse"
            }
        )
        finding_id = finding["finding_id"]

        # Update remediation status
        rem_resp = self.client.post(
            f"/api/v1/recon/{recon_id}/remediation",
            json={
                "finding_id": finding_id,
                "status": "resolved",
                "notes": "Upgraded vsftpd to 3.0.5; backdoor neutralized."
            },
            headers=self.headers
        )
        self.assertEqual(rem_resp.status_code, 200)
        rem_data = rem_resp.json()
        self.assertEqual(rem_data["status"], "SUCCESS")
        self.assertEqual(rem_data["new_status"], "resolved")

        # Verify updated finding in list
        f_resp = self.client.get(f"/api/v1/recon/{recon_id}/findings", headers=self.headers)
        self.assertEqual(f_resp.status_code, 200)
        items = f_resp.json()
        target_f = next((item for item in items if item["finding_id"] == finding_id), None)
        self.assertIsNotNone(target_f)
        self.assertEqual(target_f.get("remediation_status"), "resolved")

    def test_06_campaign_comparison(self):
        # Create baseline campaign 1
        c1 = self.client.post("/api/v1/recon", json={"name": "Baseline Scan", "target_value": "192.168.56.111"}, headers=self.headers).json()
        id1 = c1["recon_id"]
        self.repo.add_vulnerability_finding(investigation_id=id1, finding_dict={"title": "FTP Vuln", "severity": "High", "target_ip": "192.168.56.111", "port": 21, "detection_source": "nmap"})

        # Create new campaign 2
        c2 = self.client.post("/api/v1/recon", json={"name": "Followup Scan", "target_value": "192.168.56.111"}, headers=self.headers).json()
        id2 = c2["recon_id"]
        self.repo.add_vulnerability_finding(investigation_id=id2, finding_dict={"title": "FTP Vuln", "severity": "High", "target_ip": "192.168.56.111", "port": 21, "detection_source": "nmap"})
        self.repo.add_vulnerability_finding(investigation_id=id2, finding_dict={"title": "HTTP Vuln", "severity": "Medium", "target_ip": "192.168.56.111", "port": 80, "detection_source": "nmap"})

        # Compare c2 vs c1
        comp_resp = self.client.get(f"/api/v1/recon/{id2}/compare/{id1}", headers=self.headers)
        self.assertEqual(comp_resp.status_code, 200)
        comp_data = comp_resp.json()
        self.assertIn("exposure_score_delta", comp_data)
        self.assertIn("new_findings", comp_data)
        self.assertIn("persistent_findings", comp_data)
        self.assertEqual(len(comp_data["persistent_findings"]), 1)
        self.assertEqual(len(comp_data["new_findings"]), 1)

    def test_07_recon_ui_views(self):
        # Test Campaign List UI
        resp_list = self.client.get("/recon")
        self.assertEqual(resp_list.status_code, 200)
        self.assertIn(b"Reconnaissance Campaigns", resp_list.content)

        # Test Campaign Creation Wizard UI
        resp_new = self.client.get("/recon/new")
        self.assertEqual(resp_new.status_code, 200)
        self.assertIn(b"New Campaign Wizard", resp_new.content)

        # Create campaign for live & results testing
        c = self.client.post("/api/v1/recon", json={"name": "UI Test Camp", "target_value": "192.168.56.111"}, headers=self.headers).json()
        rec_id = c["recon_id"]

        # Test Live Console UI
        resp_live = self.client.get(f"/recon/{rec_id}/live")
        self.assertEqual(resp_live.status_code, 200)
        self.assertIn(b"Live Execution Telemetry", resp_live.content)

        # Test Results Dashboard UI
        resp_res = self.client.get(f"/recon/{rec_id}/results")
        self.assertEqual(resp_res.status_code, 200)
        self.assertIn(b"Results Dashboard", resp_res.content)
        self.assertIn(b"Executive View", resp_res.content)
        self.assertIn(b"Technical &amp; Remediation", resp_res.content)

    def test_08_dual_pdf_reports(self):
        # Create campaign
        c = self.client.post("/api/v1/recon", json={"name": "PDF Report Camp", "target_value": "192.168.56.111"}, headers=self.headers).json()
        rec_id = c["recon_id"]

        # Add sample finding
        self.repo.add_vulnerability_finding(
            investigation_id=rec_id,
            finding_dict={
                "title": "Sample Apache Vulnerability",
                "severity": "Medium",
                "target_ip": "192.168.56.111",
                "port": 80,
                "detection_source": "nmap_nse"
            }
        )

        # Generate Executive PDF
        exec_resp = self.client.post(
            "/api/v1/reports/generate",
            json={"investigation_id": rec_id, "report_format": "executive"},
            headers=self.headers
        )
        self.assertEqual(exec_resp.status_code, 201)
        exec_data = exec_resp.json()
        self.assertIn("download_url", exec_data)
        self.assertTrue(exec_data["file_name"].endswith(".pdf"))

        # Generate Technical PDF
        tech_resp = self.client.post(
            "/api/v1/reports/generate",
            json={"investigation_id": rec_id, "report_format": "technical"},
            headers=self.headers
        )
        self.assertEqual(tech_resp.status_code, 201)
        tech_data = tech_resp.json()
        self.assertIn("download_url", tech_data)
        self.assertTrue(tech_data["file_name"].endswith(".pdf"))


if __name__ == "__main__":
    unittest.main()
