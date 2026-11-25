"""
FootprintIQ - RBAC, Ownership Isolation, CSRF, Report Analysis & Audit Trail Verification Suite
"""

import os
import json
import unittest
from fastapi.testclient import TestClient

from src.api.app import app
from src.db.repository import FootprintIQRepository
from src.services.auth_service import AuthService


class TestRBACAndReportAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.repo = FootprintIQRepository()
        AuthService(repo=cls.repo)

        cls.admin_login = cls._login("admin", "AdminPass2026!")
        cls.inv1_login = cls._login("investigator1", "Investigator1Pass2026!")
        cls.inv2_login = cls._login("investigator2", "Investigator2Pass2026!")

        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_login['access_token']}"}
        cls.inv1_headers = {"Authorization": f"Bearer {cls.inv1_login['access_token']}"}
        cls.inv2_headers = {"Authorization": f"Bearer {cls.inv2_login['access_token']}"}

    @classmethod
    def _login(cls, username: str, password: str) -> dict:
        c = TestClient(app)
        resp = c.post("/api/v1/auth/login", json={"username": username, "password": password})
        assert resp.status_code == 200, f"Login failed for {username}: {resp.text}"
        return resp.json()

    def test_01_default_deny_unauthenticated_and_ui_redirects(self):
        anon = TestClient(app)
        for path in [
            "/api/v1/investigations",
            "/api/v1/recon",
            "/api/v1/targets",
            "/api/v1/scans",
            "/api/v1/findings",
            "/api/v1/evidence",
            "/api/v1/reports",
            "/api/v1/admin/audit-logs",
        ]:
            res = anon.get(path)
            self.assertEqual(res.status_code, 401, f"Expected 401 on {path}, got {res.status_code}")

        for ui_path in ["/", "/recon", "/recon/new", "/reports", "/admin/users", "/admin/audit-logs"]:
            res = anon.get(ui_path, follow_redirects=False)
            self.assertEqual(res.status_code, 303, f"Expected 303 redirect on {ui_path}, got {res.status_code}")
            self.assertEqual(res.headers.get("location"), "/login")

        health = anon.get("/api/v1/health")
        self.assertEqual(health.status_code, 200)
        body_str = json.dumps(health.json()).lower()
        self.assertNotIn("secret_key", body_str)
        self.assertNotIn("access_key", body_str)
        self.assertNotIn("adminpass", body_str)

    def test_02_registration_privilege_escalation_and_user_lifecycle(self):
        # Attempt self-registration as admin -> 403
        esc = self.client.post(
            "/api/v1/auth/register",
            json={
                "username": "evil_admin_try",
                "email": "evil@example.com",
                "password": "StrongPassword2026!",
                "role": "admin",
            },
        )
        self.assertEqual(esc.status_code, 403)

        # Valid investigator registration stays unapproved until Admin acts
        reg = self.client.post(
            "/api/v1/auth/register",
            json={
                "username": "pending_analyst_rbac",
                "email": "pending_rbac@footprintiq.internal",
                "password": "StrongPassword2026!",
                "role": "investigator",
            },
        )
        self.assertEqual(reg.status_code, 201)
        self.assertFalse(reg.json()["is_approved"])

        # Investigator cannot approve
        non_admin_app = self.client.post(
            "/api/v1/auth/approve/pending_analyst_rbac",
            headers=self.inv1_headers,
        )
        self.assertEqual(non_admin_app.status_code, 403)

        # Unapproved login rejected
        pre_login = self.client.post(
            "/api/v1/auth/login",
            json={"username": "pending_analyst_rbac", "password": "StrongPassword2026!"},
        )
        self.assertEqual(pre_login.status_code, 403)

        # Admin approves -> login succeeds
        app_res = self.client.post(
            "/api/v1/auth/approve/pending_analyst_rbac",
            headers=self.admin_headers,
        )
        self.assertEqual(app_res.status_code, 200)
        ok_login = self._login("pending_analyst_rbac", "StrongPassword2026!")
        analyst_headers = {"Authorization": f"Bearer {ok_login['access_token']}"}

        # Admin suspends -> active JWT immediately blocked (403) & new login blocked
        susp = self.client.patch(
            "/api/v1/auth/users/pending_analyst_rbac/status",
            json={"is_active": False},
            headers=self.admin_headers,
        )
        self.assertEqual(susp.status_code, 200)
        self.assertEqual(self.client.get("/api/v1/recon", headers=analyst_headers).status_code, 403)
        self.assertEqual(
            self.client.post(
                "/api/v1/auth/login",
                json={"username": "pending_analyst_rbac", "password": "StrongPassword2026!"},
            ).status_code,
            403,
        )

        # Admin reactivates & prevents self-demotion
        react = self.client.patch(
            "/api/v1/auth/users/pending_analyst_rbac/status",
            json={"is_active": True},
            headers=self.admin_headers,
        )
        self.assertEqual(react.status_code, 200)
        self.assertEqual(self.client.get("/api/v1/recon", headers=analyst_headers).status_code, 200)

        self_demote = self.client.patch(
            "/api/v1/auth/users/admin/role",
            json={"role": "investigator"},
            headers=self.admin_headers,
        )
        self.assertEqual(self_demote.status_code, 403)

        # Pending rejection workflow
        reg2 = self.client.post(
            "/api/v1/auth/register",
            json={
                "username": "reject_me_rbac",
                "email": "reject_rbac@footprintiq.internal",
                "password": "StrongPassword2026!",
            },
        )
        self.assertEqual(reg2.status_code, 201)
        rej = self.client.post("/api/v1/auth/reject/reject_me_rbac", headers=self.admin_headers)
        self.assertEqual(rej.status_code, 200)

    def test_03_admin_read_only_vs_investigator_execution_and_ui_nav(self):
        # Investigator1 creates investigation & recon campaign
        inv_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Inv1 RBAC Audit", "description": "Scoped test"},
            headers=self.inv1_headers,
        )
        self.assertEqual(inv_res.status_code, 201)
        inv_id = inv_res.json()["investigation_id"]

        camp_res = self.client.post(
            "/api/v1/recon",
            json={
                "name": "Inv1 Ownership Recon",
                "target_value": "192.0.2.50",
                "target_type": "ipv4",
                "purpose": "RBAC and Report Analysis Verification",
                "selected_scan_types": "draft",
                "authorization_confirmed": True,
            },
            headers=self.inv1_headers,
        )
        self.assertEqual(camp_res.status_code, 201)
        recon_id = camp_res.json()["recon_id"]

        # Admin MUST be blocked (403) from creating/modifying/scanning/generating
        self.assertEqual(
            self.client.post(
                "/api/v1/investigations",
                json={"title": "Admin Should Fail", "description": "Blocked"},
                headers=self.admin_headers,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/recon",
                json={"name": "Admin Campaign Blocked", "target_value": "192.0.2.50"},
                headers=self.admin_headers,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.put(
                f"/api/v1/recon/{recon_id}",
                json={"purpose": "Admin Mutate Blocked"},
                headers=self.admin_headers,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                f"/api/v1/recon/{recon_id}/start",
                json={"scan_type": "passive"},
                headers=self.admin_headers,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/targets",
                json={
                    "investigation_id": inv_id,
                    "target": "192.0.2.50",
                    "name": "Lab",
                    "scope": "Lab",
                },
                headers=self.admin_headers,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/scans",
                json={
                    "investigation_id": inv_id,
                    "scan_type": "passive",
                    "target": "192.0.2.50",
                },
                headers=self.admin_headers,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/reports/generate",
                json={"investigation_id": recon_id, "report_format": "executive"},
                headers=self.admin_headers,
            ).status_code,
            403,
        )
        # Admin blocked on creation UI routes & PDF generation shortcut before report exists
        self.assertEqual(self.client.get("/recon/new", headers=self.admin_headers).status_code, 403)
        self.assertEqual(self.client.get(f"/recon/{recon_id}/workspace", headers=self.admin_headers).status_code, 403)
        self.assertEqual(self.client.get(f"/recon/{recon_id}/pdf?format=executive", headers=self.admin_headers).status_code, 403)

        # Admin CAN read all oversight APIs & UIs
        self.assertEqual(self.client.get(f"/api/v1/recon/{recon_id}", headers=self.admin_headers).status_code, 200)
        self.assertEqual(self.client.get(f"/api/v1/investigations/{inv_id}", headers=self.admin_headers).status_code, 200)
        admin_dash = self.client.get("/", headers=self.admin_headers)
        self.assertEqual(admin_dash.status_code, 200)
        self.assertIn("All Investigations", admin_dash.text)
        self.assertIn("Audit Logs", admin_dash.text)
        self.assertNotIn("New Investigation", admin_dash.text)

        inv1_dash = self.client.get("/", headers=self.inv1_headers)
        self.assertEqual(inv1_dash.status_code, 200)
        self.assertIn("My Investigations", inv1_dash.text)
        self.assertIn("New Investigation", inv1_dash.text)
        self.assertNotIn("/admin/audit-logs", inv1_dash.text)

        # Investigator cannot hit admin routes
        for apath in ["/admin/users", "/admin/scanners", "/admin/system", "/admin/audit-logs", "/api/v1/admin/audit-logs"]:
            self.assertEqual(self.client.get(apath, headers=self.inv1_headers).status_code, 403, f"Admin route {apath} leaked to investigator")

    def test_04_cross_investigator_idor_isolation_and_explicit_sharing(self):
        # Create finding, evidence, and report under Investigator1 campaign
        camp_res = self.client.post(
            "/api/v1/recon",
            json={
                "name": "Inv1 Private Campaign",
                "target_value": "192.0.2.77",
                "target_type": "ipv4",
                "purpose": "IDOR & Integrated Report Analysis Test",
                "selected_scan_types": "draft",
                "authorization_confirmed": True,
            },
            headers=self.inv1_headers,
        )
        self.assertEqual(camp_res.status_code, 201)
        recon_id = camp_res.json()["recon_id"]

        # Persist a deterministic finding so report analysis computes non-empty vulnerability insights
        scan_rec = self.repo.create_scan_execution(
            investigation_id=recon_id,
            scan_type="nmap_nse",
            target="192.0.2.77",
            profile="lab-basic",
            recon_id=recon_id,
        )
        finding_rec = self.repo.add_vulnerability_finding(
            investigation_id=recon_id,
            scan_id=scan_rec["scan_id"],
            finding_dict={
                "target_ip": "192.0.2.77",
                "title": "Legacy vsftpd Backdoor Exposure",
                "severity": "Critical",
                "cvss_score": 9.8,
                "cve_identifiers": "CVE-2011-2523",
                "port": 21,
                "service": "ftp",
                "detection_source": "nmap_nse",
                "description": "Identified unpatched FTP daemon indicator on port 21.",
                "remediation": "Upgrade or disable vsftpd 2.3.4 immediately.",
                "evidence_snippet": "vsftpd 2.3.4 banner matched",
            },
        )

        # Generate Executive Report as Investigator1
        rep_res = self.client.post(
            "/api/v1/reports/generate",
            json={"investigation_id": recon_id, "report_format": "executive"},
            headers=self.inv1_headers,
        )
        self.assertEqual(rep_res.status_code, 201, rep_res.text)
        rep_data = rep_res.json()
        report_key = rep_data["report_id"] or rep_data["file_name"]
        fname = rep_data["file_name"]

        # Verify PDF was created and exists cleanly
        self.assertTrue(os.path.isfile(rep_data["pdf_report_path"]))

        # Investigator2 MUST be blocked (403) across ALL endpoints & UI for Inv1's recon/finding/report
        self.assertEqual(self.client.get(f"/api/v1/recon/{recon_id}", headers=self.inv2_headers).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/recon/{recon_id}/events", headers=self.inv2_headers).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/recon/{recon_id}/findings", headers=self.inv2_headers).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/findings/{finding_rec['finding_id']}", headers=self.inv2_headers).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/scans/{scan_rec['scan_id']}", headers=self.inv2_headers).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/reports/{report_key}/analysis", headers=self.inv2_headers).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/reports/{fname}/download?investigation_id={recon_id}", headers=self.inv2_headers).status_code, 403)
        self.assertEqual(self.client.get(f"/recon/{recon_id}/results", headers=self.inv2_headers).status_code, 403)
        self.assertEqual(self.client.get(f"/reports/{report_key}", headers=self.inv2_headers).status_code, 403)

        # Investigator2's list endpoints must NOT contain Inv1's campaign or report
        inv2_recons = [c["recon_id"] for c in self.client.get("/api/v1/recon", headers=self.inv2_headers).json()]
        self.assertNotIn(recon_id, inv2_recons)
        inv2_reports = [r["file_name"] for r in self.client.get("/api/v1/reports", headers=self.inv2_headers).json()]
        self.assertNotIn(fname, inv2_reports)

        # Admin explicitly shares Inv1 campaign with Investigator2
        share_res = self.client.post(
            f"/api/v1/admin/investigations/{recon_id}/share",
            json={"username": "investigator2", "permission_level": "collaborator"},
            headers=self.admin_headers,
        )
        self.assertEqual(share_res.status_code, 200, share_res.text)

        # Now Investigator2 can view, analyse, and download the shared campaign/report!
        self.assertEqual(self.client.get(f"/api/v1/recon/{recon_id}", headers=self.inv2_headers).status_code, 200)
        self.assertEqual(self.client.get(f"/api/v1/reports/{report_key}/analysis", headers=self.inv2_headers).status_code, 200)
        self.assertEqual(self.client.get(f"/reports/{report_key}", headers=self.inv2_headers).status_code, 200)

        # Revoke share -> Investigator2 is isolated again
        rev_res = self.client.delete(
            f"/api/v1/admin/investigations/{recon_id}/share/investigator2",
            headers=self.admin_headers,
        )
        self.assertEqual(rev_res.status_code, 200)
        self.assertEqual(self.client.get(f"/api/v1/reports/{report_key}/analysis", headers=self.inv2_headers).status_code, 403)

        # Admin & Investigator1 CAN inspect integrated Report Analysis API & HTML page
        an_api = self.client.get(f"/api/v1/reports/{report_key}/analysis", headers=self.admin_headers)
        self.assertEqual(an_api.status_code, 200)
        an_json = an_api.json()
        for key in ["executive_analysis", "vulnerability_analysis", "risk_interpretation", "remediation_analysis", "assessment_limitations"]:
            self.assertIn(key, an_json)
        self.assertIn("CVE-2011-2523", an_json["vulnerability_analysis"]["cve_inventory"])
        self.assertFalse(an_json["assessment_limitations"]["is_complete"])
        self.assertIsNotNone(an_json["assessment_limitations"]["incomplete_warning"])

        an_html = self.client.get(f"/reports/{report_key}", headers=self.admin_headers)
        self.assertEqual(an_html.status_code, 200)
        self.assertIn("Integrated Report Analysis", an_html.text)
        self.assertIn("CVE-2011-2523", an_html.text)
        self.assertIn("investigator1", an_html.text)

        # Admin CAN download existing report
        dl = self.client.get(f"/api/v1/reports/{fname}/download?investigation_id={recon_id}", headers=self.admin_headers)
        self.assertEqual(dl.status_code, 200)
        self.assertEqual(dl.headers.get("content-type"), "application/pdf")

    def test_05_csrf_cookie_enforcement(self):
        cookie_client = TestClient(app)
        login_res = cookie_client.post(
            "/api/v1/auth/login",
            json={"username": "investigator1", "password": "Investigator1Pass2026!"},
        )
        self.assertEqual(login_res.status_code, 200)
        csrf_tok = login_res.json()["csrf_token"]
        self.assertTrue(csrf_tok)

        # Cookie-authenticated POST without X-CSRF-Token header -> 403
        no_csrf = cookie_client.post(
            "/api/v1/investigations",
            json={"title": "Missing CSRF Check", "description": "Should fail"},
        )
        self.assertEqual(no_csrf.status_code, 403)

        # Cookie-authenticated POST with invalid X-CSRF-Token -> 403
        bad_csrf = cookie_client.post(
            "/api/v1/investigations",
            json={"title": "Invalid CSRF Check", "description": "Should fail"},
            headers={"X-CSRF-Token": "invalid-csrf-nonce"},
        )
        self.assertEqual(bad_csrf.status_code, 403)

        # Cookie-authenticated POST with matching X-CSRF-Token -> 201
        good_csrf = cookie_client.post(
            "/api/v1/investigations",
            json={"title": "Valid CSRF Check", "description": "Should succeed"},
            headers={"X-CSRF-Token": csrf_tok},
        )
        self.assertEqual(good_csrf.status_code, 201)

    def test_06_audit_trail_integrity_and_no_secret_leak(self):
        logs_res = self.client.get("/api/v1/admin/audit-logs?limit=250", headers=self.admin_headers)
        self.assertEqual(logs_res.status_code, 200)
        logs = logs_res.json()
        self.assertTrue(len(logs) > 0)
        actions = {row["action"] for row in logs}
        self.assertIn("LOGIN_SUCCESS", actions)
        self.assertIn("PRIVILEGE_ESCALATION_ATTEMPT", actions)
        self.assertIn("PERMISSION_DENIED", actions)
        self.assertIn("REPORT_GENERATED", actions)
        self.assertIn("REPORT_ANALYZED", actions)
        self.assertIn("REPORT_DOWNLOADED", actions)

        serialized = json.dumps(logs)
        self.assertNotIn("Investigator1Pass2026!", serialized)
        self.assertNotIn("AdminPass2026!", serialized)
        self.assertNotIn("StrongPassword2026!", serialized)
        self.assertNotIn("eyJ", serialized)  # No raw JWT substrings logged


if __name__ == "__main__":
    unittest.main()
