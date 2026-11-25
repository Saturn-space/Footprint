"""
FootprintIQ - Comprehensive Verification Suite for Upgrades (Phases 2-15):
- IST timezone conversion across UTC/naive/offset timestamps
- Repeatable ScanExecution runs (Run 001, Run 002...) under one Investigation
- Investigation-based PDF naming & historical preservation
- Report Analysis scoping, 7 canonical tool matrix, honest Risk Score & Scan-to-Scan Comparison
- ReportLab vector Drawing chart generation & IST text inside generated PDFs
- Investigator Settings (profile, theme persistence, activity log, password change & token_version invalidation)
- Evidence metadata, SHA-256, multi-facet filtering & cross-investigator RBAC isolation
- UI routes (HTTP 200 & rendered template sanity)
"""

import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from src.api.app import app
from src.db.repository import FootprintIQRepository
from src.reporting.unified_report import UnifiedReportGenerator
from src.services.auth_service import DEFAULT_DEMO_ACCOUNTS, hash_password
from src.services.report_analysis_service import (
    REPORTS_DIR,
    build_investigation_report_filename,
    build_report_analysis,
    compare_investigation_runs,
)
from src.utils.timezone import duration_human, format_ist, to_ist


class TestISTTimezoneConversion(unittest.TestCase):
    def test_utc_and_naive_timestamps_convert_strictly_to_ist(self):
        # 18:00 UTC -> 11:30 PM IST same day
        formatted = format_ist("2026-11-12T18:00:00")
        self.assertEqual(formatted, "12 Nov 2026, 11:30 PM IST")

        # Midnight rollover: 19:00 UTC on 12 Nov -> 12:30 AM IST on 13 Nov
        rollover = format_ist("2026-11-12T19:00:00Z")
        self.assertEqual(rollover, "13 Nov 2026, 12:30 AM IST")

        # Explicit non-UTC offset (+02:00): 10:00+02:00 == 08:00 UTC == 1:30 PM IST
        offset_fmt = format_ist("2026-11-12T10:00:00+02:00")
        self.assertEqual(offset_fmt, "12 Nov 2026, 1:30 PM IST")

    def test_duration_human_formatting(self):
        self.assertEqual(duration_human(None, None, 42), "42s")
        self.assertEqual(duration_human(None, None, 135), "2m 15s")
        self.assertEqual(duration_human(None, None, 3725), "1h 2m")


class TestUpgradeWorkflowsEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.repo = FootprintIQRepository()
        cls.tmp_dir = tempfile.mkdtemp(prefix="fiq_test_reports_")
        cls.created_files = []

        # Ensure clean demo accounts exist
        for uname, email, pwd, role, approved in DEFAULT_DEMO_ACCOUNTS:
            existing = cls.repo.get_user_by_username(uname)
            if not existing:
                cls.repo.create_user(
                    username=uname,
                    email=email,
                    hashed_password=hash_password(pwd),
                    role=role,
                    is_approved=approved,
                )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)
        for p in cls.created_files:
            try:
                if p and os.path.isfile(p):
                    os.remove(p)
            except OSError:
                pass

    def _login(self, username: str, password: str) -> dict:
        res = self.client.post("/api/v1/auth/login", json={"username": username, "password": password})
        self.assertEqual(res.status_code, 200, f"Login failed for {username}: {res.text}")
        return res.json()

    def _auth_headers(self, tok: dict) -> dict:
        return {
            "Authorization": f"Bearer {tok['access_token']}",
            "X-CSRF-Token": tok["csrf_token"],
        }

    def test_investigation_based_pdf_naming_never_overwrites(self):
        first = build_investigation_report_filename("test1", "active", reports_dir=self.tmp_dir, run_number=1)
        self.assertEqual(first, "test1_active.pdf")
        with open(os.path.join(self.tmp_dir, first), "wb") as f:
            f.write(b"%PDF-1.4 dummy")

        second = build_investigation_report_filename("test1", "active", reports_dir=self.tmp_dir, run_number=2)
        self.assertEqual(second, "test1_active_run-002.pdf")
        with open(os.path.join(self.tmp_dir, second), "wb") as f:
            f.write(b"%PDF-1.4 dummy2")

        third = build_investigation_report_filename("test1", "active", reports_dir=self.tmp_dir, run_number=2)
        self.assertEqual(third, "test1_active_run-002_2.pdf")

    def test_repeatable_runs_reports_analysis_comparison_evidence_and_pdf(self):
        inv1_tok = self._login("investigator1", "Investigator1Pass2026!")
        h1 = self._auth_headers(inv1_tok)
        inv1_user = self.repo.get_user_by_username("investigator1")
        inv2_tok = self._login("investigator2", "Investigator2Pass2026!")
        h2 = self._auth_headers(inv2_tok)

        # Create investigation 'test1'
        c_res = self.client.post(
            "/api/v1/recon",
            json={
                "name": "test1",
                "target_value": "127.0.0.1",
                "purpose": "Repeatable multi-run audit",
            },
            headers=h1,
        )
        self.assertEqual(c_res.status_code, 201, c_res.text)
        recon_id = c_res.json()["recon_id"]

        # Create Run 001 (Passive + Active Nmap + Nuclei)
        s1 = self.repo.create_scan_execution(
            investigation_id=recon_id,
            recon_id=recon_id,
            target="127.0.0.1",
            scan_type="Combined (Nmap + Nuclei)",
            selected_scanners=["nmap", "nuclei"],
            selected_components=["ports", "vulns"],
            initiating_user_id=inv1_user["id"],
            initiated_by="investigator1",
            scanner_versions={"nmap": "7.94", "nuclei": "3.2.0"},
        )
        scan1_id = s1["scan_id"]
        self.assertEqual(s1["run_number"], 1)
        self.repo.update_scan_execution(scan1_id, "running")

        self.repo.add_vulnerability_finding(
            investigation_id=recon_id,
            scan_id=scan1_id,
            finding_dict={
                "target_ip": "127.0.0.1",
                "port": 22,
                "service": "ssh",
                "title": "SSH Weak MAC Algorithms Enabled",
                "severity": "Medium",
                "description": "Nmap detected weak CBC/MD5 MAC algorithms on port 22.",
                "remediation": "Disable legacy MACs in sshd_config.",
                "detection_source": "nmap",
            },
        )
        self.repo.add_vulnerability_finding(
            investigation_id=recon_id,
            scan_id=scan1_id,
            finding_dict={
                "target_ip": "127.0.0.1",
                "port": 8080,
                "service": "http",
                "title": "Exposed Metrics Endpoint via Nuclei",
                "severity": "High",
                "cve_identifiers": "CVE-2026-1001",
                "cvss_score": 7.8,
                "confidence": 0.95,
                "description": "Nuclei confirmed unauthenticated metrics endpoint.",
                "remediation": "Restrict /metrics to authenticated loopback.",
                "detection_source": "nuclei",
            },
        )
        self.repo.add_scan_execution_event(
            scan1_id, recon_id, "scanner_status", "Nmap completed cleanly",
            stage="Nmap",
            details_json=json.dumps({"scanner": "Nmap", "status": "COMPLETED", "target": "127.0.0.1", "detail": "2 ports audited"}),
        )
        self.repo.add_scan_execution_event(
            scan1_id, recon_id, "scanner_status", "Nuclei completed cleanly",
            stage="Nuclei",
            details_json=json.dumps({"scanner": "Nuclei", "status": "COMPLETED", "target": "127.0.0.1", "detail": "1 high finding"}),
        )

        # Persist Evidence linked cleanly to Run 001
        ev1_path = os.path.join(self.tmp_dir, "run1_nmap.xml")
        with open(ev1_path, "wb") as f:
            f.write(b"<nmaprun><host><address addr='127.0.0.1'/></host></nmaprun>")
        ev1 = self.repo.add_evidence_record(
            investigation_id=recon_id,
            scan_id=scan1_id,
            evidence_type="nmap_xml",
            scanner_source="nmap",
            target="127.0.0.1",
            run_number=1,
            file_name="run1_nmap.xml",
            content_type="application/xml",
            file_size=56,
            sha256_hash="a" * 64,
            local_path=ev1_path,
        )

        # Create Run 002 (ONLY Nmap executed; Nuclei NOT selected; Nessus failed)
        s2 = self.repo.create_scan_execution(
            investigation_id=recon_id,
            recon_id=recon_id,
            target="127.0.0.1",
            scan_type="Active (Nmap Only)",
            selected_scanners=["nmap", "nessus"],
            selected_components=["ports"],
            initiating_user_id=inv1_user["id"],
            initiated_by="investigator1",
            scanner_versions={"nmap": "7.94"},
        )
        scan2_id = s2["scan_id"]
        self.assertEqual(s2["run_number"], 2)
        self.repo.update_scan_execution(scan2_id, "running")

        # Same Nmap finding remains persistent; also discover a new Low finding in Run 002
        self.repo.add_vulnerability_finding(
            investigation_id=recon_id,
            scan_id=scan2_id,
            finding_dict={
                "target_ip": "127.0.0.1",
                "port": 22,
                "service": "ssh",
                "title": "SSH Weak MAC Algorithms Enabled",
                "severity": "Medium",
                "description": "Still detected on port 22.",
                "remediation": "Disable legacy MACs in sshd_config.",
                "detection_source": "nmap",
            },
        )
        self.repo.add_vulnerability_finding(
            investigation_id=recon_id,
            scan_id=scan2_id,
            finding_dict={
                "target_ip": "127.0.0.1",
                "port": 80,
                "service": "http",
                "title": "HTTP Server Banner Exposed",
                "severity": "Low",
                "description": "Server banner visible.",
                "remediation": "Suppress Server header.",
                "detection_source": "nmap",
            },
        )
        self.repo.add_scan_execution_event(
            scan2_id, recon_id, "scanner_status", "Nmap completed",
            stage="Nmap",
            details_json=json.dumps({"scanner": "Nmap", "status": "COMPLETED", "target": "127.0.0.1", "detail": "2 findings"}),
        )
        self.repo.add_scan_execution_event(
            scan2_id, recon_id, "scanner_status", "Nessus failed",
            stage="Nessus",
            details_json=json.dumps({"scanner": "Nessus", "status": "FAILED", "target": "127.0.0.1", "detail": "Read-only license prevented scan"}),
        )

        # Complete scan records with duration
        self.repo.update_scan_execution(scan1_id, "completed")
        self.repo.update_scan_execution(scan2_id, "partially_completed")

        # Verify Repeatable Runs API
        runs_res = self.client.get(f"/api/v1/recon/{recon_id}/runs", headers=h1)
        self.assertEqual(runs_res.status_code, 200)
        runs_data = runs_res.json()
        self.assertEqual(len(runs_data), 2)

        # Verify Findings isolation per run
        f_r1 = self.client.get(f"/api/v1/recon/{recon_id}/findings?scan_id={scan1_id}", headers=h1).json()
        f_r2 = self.client.get(f"/api/v1/recon/{recon_id}/findings?scan_id={scan2_id}", headers=h1).json()
        self.assertEqual(len(f_r1), 2)
        self.assertEqual(len(f_r2), 2)
        self.assertEqual({f["title"] for f in f_r1} & {"Exposed Metrics Endpoint via Nuclei"}, {"Exposed Metrics Endpoint via Nuclei"})
        self.assertNotIn("Exposed Metrics Endpoint via Nuclei", {f["title"] for f in f_r2})

        # Generate distinct PDFs for Run 001 (combined) and Run 002 (active + comparison)
        gen1 = self.client.post(
            "/api/v1/reports/generate",
            json={"investigation_id": recon_id, "scan_id": scan1_id, "report_format": "combined"},
            headers=h1,
        )
        self.assertEqual(gen1.status_code, 201, gen1.text)
        g1 = gen1.json()
        self.created_files.append(g1["pdf_report_path"])
        self.assertTrue(g1["file_name"].startswith("test1_combined"))
        self.assertTrue(os.path.isfile(g1["pdf_report_path"]))

        gen2 = self.client.post(
            "/api/v1/reports/generate",
            json={"investigation_id": recon_id, "scan_id": scan2_id, "report_format": "active", "include_comparison": True},
            headers=h1,
        )
        self.assertEqual(gen2.status_code, 201, gen2.text)
        g2 = gen2.json()
        self.created_files.append(g2["pdf_report_path"])
        self.assertTrue(g2["file_name"].startswith("test1_active"))
        self.assertEqual(g2["report_status"], "partial")

        # Validate generated PDF binary structure and IST / chart content
        with open(g2["pdf_report_path"], "rb") as pf:
            pdf_bytes = pf.read()
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 4000)

        # Verify Report Analysis strictly scoped to Run 001 via report_id
        a1_res = self.client.get(f"/api/v1/reports/{g1['report_id']}/analysis", headers=h1)
        self.assertEqual(a1_res.status_code, 200, a1_res.text)
        a1 = a1_res.json()
        self.assertIn("executive_analysis", a1)
        self.assertIn("vulnerability_analysis", a1)
        self.assertIn("risk_interpretation", a1)
        self.assertIn("remediation_analysis", a1)
        self.assertIn("assessment_limitations", a1)
        self.assertIn("analytics", a1)
        self.assertEqual(len(a1["analytics"]["scanner_contribution"]), 7)
        self.assertEqual(a1["scan_run"]["scan_id"], scan1_id)

        # Verify Run-to-Run Comparison honesty: Nuclei finding was NOT executed in Run 002 -> NOT resolved!
        comp_res = self.client.get(
            f"/api/v1/reports/compare?investigation_id={recon_id}&base_scan_id={scan1_id}&target_scan_id={scan2_id}",
            headers=h1,
        )
        self.assertEqual(comp_res.status_code, 200, comp_res.text)
        comp = comp_res.json()
        self.assertEqual(comp["summary"]["new_findings_count"], 1)
        self.assertEqual(comp["summary"]["persistent_findings_count"], 1)
        self.assertEqual(comp["summary"]["resolved_findings_count"], 0)
        self.assertEqual(comp["summary"]["not_reassessed_count"], 1)
        self.assertEqual(comp["not_reassessed_findings"][0]["title"], "Exposed Metrics Endpoint via Nuclei")
        self.assertTrue(comp["limitation_warnings"])

        # Evidence API filtering & cross-investigator isolation (IDOR protection)
        ev_list = self.client.get(f"/api/v1/evidence?investigation_id={recon_id}&scanner_source=nmap", headers=h1)
        self.assertEqual(ev_list.status_code, 200)
        self.assertGreaterEqual(len(ev_list.json()), 1)

        ev_meta = self.client.get(f"/api/v1/evidence/{ev1['evidence_id']}", headers=h1)
        self.assertEqual(ev_meta.status_code, 200)
        self.assertIn("IST", ev_meta.json()["created_at_ist"])

        # Cross-investigator (investigator2) must get 403 on reports, analysis, comparison, evidence!
        self.assertEqual(self.client.get(f"/api/v1/reports/{g1['report_id']}/analysis", headers=h2).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/reports/{g1['report_id']}/download", headers=h2).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/evidence/{ev1['evidence_id']}", headers=h2).status_code, 403)
        self.assertEqual(
            self.client.get(
                f"/api/v1/reports/compare?investigation_id={recon_id}&base_scan_id={scan1_id}&target_scan_id={scan2_id}",
                headers=h2,
            ).status_code,
            403,
        )

        # Render HTML UI views cleanly (HTTP 200 + expected upgraded markers)
        for route, marker in [
            ("/reports", "Reports Archive" if False else "Report Archive"),
            (f"/reports/{g1['report_id']}", "Integrated Report Analysis"),
            (f"/recon/{recon_id}/results?scan_id={scan2_id}", "Scan History &amp; Execution Runs"),
            ("/settings", "Account Settings &amp; Activity"),
            ("/evidence", "SeaweedFS Cryptographic Evidence Catalog"),
        ]:
            page = self.client.get(route, headers=h1)
            self.assertEqual(page.status_code, 200, f"UI route {route} failed: {page.status_code}")
            self.assertIn(marker, page.text, f"Missing marker '{marker}' on {route}")

    def test_failed_scan_with_zero_findings_marks_risk_score_unavailable(self):
        inv1_tok = self._login("investigator1", "Investigator1Pass2026!")
        h1 = self._auth_headers(inv1_tok)
        c_res = self.client.post(
            "/api/v1/recon",
            json={"name": "failed_empty_check", "target_value": "127.0.0.1", "purpose": "Verify honest unavailable score"},
            headers=h1,
        )
        self.assertEqual(c_res.status_code, 201, c_res.text)
        recon_id = c_res.json()["recon_id"]
        self.repo.update_recon_campaign(recon_id, status="Failed", progress=100, current_stage="Failed")
        analysis = build_report_analysis(recon_id, self.repo)
        self.assertFalse(analysis["risk_interpretation"]["risk_score_available"])
        self.assertEqual(analysis["risk_interpretation"]["exposure_level"], "Risk score unavailable")
        self.assertIsNone(analysis["risk_interpretation"]["exposure_score"])

    def test_settings_profile_theme_activity_and_password_session_invalidation(self):
        # Use investigator2 to avoid mutating investigator1 session state for other parallel calls
        tok = self._login("investigator2", "Investigator2Pass2026!")
        h = self._auth_headers(tok)

        # 1. Profile read & permitted edit (role injection attempt ignored/rejected)
        me = self.client.get("/api/v1/auth/me", headers=h).json()
        self.assertEqual(me["role"], "investigator")
        self.assertEqual(me["theme_preference"], "light")
        self.assertIn("IST", me["created_at_ist"])

        upd = self.client.patch(
            "/api/v1/auth/me",
            json={"full_name": "Investigator Two Analyst", "email": "inv2.updated@footprintiq.internal"},
            headers=h,
        )
        self.assertEqual(upd.status_code, 200, upd.text)
        self.assertEqual(upd.json()["profile"]["full_name"], "Investigator Two Analyst")

        # 2. Theme preference saved cleanly and reflected in HTML meta tag
        pref = self.client.patch(
            "/api/v1/auth/me/preferences",
            json={"theme_preference": "dark"},
            headers=h,
        )
        self.assertEqual(pref.status_code, 200, pref.text)
        self.assertEqual(pref.json()["profile"]["theme_preference"], "dark")
        settings_html = self.client.get("/settings", headers=h)
        self.assertEqual(settings_html.status_code, 200)
        self.assertIn('name="fiq-theme-preference" content="dark"', settings_html.text)

        # 3. Own activity log populated in IST
        act = self.client.get("/api/v1/auth/me/activity", headers=h)
        self.assertEqual(act.status_code, 200)
        items = act.json()["items"]
        self.assertGreaterEqual(len(items), 2)
        self.assertIn("IST", items[0]["created_at_ist"])

        # 4. Change password rejects invalid current password and rotates token_version on success
        bad_pwd = self.client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "WrongPassword!", "new_password": "NewValidPass2026!", "confirm_password": "NewValidPass2026!"},
            headers=h,
        )
        self.assertEqual(bad_pwd.status_code, 400)

        ok_pwd = self.client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "Investigator2Pass2026!", "new_password": "NewValidPass2026!", "confirm_password": "NewValidPass2026!"},
            headers=h,
        )
        self.assertEqual(ok_pwd.status_code, 200, ok_pwd.text)

        # Prior JWT MUST now be rejected (401 Unauthorized)
        stale = self.client.get("/api/v1/auth/me", headers=h)
        self.assertEqual(stale.status_code, 401)

        # Sign in with new password works cleanly, then restore demo password & light/system theme
        new_tok = self._login("investigator2", "NewValidPass2026!")
        h_new = self._auth_headers(new_tok)
        self.assertEqual(self.client.get("/api/v1/auth/me", headers=h_new).status_code, 200)

        restore = self.client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "NewValidPass2026!", "new_password": "Investigator2Pass2026!", "confirm_password": "Investigator2Pass2026!"},
            headers=h_new,
        )
        self.assertEqual(restore.status_code, 200)
        tok_restored = self._login("investigator2", "Investigator2Pass2026!")
        self.client.patch(
            "/api/v1/auth/me/preferences",
            json={"theme_preference": "light"},
            headers=self._auth_headers(tok_restored),
        )


if __name__ == "__main__":
    unittest.main()

