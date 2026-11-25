"""
FootprintIQ - Comprehensive Verification Suite for Complete Manual Recon Workflow (Parts 1-11)
Tests category catalog, port validation, fail-closed passive vs active authorization,
multi-target & edit workflow, strict honest scanner unavailability, RBAC/cookies,
cross-campaign report isolation, and jargon-free investigator UI templates.
"""

import json
import os
import re
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.api.app import app
from src.collectors.nuclei_collector import NucleiCollector
from src.collectors.nessus_collector import NessusCollector
from src.collectors.nmap_collector import NmapCollector
from src.db.repository import FootprintIQRepository
from src.services.auth_service import hash_password
from src.services.scan_options_service import ScanOptionsService


class TestManualReconWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.repo = FootprintIQRepository()

        # Login as administrator
        admin_login = cls.client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "AdminPass2026!"}
        )
        cls.admin_token = admin_login.json().get("access_token")
        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}

        # Create/ensure non-admin investigator for RBAC tests
        if not cls.repo.get_user_by_username("qa_investigator"):
            cls.repo.create_user(
                username="qa_investigator",
                email="qa_investigator@footprintiq.internal",
                hashed_password=hash_password("InvestigatorPass2026!"),
                role="investigator",
                is_approved=True
            )
        inv_login = cls.client.post(
            "/api/v1/auth/login",
            json={"username": "qa_investigator", "password": "InvestigatorPass2026!"}
        )
        cls.inv_token = inv_login.json().get("access_token")
        cls.inv_headers = {"Authorization": f"Bearer {cls.inv_token}"}

    def test_01_public_api_docs_disabled_by_default(self):
        self.assertEqual(self.client.get("/docs").status_code, 404)
        self.assertEqual(self.client.get("/redoc").status_code, 404)
        self.assertEqual(self.client.get("/openapi.json").status_code, 404)

    def test_02_options_catalog_dynamic_and_honest(self):
        resp = self.client.get("/api/v1/recon/options")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("categories", data)
        self.assertEqual(len(data["categories"]), 3)
        self.assertIn("passive", data)
        self.assertIn("active", data)
        self.assertIn("vulnerability", data)
        self.assertIn("groups", data["passive"])
        self.assertIn("presets", data["passive"])
        self.assertIn("nse", data["vulnerability"])
        self.assertIn("ssh_ftp", data["vulnerability"]["nse"]["groups"])
        self.assertIn("nessus", data["vulnerability"])
        self.assertIn("nuclei", data["vulnerability"])
        self.assertNotIn("greenbone", data["vulnerability"])

    def test_03_port_validation_endpoint(self):
        ok = self.client.post(
            "/api/v1/recon/validate-ports",
            json={"ports_spec": "22, 80, 443, 1000-1005"},
            headers=self.inv_headers
        )
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(ok.json()["valid"])
        self.assertEqual(ok.json()["normalized"], "22,80,443,1000-1005")

        for bad_spec in ["", "0", "70000", "22;whoami", "80,abc", "-sS 80", "500-100"]:
            bad = self.client.post(
                "/api/v1/recon/validate-ports",
                json={"ports_spec": bad_spec},
                headers=self.inv_headers
            )
            self.assertEqual(bad.status_code, 400, f"Expected 400 for invalid ports spec: {bad_spec}")

    def test_04_nmap_safe_custom_args_blocks_unsafe_flags(self):
        collector = NmapCollector()
        with patch.object(collector, "capabilities", {"binary_found": True, "has_raw_socket": False}):
            with self.assertRaises(ValueError):
                collector.build_safe_custom_args({"tcp_scan_type": "tcp_syn", "port_mode": "top_100"})
            with self.assertRaises(ValueError):
                collector.build_safe_custom_args({"os_detection": True, "port_mode": "top_100"})
            with self.assertRaises(ValueError):
                collector.build_safe_custom_args({"udp_scan": True, "port_mode": "top_100"})

            args = collector.build_safe_custom_args({
                "host_discovery": "skip_discovery",
                "tcp_scan_type": "tcp_connect",
                "port_mode": "custom",
                "custom_ports": "22,80,443",
                "service_version": True,
                "timing": "T3"
            })
            self.assertIn("-sT", args)
            self.assertIn("-Pn", args)
            self.assertIn("-p", args)
            self.assertIn("22,80,443", args)
            self.assertIn("-sV", args)

    def test_05_passive_vs_active_authorization_boundaries(self):
        # 1. Pure passive domain allowed with explicit authorization confirmation
        passive_cfg = {
            "selected_categories": ["passive"],
            "passive": {"checks": ["whois_lookup", "dns_records"], "allow_target_contact": False}
        }
        pass_ok = self.client.post(
            "/api/v1/recon",
            json={
                "name": "Passive Domain Audit",
                "target_value": "example.com",
                "target_type": "domain",
                "selected_scan_types": "passive",
                "scan_config_json": json.dumps(passive_cfg),
                "authorization_confirmed": True
            },
            headers=self.inv_headers
        )
        self.assertEqual(pass_ok.status_code, 201)

        # 2. Active/combined on unauthorized public IP rejected (403)
        act_bad = self.client.post(
            "/api/v1/recon",
            json={
                "name": "Blocked Public Active",
                "target_value": "8.8.8.8",
                "target_type": "ipv4",
                "selected_scan_types": "active",
                "scan_config_json": json.dumps({"selected_categories": ["active"]}),
                "authorization_confirmed": True
            },
            headers=self.inv_headers
        )
        self.assertEqual(act_bad.status_code, 403)

        # 3. Active on unauthorized domain rejected (403)
        dom_bad = self.client.post(
            "/api/v1/recon",
            json={
                "name": "Blocked Active Domain",
                "target_value": "example.com",
                "target_type": "domain",
                "selected_scan_types": "active",
                "scan_config_json": json.dumps({"selected_categories": ["active"]}),
                "authorization_confirmed": True
            },
            headers=self.inv_headers
        )
        self.assertEqual(dom_bad.status_code, 403)

        # 4. Mixed target list with one unauthorized host rejected fail-closed (403)
        mixed_bad = self.client.post(
            "/api/v1/recon",
            json={
                "name": "Mixed Scope Reject",
                "target_value": "192.168.56.111",
                "targets": ["192.168.56.111", "8.8.8.8"],
                "target_type": "ipv4",
                "selected_scan_types": "active",
                "scan_config_json": json.dumps({"selected_categories": ["active"]}),
                "authorization_confirmed": True
            },
            headers=self.inv_headers
        )
        self.assertEqual(mixed_bad.status_code, 403)

        # 5. Missing authorization confirmation blocked (403)
        no_conf = self.client.post(
            "/api/v1/recon",
            json={
                "name": "No Confirm Flag",
                "target_value": "192.168.56.111",
                "target_type": "ipv4",
                "selected_scan_types": "active",
                "authorization_confirmed": False
            },
            headers=self.inv_headers
        )
        self.assertEqual(no_conf.status_code, 403)

    def test_06_pre_scan_draft_edit_no_autostart(self):
        cfg = {
            "selected_categories": ["active"],
            "active": {"tcp_scan_type": "tcp_connect", "port_mode": "custom", "custom_ports": "22,80"}
        }
        create_resp = self.client.post(
            "/api/v1/recon",
            json={
                "name": "Manual Review Draft",
                "target_value": "192.168.56.111",
                "targets": ["192.168.56.111"],
                "target_type": "ipv4",
                "selected_scan_types": "active",
                "scan_config_json": json.dumps(cfg),
                "authorization_confirmed": True
            },
            headers=self.inv_headers
        )
        self.assertEqual(create_resp.status_code, 201)
        recon_id = create_resp.json()["recon_id"]
        self.assertRegex(recon_id, r"^FIQ-REC-\d{8}-[A-F0-9]{4}$")

        # Verify scan has NOT auto-started
        detail = self.client.get(f"/api/v1/recon/{recon_id}", headers=self.inv_headers).json()
        self.assertEqual(len(detail["scans"]), 0)

        # Edit configuration cleanly
        updated_cfg = {
            "selected_categories": ["active", "vulnerability"],
            "active": {"tcp_scan_type": "tcp_connect", "port_mode": "custom", "custom_ports": "21,22,80"},
            "vulnerability": {"engine": "nse", "nse_scripts": ["banner", "http-title"]}
        }
        upd_resp = self.client.put(
            f"/api/v1/recon/{recon_id}",
            json={
                "name": "Manual Review Draft Updated",
                "excluded_ports": "25",
                "selected_scan_types": "active,vulnerability",
                "scan_config_json": json.dumps(updated_cfg)
            },
            headers=self.inv_headers
        )
        self.assertEqual(upd_resp.status_code, 200)
        self.assertEqual(upd_resp.json()["name"], "Manual Review Draft Updated")

        # Verify Edit page renders cleanly with recon_id pre-hydrated
        edit_page = self.client.get(f"/recon/new?edit={recon_id}")
        self.assertEqual(edit_page.status_code, 200)
        self.assertIn(recon_id.encode(), edit_page.content)

    @patch("src.collectors.nuclei_collector.NucleiCollector.check_readiness")
    def test_07_greenbone_deprecated_and_nuclei_unavailable_blocks_honestly(self, mock_nuc_ready):
        mock_nuc_ready.return_value = {
            "available": False,
            "ready": False,
            "status": "Unavailable",
            "reason": "Nuclei binary missing in test",
        }
        # 1. Deprecated greenbone engine request is explicitly rejected
        cfg_gb = {
            "selected_categories": ["vulnerability"],
            "vulnerability": {"engine": "greenbone"}
        }
        c_gb = self.client.post(
            "/api/v1/recon",
            json={
                "name": "Deprecated Greenbone Reject Test",
                "target_value": "192.168.56.111",
                "selected_scan_types": "vulnerability",
                "scan_config_json": json.dumps(cfg_gb),
                "authorization_confirmed": True
            },
            headers=self.inv_headers
        )
        self.assertEqual(c_gb.status_code, 400)
        self.assertIn("Greenbone", c_gb.json()["detail"])

        # 2. Unavailable Nuclei blocks honestly instead of faking results
        cfg_nuc = {
            "selected_categories": ["vulnerability"],
            "vulnerability": {"engine": "nuclei", "nuclei_profile": "http-security"}
        }
        c_nuc = self.client.post(
            "/api/v1/recon",
            json={
                "name": "Nuclei Unavailable Check Test",
                "target_value": "192.168.56.111",
                "selected_scan_types": "vulnerability",
                "scan_config_json": json.dumps(cfg_nuc),
                "authorization_confirmed": True
            },
            headers=self.inv_headers
        )
        self.assertEqual(c_nuc.status_code, 201)
        start_nuc = self.client.post(
            f"/api/v1/recon/{c_nuc.json()['recon_id']}/start",
            json={"scan_type": "vulnerability"},
            headers=self.inv_headers
        )
        self.assertEqual(start_nuc.status_code, 400)
        self.assertIn("Nuclei", start_nuc.json()["detail"])

    def test_08_nessus_manual_no_simulation_fallback(self):
        nc = NessusCollector()
        with patch.object(nc, "test_connection", return_value={"connected": False, "error": "Offline in test"}):
            res = nc.scan_target(
                target="192.168.56.111",
                investigation_id="FIQ-TEST-NOSIM",
                scan_id="SCAN-NOSIM",
                allow_simulation=False
            )
        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(res.get("findings", []), [])

    def test_09_rbac_and_admin_scope_routes(self):
        # Non-admin investigator must be denied admin UI and APIs
        for path in ["/admin/users", "/admin/scanners", "/admin/system"]:
            r_anon = self.client.get(path)
            self.assertEqual(r_anon.status_code, 403, f"Expected 403 unauthenticated on {path}")
            r_inv = self.client.get(path, headers=self.inv_headers)
            self.assertEqual(r_inv.status_code, 403, f"Expected 403 investigator on {path}")

        r_api_inv = self.client.post(
            "/api/v1/admin/scope/ranges",
            json={"range_spec": "10.99.0.0/24"},
            headers=self.inv_headers
        )
        self.assertEqual(r_api_inv.status_code, 403)

        # Admin cookie session works across admin pages & system diagnostics API
        admin_client = TestClient(app)
        login_res = admin_client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "AdminPass2026!"}
        )
        self.assertEqual(login_res.status_code, 200)
        self.assertIn("fiq_session", admin_client.cookies)

        for path in ["/login", "/settings", "/admin/users", "/admin/scanners", "/admin/system"]:
            page = admin_client.get(path)
            self.assertEqual(page.status_code, 200, f"Expected 200 for admin on {path}")

        sys_api = admin_client.get("/api/v1/admin/system")
        self.assertEqual(sys_api.status_code, 200)

        # Admin can add & delete a temporary authorized domain cleanly (with bound CSRF token)
        csrf_headers = {"X-CSRF-Token": admin_client.cookies.get("fiq_csrf", "")}
        add_dom = admin_client.post(
            "/api/v1/admin/scope/domains",
            json={"domain": "qa-lab.internal"},
            headers=csrf_headers
        )
        self.assertEqual(add_dom.status_code, 200)
        self.assertEqual(add_dom.json()["entry"]["domain"], "qa-lab.internal")

        del_dom = admin_client.delete(
            "/api/v1/admin/scope/domains",
            params={"domain": "qa-lab.internal"},
            headers=csrf_headers
        )
        self.assertEqual(del_dom.status_code, 200)
        scope_after = admin_client.get("/api/v1/admin/scope").json()
        self.assertFalse(any(
            (d.get("domain") if isinstance(d, dict) else d) == "qa-lab.internal"
            for d in scope_after.get("authorized_domains", [])
        ))

    def test_10_pdf_cross_campaign_isolation(self):
        c_a = self.client.post(
            "/api/v1/recon",
            json={"name": "Isolation A", "target_value": "192.168.56.111"},
            headers=self.inv_headers
        ).json()["recon_id"]
        c_b = self.client.post(
            "/api/v1/recon",
            json={"name": "Isolation B", "target_value": "192.168.56.111"},
            headers=self.inv_headers
        ).json()["recon_id"]

        self.repo.add_vulnerability_finding(
            investigation_id=c_a,
            finding_dict={"title": "Campaign A Finding", "severity": "High", "target_ip": "192.168.56.111", "port": 22, "detection_source": "nmap_nse"}
        )
        rep_a = self.client.post(
            "/api/v1/reports/generate",
            json={"investigation_id": c_a, "report_format": "technical"},
            headers=self.inv_headers
        )
        self.assertEqual(rep_a.status_code, 201)
        fname_a = rep_a.json()["file_name"]
        dl_url_a = rep_a.json()["download_url"]

        # Valid download works
        dl_ok = self.client.get(dl_url_a)
        self.assertEqual(dl_ok.status_code, 200)
        self.assertEqual(dl_ok.headers.get("content-type"), "application/pdf")

        # Campaign B report list must NOT include Campaign A report
        list_b = self.client.get(f"/api/v1/reports?investigation_id={c_b}")
        self.assertEqual(list_b.status_code, 200)
        self.assertFalse(any(r["file_name"] == fname_a for r in list_b.json()))

        # Cross-campaign download attempt returns 403
        cross_dl = self.client.get(f"/api/v1/reports/{fname_a}/download?investigation_id={c_b}")
        self.assertEqual(cross_dl.status_code, 403)

    def test_11_ui_views_hide_implementation_details(self):
        for route in ["/", "/recon/new", "/settings", "/reports"]:
            resp = self.client.get(route)
            self.assertEqual(resp.status_code, 200, f"Route {route} failed to render")
            body = resp.text
            for leaked in ["mssql+pymssql", "Swagger", "/docs", "9333 / 8080", "SeaweedFS FID"]:
                self.assertNotIn(leaked, body, f"Leaked technical term '{leaked}' found in {route}")

    def test_12_nuclei_and_nessus_honest_readiness_normalization(self):
        nuc_ready = NucleiCollector().check_readiness()
        self.assertIsInstance(nuc_ready, dict)
        self.assertIn("ready", nuc_ready)
        self.assertIn("templates_count", nuc_ready)
        self.assertIn("profiles", nuc_ready)

        with patch("src.services.scan_options_service.NessusCollector.test_connection", return_value={
            "connected": True,
            "status": "Operational",
            "version": "10.12.4",
            "scan_api_enabled": False,
            "limitations": "scan_api=false"
        }), patch("src.services.scan_options_service.NessusCollector.get_scan_templates", return_value=[]):
            vuln_cat = ScanOptionsService.get_vulnerability_catalog()
            self.assertFalse(vuln_cat["nessus"]["available"])
            self.assertEqual(vuln_cat["nessus"]["status"], "READ_ONLY_LICENSE")
            self.assertIn("scan_api=false", vuln_cat["nessus"]["reason"])

    def test_13_unauthenticated_access_blocked_and_public_routes_clean(self):
        anon = TestClient(app)
        protected_apis = [
            "/api/v1/recon",
            "/api/v1/recon/options",
            "/api/v1/investigations",
            "/api/v1/targets",
            "/api/v1/scans",
            "/api/v1/findings",
            "/api/v1/evidence",
            "/api/v1/reports",
            "/api/v1/scanners/nessus/status",
            "/api/v1/scanners/nessus/templates",
        ]
        for ep in protected_apis:
            r = anon.get(ep)
            self.assertEqual(r.status_code, 401, f"Expected 401 on {ep}, got {r.status_code}")

        for ui_route in ["/", "/recon", "/recon/new", "/settings", "/reports", "/findings", "/evidence"]:
            r_ui = anon.get(ui_route, follow_redirects=False)
            self.assertEqual(r_ui.status_code, 303, f"Expected 303 redirect to /login on {ui_route}, got {r_ui.status_code}")
            self.assertIn("/login", r_ui.headers.get("location", ""))

        # Public routes must expose ZERO private lab IPs or VM names
        for pub_route in ["/login", "/api/v1/health"]:
            r_pub = anon.get(pub_route)
            self.assertEqual(r_pub.status_code, 200)
            low = r_pub.text.lower()
            for secret in ["192.168.56.111", "metasploitable2", "virtualbox", "host-only"]:
                self.assertNotIn(secret, low, f"Confidential marker '{secret}' leaked on public route {pub_route}")

    def test_14_draft_creation_no_autostart_and_workspace_flow(self):
        draft_resp = self.client.post(
            "/api/v1/recon",
            json={
                "name": "External Perimeter Draft",
                "target_value": "example.com",
                "purpose": "External Attack Surface Assessment",
                "selected_scan_types": "draft",
                "scan_config_json": json.dumps({"selected_categories": []}),
                "authorization_confirmed": True
            },
            headers=self.inv_headers
        )
        self.assertEqual(draft_resp.status_code, 201)
        data = draft_resp.json()
        recon_id = data["recon_id"]
        self.assertEqual(data["status"], "Draft")
        self.assertEqual(data["current_stage"], "Initialized")

        # Cannot start an unconfigured Draft campaign without selecting categories
        premature = self.client.post(f"/api/v1/recon/{recon_id}/start", json={}, headers=self.inv_headers)
        self.assertEqual(premature.status_code, 400)

        # Workspace page renders cleanly; /recon/{id} redirects Draft -> /workspace
        ws = self.client.get(f"/recon/{recon_id}/workspace?created=1")
        self.assertEqual(ws.status_code, 200)
        self.assertIn(b"Configure Your Security Assessment", ws.content)
        self.assertIn(b"Explore Passive Recon", ws.content)
        self.assertIn(b"Explore Active Recon", ws.content)
        self.assertIn(b"Explore Vulnerability Assessment", ws.content)

        redir = self.client.get(f"/recon/{recon_id}", follow_redirects=False)
        self.assertEqual(redir.status_code, 303)
        self.assertIn(f"/recon/{recon_id}/workspace", redir.headers.get("location", ""))

    def test_15_all_seven_category_combinations_and_port_range(self):
        combos = [
            ["passive"],
            ["active"],
            ["vulnerability"],
            ["passive", "active"],
            ["passive", "vulnerability"],
            ["active", "vulnerability"],
            ["passive", "active", "vulnerability"],
        ]
        # Create one authorized private target Draft Recon
        c = self.client.post(
            "/api/v1/recon",
            json={
                "name": "Combo Matrix Campaign",
                "target_value": "192.168.56.111",
                "purpose": "Combination Verification",
                "selected_scan_types": "draft",
                "scan_config_json": json.dumps({"selected_categories": []}),
                "authorization_confirmed": True
            },
            headers=self.inv_headers
        )
        self.assertEqual(c.status_code, 201)
        recon_id = c.json()["recon_id"]

        for cats in combos:
            cfg = {"selected_categories": cats}
            if "passive" in cats:
                cfg["passive"] = {"selected_checks": ["whois_lookup", "dns_enumeration"]}
            if "active" in cats:
                cfg["active"] = {
                    "host_discovery": "ping_discovery",
                    "tcp_scan_type": "tcp_connect",
                    "port_mode": "port_range",
                    "port_range": "20-85",
                    "timing": "T3",
                    "service_version": True
                }
            if "vulnerability" in cats:
                cfg["vulnerability"] = {
                    "engines": ["nse"],
                    "engine": "nse",
                    "nse_scripts": ["http-title", "ssl-cert"]
                }

            upd = self.client.put(
                f"/api/v1/recon/{recon_id}",
                json={
                    "selected_scan_types": ",".join(cats),
                    "scan_config_json": json.dumps(cfg),
                    "authorization_confirmed": True
                },
                headers=self.inv_headers
            )
            self.assertEqual(upd.status_code, 200, f"Combination {cats} failed: {upd.text}")
            saved_cfg = json.loads(upd.json()["scan_config_json"])
            self.assertEqual(saved_cfg["selected_categories"], cats)

        # Verify UDP custom & Nmap custom args validation
        nmap_args = NmapCollector().build_safe_custom_args({
            "host_discovery": "skip_discovery",
            "tcp_scan_type": "tcp_connect",
            "port_mode": "port_range",
            "port_range": "21-80"
        })
        self.assertIn("-p", nmap_args)
        self.assertIn("21-80", nmap_args)

    def test_16_confidentiality_ui_3d_css_and_empty_state(self):
        # Temporarily isolate in-memory records so UI pages are inspected with clean workspace state
        saved_camps = dict(self.repo._mem_recon_campaigns)
        saved_invs = dict(self.repo._mem_investigations)
        saved_tgts = dict(self.repo._mem_targets)
        saved_scans = dict(self.repo._mem_scans)
        saved_findings = dict(self.repo._mem_findings)
        saved_reports = dict(self.repo._mem_reports)
        saved_evidence = dict(self.repo._mem_evidence)
        saved_audit = list(self.repo._mem_audit)
        try:
            self.repo._mem_recon_campaigns.clear()
            self.repo._mem_investigations.clear()
            self.repo._mem_targets.clear()
            self.repo._mem_scans.clear()
            self.repo._mem_findings.clear()
            self.repo._mem_reports.clear()
            self.repo._mem_evidence.clear()
            self.repo._mem_audit.clear()

            list_empty = self.client.get("/recon")
            self.assertEqual(list_empty.status_code, 200)
            self.assertIn(b"No Recon campaigns yet. Create your first Recon to begin.", list_empty.content)

            dash_empty = self.client.get("/")
            self.assertEqual(dash_empty.status_code, 200)
            self.assertIn(b"No Recon campaigns yet. Create your first Recon to begin.", dash_empty.content)

            # Verify zero lab/VM strings appear on ANY UI page or static asset when clean
            for route in ["/", "/recon", "/recon/new", "/settings", "/reports", "/investigations", "/scans", "/static/js/app.js"]:
                resp = self.client.get(route)
                self.assertEqual(resp.status_code, 200)
                low = resp.text.lower()
                for forbidden in ["192.168.56.111", "metasploitable2", "virtualbox", "host-only", "live terminal"]:
                    self.assertNotIn(forbidden, low, f"Forbidden label '{forbidden}' found in {route}")
        finally:
            self.repo._mem_recon_campaigns.update(saved_camps)
            self.repo._mem_investigations.update(saved_invs)
            self.repo._mem_targets.update(saved_tgts)
            self.repo._mem_scans.update(saved_scans)
            self.repo._mem_findings.update(saved_findings)
            self.repo._mem_reports.update(saved_reports)
            self.repo._mem_evidence.update(saved_evidence)
            self.repo._mem_audit[:] = saved_audit

        # Verify 3D CSS classes + reduced-motion accessibility override
        css_resp = self.client.get("/static/css/app.css")
        self.assertEqual(css_resp.status_code, 200)
        self.assertIn(".fiq-3d-card", css_resp.text)
        self.assertIn("prefers-reduced-motion: reduce", css_resp.text)

    def test_17_extended_passive_collector_and_pdf_content(self):
        from src.collectors.passive_intel_collector import PassiveIntelCollector
        from src.reporting.unified_report import UnifiedReportGenerator

        pic = PassiveIntelCollector()
        with patch.object(pic, "_enumerate_extended_dns", return_value={"SOA": ["ns1.example.com"], "CAA": []}), \
             patch.object(pic, "_analyze_nameservers", return_value={"count": 1, "nameservers": [{"nameserver": "ns1.example.com", "ipv4": ["93.184.216.34"]}]}), \
             patch.object(pic, "_query_crtsh", return_value={"status": "SUCCESS", "subdomains": ["www.example.com"], "certificates": []}):
            res = pic.run_selected_checks(
                target="example.com",
                selected_checks=["dns_enumeration", "nameserver_analysis", "certificate_info", "technology_intel", "public_metadata"]
            )
        executed_ids = {c["id"] for c in res["checks_executed"]}
        self.assertTrue({"dns_enumeration", "nameserver_analysis", "certificate_info", "technology_intel", "public_metadata"}.issubset(executed_ids))

        # Verify Executive and Technical PDFs generate cleanly
        gen = UnifiedReportGenerator()
        inv = {
            "investigation_id": "FIQ-REC-20261111-TEST",
            "recon_id": "FIQ-REC-20261111-TEST",
            "title": "Verification Assessment",
            "purpose": "Security Audit",
            "target_value": "example.com",
            "target_type": "domain",
            "status": "Completed",
            "selected_scan_types": "passive",
            "scan_config_json": json.dumps({"selected_categories": ["passive"], "passive": {"selected_checks": ["whois_lookup"]}})
        }
        exec_pdf = gen.generate_pdf_report(investigation=inv, targets=[], findings=[], evidence=[], report_format="executive")
        tech_pdf = gen.generate_pdf_report(investigation=inv, targets=[], findings=[], evidence=[], report_format="technical")
        self.assertTrue(os.path.exists(exec_pdf) and os.path.getsize(exec_pdf) > 1500)
        self.assertTrue(os.path.exists(tech_pdf) and os.path.getsize(tech_pdf) > 1500)

    def test_18_demo_accounts_seeded_and_authenticated(self):
        expected_accounts = [
            ("admin", "AdminPass2026!", "admin", "admin@footprintiq.internal"),
            ("investigator1", "Investigator1Pass2026!", "investigator", "investigator1@footprintiq.internal"),
            ("investigator2", "Investigator2Pass2026!", "investigator", "investigator2@footprintiq.internal"),
        ]
        admin_token = None
        for username, password, expected_role, expected_email in expected_accounts:
            login_resp = self.client.post(
                "/api/v1/auth/login",
                json={"username": username, "password": password}
            )
            self.assertEqual(login_resp.status_code, 200, f"Login failed for demo user {username}")
            payload = login_resp.json()
            self.assertEqual(payload["username"], username)
            self.assertEqual(payload["role"], expected_role)
            token = payload["access_token"]
            if expected_role == "admin":
                admin_token = token

            me_resp = self.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
            self.assertEqual(me_resp.status_code, 200)
            me_data = me_resp.json()
            self.assertEqual(me_data["username"], username)
            self.assertEqual(me_data["role"], expected_role)
            self.assertEqual(me_data["email"], expected_email)
            self.assertTrue(me_data["is_active"])
            self.assertTrue(me_data["is_approved"])

            if expected_role == "investigator":
                self.assertEqual(
                    self.client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {token}"}).status_code,
                    403
                )
                self.assertEqual(
                    self.client.get("/api/v1/recon", headers={"Authorization": f"Bearer {token}"}).status_code,
                    200
                )

        users_resp = self.client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(users_resp.status_code, 200)
        usernames = {u["username"]: u["role"] for u in users_resp.json()}
        self.assertEqual(usernames.get("admin"), "admin")
        self.assertEqual(usernames.get("investigator1"), "investigator")
        self.assertEqual(usernames.get("investigator2"), "investigator")

    def test_19_nmap_udp_ports_nse_failure_and_passive_issuer(self):
        from src.collectors.nse_collector import NSECollector
        from src.collectors.passive_intel_collector import PassiveIntelCollector

        collector = NmapCollector()
        with patch.dict(collector.capabilities, {"has_raw_socket": True}):
            # 1. top_1000 + udp_ports must not combine --top-ports with -p and must honor udp_ports
            args_combo = collector.build_safe_custom_args({
                "host_discovery": "skip_discovery",
                "tcp_scan_type": "tcp_connect",
                "port_mode": "top_1000",
                "udp_scan": True,
                "udp_port_mode": "udp_selected",
                "udp_ports": "53,161",
            })
            self.assertNotIn("--top-ports", args_combo)
            self.assertIn("-sU", args_combo)
            self.assertIn("-sT", args_combo)
            p_idx = args_combo.index("-p")
            self.assertIn("U:53,161", args_combo[p_idx + 1])
            self.assertIn("T:1-1024", args_combo[p_idx + 1])

            # 2. udp_only must skip -sT/-sS and target UDP ports only
            args_udp_only = collector.build_safe_custom_args({
                "host_discovery": "skip_discovery",
                "tcp_scan_type": "tcp_connect",
                "port_mode": "udp_only",
                "udp_port_mode": "udp_selected",
                "udp_ports": "53,123",
            })
            self.assertIn("-sU", args_udp_only)
            self.assertNotIn("-sT", args_udp_only)
            self.assertNotIn("-sS", args_udp_only)
            self.assertIn("U:53,123", args_udp_only)

        # 3. NSECollector returns FAILED (not PARTIAL) when nonzero exit produces no XML
        nse = NSECollector()
        mock_proc = unittest.mock.MagicMock(returncode=1, stderr="nmap permission denied", stdout="")
        with patch("src.collectors.nse_collector.subprocess.run", return_value=mock_proc), \
             patch("src.collectors.nse_collector.os.path.exists", return_value=False):
            nse_res = nse.scan_target(target="127.0.0.1", scripts=["http-title"])
        self.assertEqual(nse_res["status"], "FAILED")
        self.assertTrue(any("permission denied" in e for e in nse_res.get("errors", [])))

        # 4. PassiveIntelCollector extracts issuer from _query_crtsh 'issuer' field
        pic = PassiveIntelCollector()
        with patch.object(pic, "_enumerate_extended_dns", return_value={"TXT": ["v=spf1 ~all"]}), \
             patch.object(pic, "_query_crtsh", return_value={
                 "status": "SUCCESS",
                 "subdomains": ["www.example.com"],
                 "certificates": [{"issuer": "Let's Encrypt R3"}],
             }):
            p_res = pic.run_selected_checks(
                target="example.com",
                selected_checks=["certificate_info", "public_metadata"],
            )
        issuers = p_res["osint_intel"]["public_metadata"]["certificate_issuers"]
        self.assertEqual(issuers, ["Let's Encrypt R3"])

    def test_20_execution_manager_live_telemetry_and_ui_safety(self):
        from src.orchestration.execution_manager import ExecutionManager, ScanJobContext

        # 1. Public login page must not leak local OS username
        self.client.cookies.clear()
        login_page = self.client.get("/login")
        self.assertEqual(login_page.status_code, 200)
        self.assertNotIn("asip_ali", login_page.text)

        # Restore admin session cookie
        self.client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminPass2026!"})

        # 2. ExecutionManager counts passive_result cleanly and avoids COMPLETION double count
        em = ExecutionManager()
        ctx = ScanJobContext(scan_id="SCAN-TEST-EM-20", recon_id="FIQ-TEST-EM-20", target="example.com")
        ctx.planned_checks = 1
        with patch.object(em.repo, "add_scan_execution_event"):
            em._emit_event(ctx, "passive_result", "Passive done", stage="PASSIVE_RECON")
            self.assertEqual(ctx.completed_checks, 1)
            em._emit_event(ctx, "stage_complete", "All done", stage="COMPLETION")
            self.assertEqual(ctx.completed_checks, 1)

        snap = em.build_live_snapshot(
            "FIQ-NONE-EXIST",
            {"status": "Completed", "current_stage": "Completed", "updated_at": "2026-11-11T00:00:00Z"},
            [{"started_at": "2026-11-11T00:00:00Z", "result_summary_json": json.dumps({"elapsed_seconds": 12.34})}],
            {"scanner_statuses": [{"scanner": "Passive", "status": "COMPLETED"}], "discovered_ports": [{"port": 80}]},
        )
        self.assertEqual(snap["completed_checks"], 1)
        self.assertEqual(snap["pending_checks"], 0)
        self.assertEqual(snap["services_count"], 1)
        self.assertEqual(snap["elapsed_seconds"], 12.34)

        # 3. Cancelled SSE progress respects campaign progress and results/live templates escape cleanly
        saved_camps = dict(self.repo._mem_recon_campaigns)
        saved_invs = dict(self.repo._mem_investigations)
        saved_findings = dict(self.repo._mem_findings)
        saved_scans = dict(self.repo._mem_scans)
        try:
            rid = "FIQ-REC-TEST-20-SAFE"
            qa_user = self.repo.get_user_by_username("qa_investigator") or {}
            self.repo._mem_investigations[rid] = {
                "investigation_id": rid,
                "recon_id": rid,
                "creator_id": qa_user.get("id"),
                "title": "XSS & Quote Safety Check",
                "target_value": "example.com",
                "target_type": "domain",
                "status": "Cancelled",
                "progress": 42,
                "current_stage": "Cancelled",
            }
            self.repo._mem_recon_campaigns[rid] = dict(self.repo._mem_investigations[rid])
            self.repo._mem_findings["FND-TEST-QUOTE"] = {
                "finding_id": "FND-TEST-QUOTE",
                "investigation_id": rid,
                "title": "O'Reilly's <test> \"alert\"",
                "severity": "medium",
                "confidence": "medium",
                "target_ip": "93.184.216.34",
                "port": 443,
                "protocol": "tcp",
                "remediation_status": "open",
                "version_id": 1,
            }

            stream_resp = self.client.get(f"/api/v1/recon/{rid}/stream", headers=self.inv_headers)
            self.assertEqual(stream_resp.status_code, 200)
            self.assertIn('"progress": 42', stream_resp.text)

            res_html = self.client.get(f"/recon/{rid}/results", headers=self.inv_headers)
            self.assertEqual(res_html.status_code, 200)
            self.assertIn('onclick="openRemediationModal(this)"', res_html.text)
            self.assertIn('id="fiqResultsMeta"', res_html.text)
            self.assertNotIn("openRemediationModal('FND-TEST-QUOTE'", res_html.text)

            admin_res_html = self.client.get(f"/recon/{rid}/results", headers=self.admin_headers)
            self.assertEqual(admin_res_html.status_code, 200)
            self.assertNotIn('onclick="openRemediationModal(this)"', admin_res_html.text)
            self.assertIn("Read-Only", admin_res_html.text)

            live_html = self.client.get(f"/recon/{rid}/live", headers=self.inv_headers)
            self.assertEqual(live_html.status_code, 200)
            self.assertIn('data-progress-width="42"', live_html.text)
            self.assertIn('id="fiqLiveBootstrap"', live_html.text)
            self.assertNotIn('style="width: 42', live_html.text)
        finally:
            self.repo._mem_recon_campaigns.clear()
            self.repo._mem_recon_campaigns.update(saved_camps)
            self.repo._mem_investigations.clear()
            self.repo._mem_investigations.update(saved_invs)
            self.repo._mem_findings.clear()
            self.repo._mem_findings.update(saved_findings)
            self.repo._mem_scans.clear()
            self.repo._mem_scans.update(saved_scans)


if __name__ == "__main__":
    unittest.main()
