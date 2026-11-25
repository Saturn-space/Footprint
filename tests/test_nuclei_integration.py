"""
FootprintIQ - ProjectDiscovery Nuclei Policy, Collector, Normalization & API Integration Tests
Verifies safe scanning profiles, destructive tag/protocol exclusions, shell=False execution,
TargetAuthorizer fail-closed enforcement, live HTTP target execution, SeaweedFS JSONL evidence,
and authenticated /api/v1/scanners/nuclei endpoints.
"""

import http.server
import json
import os
import socketserver
import threading
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.api.app import app
from src.authorization.target_authorizer import TargetAuthorizationError
from src.collectors.nuclei_collector import NucleiCollector, resolve_nuclei_binary
from src.services.nuclei_policy_service import (
    EXCLUDED_NUCLEI_PROTOCOLS,
    EXCLUDED_NUCLEI_TAGS,
    NucleiPolicyService,
)


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        # Deliberately omit security headers (X-Frame-Options, CSP, HSTS, etc.)
        self.end_headers()
        self.wfile.write(b"FootprintIQ Nuclei Verification Endpoint\n")

    def log_message(self, format, *args):
        return


class TestNucleiIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.anon_client = TestClient(app)
        login_res = cls.client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "AdminPass2026!"},
        )
        cls.headers = {"Authorization": f"Bearer {login_res.json().get('access_token')}"}

    def test_01_policy_blocks_destructive_tags_and_path_traversal(self):
        with self.assertRaises(ValueError):
            NucleiPolicyService.validate_profile("nonexistent-profile")

        for bad_tag in ["dos", "fuzz", "bruteforce", "exploit", "dast", "sqli"]:
            with self.assertRaises(ValueError):
                NucleiPolicyService.validate_tags([bad_tag])

        tdir = os.path.expanduser("~/.local/nuclei-templates")
        if os.path.isdir(tdir):
            for bad_tpl in ["../../etc/passwd", "/etc/passwd", "nonexistent-fake-id-12345"]:
                with self.assertRaises(ValueError):
                    NucleiPolicyService.validate_template_ids([bad_tpl], templates_dir=tdir)

    def test_02_policy_builds_safe_shell_false_argv_and_urls(self):
        urls = NucleiPolicyService.build_target_urls(
            "192.168.56.111",
            discovered_ports=[
                {"target_ip": "192.168.56.111", "port": 80, "service": "http"},
                {"target_ip": "192.168.56.111", "port": 8443, "service": "https"},
                {"target_ip": "192.168.56.111", "port": 22, "service": "ssh"},
            ],
            profile="http-security",
        )
        self.assertEqual(urls, ["http://192.168.56.111", "https://192.168.56.111:8443"])

        binary = resolve_nuclei_binary() or "/usr/bin/nuclei"
        argv, meta = NucleiPolicyService.build_cli_arguments(
            binary_path=binary,
            target_urls=urls,
            jsonl_output_path="/tmp/test_nuclei.jsonl",
            profile="http-security",
            rate_limit=999,
            concurrency=50,
        )
        self.assertEqual(argv[0], binary)
        self.assertIn("-etags", argv)
        self.assertEqual(argv[argv.index("-etags") + 1], ",".join(EXCLUDED_NUCLEI_TAGS))
        self.assertIn("-ept", argv)
        self.assertEqual(argv[argv.index("-ept") + 1], ",".join(EXCLUDED_NUCLEI_PROTOCOLS))
        # Rate limit & concurrency clamped safely
        self.assertLessEqual(int(argv[argv.index("-rl") + 1]), 100)
        self.assertLessEqual(int(argv[argv.index("-c") + 1]), 20)
        self.assertEqual(meta["profile"], "http-security")

    def test_03_jsonl_parsing_and_normalization(self):
        sample_jsonl = "\n".join([
            json.dumps({
                "template-id": "http-missing-security-headers",
                "matcher-name": "x-frame-options",
                "matched-at": "http://192.168.56.111:8080/",
                "ip": "192.168.56.111",
                "host": "192.168.56.111",
                "type": "http",
                "info": {
                    "name": "HTTP Missing Security Headers",
                    "severity": "info",
                    "description": "Missing X-Frame-Options header.",
                    "reference": ["https://owasp.org"],
                    "tags": ["misconfig", "headers"],
                },
            }),
            json.dumps({
                "template-id": "CVE-2021-41773",
                "matched-at": "http://192.168.56.111:80/",
                "ip": "192.168.56.111",
                "type": "http",
                "info": {
                    "name": "Apache 2.4.49 Path Traversal",
                    "severity": "high",
                    "description": "Path traversal flaw in Apache HTTP Server 2.4.49.",
                    "remediation": "Upgrade Apache HTTP Server to 2.4.51 or later.",
                    "classification": {
                        "cve-id": ["CVE-2021-41773"],
                        "cwe-id": ["CWE-22"],
                        "cvss-score": 7.5,
                    },
                },
            }),
        ])
        findings, raw_count = NucleiCollector.parse_jsonl_output(
            sample_jsonl,
            default_target="192.168.56.111",
            investigation_id="RECON-TEST-NUC",
            scan_id="SCAN-NUC-1",
            evidence_reference="ev_fid_123",
        )
        self.assertEqual(raw_count, 2)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["detection_source"], "nuclei")
        self.assertEqual(findings[0]["severity"], "Informational")
        self.assertEqual(findings[0]["port"], 8080)
        self.assertEqual(findings[1]["severity"], "High")
        self.assertEqual(findings[1]["port"], 80)
        self.assertEqual(findings[1]["cvss_score"], 7.5)
        self.assertIn("CVE-2021-41773", findings[1]["cve_identifiers"])
        self.assertEqual(findings[1]["evidence_reference"], "ev_fid_123")

    def test_04_blocks_unauthorized_external_target(self):
        collector = NucleiCollector()
        if not collector.check_readiness().get("ready"):
            self.skipTest("Nuclei binary or templates not installed on host")
        with self.assertRaises(TargetAuthorizationError):
            collector.run_scan(
                target="8.8.8.8",
                investigation_id="RECON-UNAUTH-NUC",
                profile="http-security",
            )

    def test_05_real_nuclei_execution_against_local_http_endpoint(self):
        collector = NucleiCollector()
        ready = collector.check_readiness()
        if not ready.get("ready"):
            self.skipTest(f"Nuclei not ready: {ready.get('reason')}")

        httpd = socketserver.TCPServer(("127.0.0.1", 0), _QuietHandler)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.object(
                collector.authorizer,
                "authorize_target",
                return_value=type("AuthOk", (), {"authorized": True})(),
            ):
                res = collector.run_scan(
                    target=f"http://127.0.0.1:{port}",
                    investigation_id="RECON-LIVE-NUC-TEST",
                    scan_id="SCAN-LIVE-NUC-01",
                    profile="http-security",
                    template_ids=["http/misconfiguration/http-missing-security-headers.yaml"],
                    timeout=45,
                )
        finally:
            httpd.shutdown()
            httpd.server_close()

        self.assertIn(res["status"], ("COMPLETED", "PARTIAL"))
        self.assertGreaterEqual(len(res["findings"]), 1)
        self.assertTrue(all(f["detection_source"] == "nuclei" for f in res["findings"]))
        self.assertTrue(all(f["port"] == port for f in res["findings"]))
        self.assertIsNotNone(res.get("evidence"))
        self.assertTrue(res["evidence"]["sha256_hash"])

    def test_06_api_nuclei_status_and_profiles_require_auth(self):
        self.assertEqual(self.anon_client.get("/api/v1/scanners/nuclei/status").status_code, 401)
        self.assertEqual(self.anon_client.get("/api/v1/scanners/nuclei/profiles").status_code, 401)

        r_stat = self.client.get("/api/v1/scanners/nuclei/status", headers=self.headers)
        self.assertEqual(r_stat.status_code, 200)
        data = r_stat.json()
        self.assertIn("ready", data)
        self.assertIn("templates_count", data)

        r_prof = self.client.get("/api/v1/scanners/nuclei/profiles", headers=self.headers)
        self.assertEqual(r_prof.status_code, 200)
        pdata = r_prof.json()
        self.assertEqual(pdata["count"], 6)
        self.assertIn("http-security", [p["id"] for p in pdata["profiles"]])


if __name__ == "__main__":
    unittest.main()

