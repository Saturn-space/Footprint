"""
Integration Tests for Passive Reconnaissance Pipeline
Validates end-to-end orchestration, error isolation, schema validation,
unique scan ID generation, and JSON/PDF reporting with deterministic mocks.
"""

import unittest
from unittest.mock import patch, MagicMock
import os
import sys
import json
import tempfile

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.orchestration.passive_pipeline import PassiveReconPipeline, generate_scan_id
from src.schema import ReconRecord, TargetInfo, ToolInfo, DNSRecord, WhoisData


def create_fake_whois_record(target: str, scan_id: str) -> ReconRecord:
    return ReconRecord(
        target_info=TargetInfo(
            target=target,
            category="normal_benchmark_domain",
            authorization_status="AUTHORIZED_PASSIVE_ONLY",
            scope=f"{target} scope"
        ),
        tool_info=ToolInfo(name="whois", version="5.6.5", execution_args=f"whois {target}"),
        recon_category="whois",
        scan_id=scan_id,
        discovered_domains=[target, f"ns1.{target}", f"ns2.{target}"],
        whois_data=WhoisData(
            domain_name=target.upper(),
            registrar="Mock Registrar LLC",
            creation_date="2000-01-01T00:00:00+00:00",
            expiration_date="2030-01-01T00:00:00+00:00",
            name_servers=[f"ns1.{target}", f"ns2.{target}"],
            emails=[f"abuse@{target}"]
        ),
        evidence_source="mock-whois-evidence",
        scan_status="SUCCESS"
    )


def create_fake_dns_record(target: str, scan_id: str) -> ReconRecord:
    return ReconRecord(
        target_info=TargetInfo(
            target=target,
            category="normal_benchmark_domain",
            authorization_status="AUTHORIZED_PASSIVE_ONLY",
            scope=f"{target} scope"
        ),
        tool_info=ToolInfo(name="dnspython", version="2.9.2", execution_args="resolver.resolve"),
        recon_category="dns",
        scan_id=scan_id,
        discovered_domains=[target, f"mail.{target}"],
        ip_addresses=["93.184.215.14"],
        dns_records=[
            DNSRecord(record_type="A", value="93.184.215.14", ttl=3600),
            DNSRecord(record_type="MX", value=f"mail.{target}", ttl=3600, priority=10),
            DNSRecord(record_type="TXT", value="v=spf1 -all", ttl=3600)
        ],
        evidence_source="mock-dns-evidence",
        scan_status="SUCCESS"
    )


def create_fake_harvester_record(target: str, scan_id: str) -> ReconRecord:
    return ReconRecord(
        target_info=TargetInfo(
            target=target,
            category="normal_benchmark_domain",
            authorization_status="AUTHORIZED_PASSIVE_ONLY",
            scope=f"{target} scope"
        ),
        tool_info=ToolInfo(name="theHarvester", version="4.8.2", execution_args=f"theHarvester -d {target}"),
        recon_category="search_engine_harvesting",
        scan_id=scan_id,
        discovered_domains=[target, f"api.{target}", f"dev.{target}"],
        email_addresses=[f"security@{target}"],
        evidence_source="mock-harvester-evidence",
        scan_status="SUCCESS"
    )


class TestPassivePipelineIntegration(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.pipeline = PassiveReconPipeline(
            base_dir=self.temp_dir.name,
            timeout=5,
            enable_pdf=True
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_scan_id_generation_unique(self):
        id1 = generate_scan_id()
        id2 = generate_scan_id()
        self.assertNotEqual(id1, id2)
        self.assertTrue(id1.startswith("SCAN-"))

    def test_invalid_target_rejection(self):
        res = self.pipeline.run("invalid domain!!")
        self.assertEqual(res.overall_status, "FAILED")
        self.assertTrue(any("Invalid target domain" in err for err in res.errors))

    @patch("src.collectors.theharvester_collector.TheHarvesterCollector.collect")
    @patch("src.collectors.dns_collector.DNSCollector.collect")
    @patch("src.collectors.whois_collector.WhoisCollector.collect")
    def test_full_pipeline_success(self, mock_w, mock_d, mock_h):
        target = "example.com"
        mock_w.side_effect = lambda dom, scan_id=None: create_fake_whois_record(target, scan_id)
        mock_d.side_effect = lambda dom, scan_id=None: create_fake_dns_record(target, scan_id)
        mock_h.side_effect = lambda dom, scan_id=None: create_fake_harvester_record(target, scan_id)

        result = self.pipeline.run(target)

        # 1. Overall Status
        self.assertEqual(result.overall_status, "SUCCESS")
        self.assertEqual(result.target_domain, "example.com")
        self.assertEqual(len(result.collector_records), 3)

        # 2. Correlated metrics
        summary = result.summary
        self.assertGreater(summary["total_normalized_findings"], 0)
        self.assertEqual(summary["registrar"], "Mock Registrar LLC")
        self.assertIn("93.184.215.14", [f.finding_value for f in result.deduplicated_findings if f.finding_type == "ip_address"])

        # 3. JSON Report File Generated
        self.assertIsNotNone(result.json_report_path)
        self.assertTrue(os.path.isfile(result.json_report_path))
        with open(result.json_report_path, "r", encoding="utf-8") as jf:
            loaded = json.load(jf)
            self.assertEqual(loaded["scan_id"], result.scan_id)
            self.assertEqual(loaded["json_report_path"], result.json_report_path)
            self.assertEqual(loaded["pdf_report_path"], result.pdf_report_path)

        # 4. PDF Report File Generated
        self.assertIsNotNone(result.pdf_report_path)
        self.assertTrue(os.path.isfile(result.pdf_report_path))
        self.assertGreater(os.path.getsize(result.pdf_report_path), 1000)

    @patch("src.collectors.theharvester_collector.TheHarvesterCollector.collect")
    @patch("src.collectors.dns_collector.DNSCollector.collect")
    @patch("src.collectors.whois_collector.WhoisCollector.collect")
    def test_partial_pipeline_isolation(self, mock_w, mock_d, mock_h):
        target = "example.com"
        # WHOIS fails
        failed_whois = ReconRecord(
            target_info=TargetInfo(
                target=target,
                category="normal_benchmark_domain",
                authorization_status="AUTHORIZED_PASSIVE_ONLY",
                scope="scope"
            ),
            tool_info=ToolInfo(name="whois", version="5.6.5"),
            recon_category="whois",
            evidence_source="failed",
            scan_status="FAILED",
            errors_and_warnings=["WHOIS server timeout"]
        )
        mock_w.return_value = failed_whois
        # DNS and theHarvester succeed
        mock_d.side_effect = lambda dom, scan_id=None: create_fake_dns_record(target, scan_id)
        mock_h.side_effect = lambda dom, scan_id=None: create_fake_harvester_record(target, scan_id)

        result = self.pipeline.run(target)

        # Result must be PARTIAL, not complete or failed
        self.assertEqual(result.overall_status, "PARTIAL")
        self.assertTrue(any("WHOIS server timeout" in err for err in result.errors))
        # Ensure partial findings were still collected and saved
        self.assertGreater(len(result.deduplicated_findings), 0)
        self.assertIsNotNone(result.json_report_path)
        self.assertTrue(os.path.isfile(result.json_report_path))
        self.assertIsNotNone(result.pdf_report_path)
        self.assertTrue(os.path.isfile(result.pdf_report_path))

    @patch("src.collectors.theharvester_collector.TheHarvesterCollector.collect")
    @patch("src.collectors.dns_collector.DNSCollector.collect")
    @patch("src.collectors.whois_collector.WhoisCollector.collect")
    def test_all_collectors_fail(self, mock_w, mock_d, mock_h):
        target = "example.com"
        mock_w.side_effect = Exception("WHOIS Crash")
        mock_d.side_effect = Exception("DNS Crash")
        mock_h.side_effect = Exception("theHarvester Crash")

        result = self.pipeline.run(target)
        self.assertEqual(result.overall_status, "FAILED")
        self.assertEqual(len(result.collector_records), 0)


if __name__ == "__main__":
    unittest.main()

