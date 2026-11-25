"""
Unit Tests for Correlation Engine Orchestrator (W4 Phase 8)
Tests pipeline execution, schema validation, input validation, partial inputs, and dual report output.
"""

import os
import json
import tempfile
import unittest
import jsonschema

from src.correlation.correlation_engine import CorrelationEngine, generate_correlation_id
from src.schema import (
    PassivePipelineResult,
    ActiveReconResult,
    TargetAuthorizationRecord,
    ReconRecord,
    TargetInfo,
    ToolInfo,
    DNSRecord,
    NmapHost,
    NmapPort,
    NmapService
)


class TestCorrelationEngine(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.engine = CorrelationEngine(
            base_dir=self.tmp_dir.name,
            enable_pdf=True
        )

        # Build mock passive result
        self.mock_passive = PassivePipelineResult(
            scan_id="SCAN-PASSIVE-TEST",
            target_domain="example.com",
            start_time_utc="2026-11-09T08:00:00Z",
            end_time_utc="2026-11-09T08:00:10Z",
            overall_status="SUCCESS",
            collector_records=[
                ReconRecord(
                    target_info=TargetInfo(
                        target="example.com",
                        category="normal_benchmark_domain",
                        authorization_status="AUTHORIZED",
                        scope="example.com"
                    ),
                    tool_info=ToolInfo(name="dnspython", version="2.0.0"),
                    recon_category="dns",
                    scan_id="SCAN-PASSIVE-TEST",
                    dns_records=[
                        DNSRecord(record_type="A", value="93.184.216.34", ttl=300),
                        DNSRecord(record_type="NS", value="a.iana-servers.net", ttl=3600)
                    ],
                    evidence_source="memory"
                )
            ],
            deduplicated_findings=[]
        )

        # Build mock active result
        auth = TargetAuthorizationRecord(
            target="192.168.56.111",
            authorized=True,
            authorization_status="AUTHORIZED_LOCAL_LAB",
            category="intentionally_vulnerable_lab",
            scope="192.168.56.111",
            scan_profile="lab-basic",
            operator="tester"
        )
        self.mock_active = ActiveReconResult(
            scan_id="SCAN-ACTIVE-TEST",
            target="192.168.56.111",
            authorization_record=auth,
            scan_profile="lab-basic",
            start_time_utc="2026-11-09T08:00:15Z",
            end_time_utc="2026-11-09T08:00:35Z",
            overall_status="SUCCESS",
            hosts=[
                NmapHost(
                    address="192.168.56.111",
                    addrtype="ipv4",
                    status="up",
                    hostnames=["metasploitable.localdomain"],
                    ports=[
                        NmapPort(
                            portid=22,
                            protocol="tcp",
                            state="open",
                            service=NmapService(
                                name="ssh",
                                product="OpenSSH",
                                version="4.7p1",
                                cpe=["cpe:/a:openbsd:openssh:4.7p1"]
                            )
                        )
                    ]
                )
            ]
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_correlation_id_generation(self):
        """Verifies correlation ID format."""
        cid = generate_correlation_id()
        self.assertTrue(cid.startswith("CORR-"))

    def test_empty_inputs_returns_failed_status(self):
        """Verifies running correlation with zero inputs returns FAILED status cleanly."""
        result = self.engine.correlate(passive_files=[], active_files=[])
        self.assertEqual(result.overall_status, "FAILED")
        self.assertTrue(any("No valid passive or active scan inputs" in err for err in result.errors))

    def test_malformed_json_file_handled_safely(self):
        """Verifies corrupt JSON input generates warning without crashing."""
        corrupt_file = os.path.join(self.tmp_dir.name, "corrupt.json")
        with open(corrupt_file, "w") as f:
            f.write("{invalid_json: true,")

        result = self.engine.correlate(passive_files=[corrupt_file])
        self.assertEqual(result.overall_status, "FAILED")
        self.assertTrue(any("Failed to parse passive result file" in w for w in result.warnings))

    def test_partial_correlation_passive_only(self):
        """Verifies providing only passive input succeeds with PARTIAL status."""
        result = self.engine.correlate(passive_results=[self.mock_passive])
        self.assertEqual(result.overall_status, "PARTIAL")
        self.assertGreater(len(result.assets), 0)
        self.assertGreater(len(result.relationships), 0)

    def test_full_correlation_success_and_schema_validation(self):
        """Verifies providing both passive and active inputs succeeds with SUCCESS and validates against schema."""
        result = self.engine.correlate(
            passive_results=[self.mock_passive],
            active_results=[self.mock_active]
        )
        self.assertEqual(result.overall_status, "SUCCESS")
        self.assertIn("SCAN-PASSIVE-TEST", result.source_scan_ids)
        self.assertIn("SCAN-ACTIVE-TEST", result.source_scan_ids)

        # Verify JSON report on disk
        self.assertIsNotNone(result.json_report_path)
        self.assertTrue(os.path.isfile(result.json_report_path))

        # Validate generated JSON report against config/correlation_schema.json
        schema_path = os.path.join(os.path.dirname(__file__), "..", "config", "correlation_schema.json")
        if os.path.isfile(schema_path):
            with open(schema_path, "r", encoding="utf-8") as sf:
                corr_schema = json.load(sf)
            result_dict = json.loads(result.model_dump_json())
            jsonschema.validate(instance=result_dict, schema=corr_schema)

        # Verify PDF report on disk
        self.assertIsNotNone(result.pdf_report_path)
        self.assertTrue(os.path.isfile(result.pdf_report_path))
        self.assertGreater(os.path.getsize(result.pdf_report_path), 2000)


if __name__ == "__main__":
    unittest.main()

