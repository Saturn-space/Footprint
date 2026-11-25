"""
Integration Tests for Week 4 Intelligence Correlation Engine (Real Data & CLI)
Validates cross-source correlation using real repository evidence, verifies strict laboratory
isolation, tests intelligence graph component partitioning, and verifies CLI execution.
"""

import os
import sys
import json
import unittest
import subprocess
import tempfile

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.correlation.correlation_engine import CorrelationEngine


class TestW4Integration(unittest.TestCase):

    def setUp(self):
        self.passive_file = os.path.join(PROJECT_ROOT, "data", "processed", "SCAN-20261109-053636-b40a_report.json")
        self.active_file = os.path.join(PROJECT_ROOT, "data", "processed", "SCAN-20261109-082403-bdd8_report.json")
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.engine = CorrelationEngine(base_dir=self.tmp_dir.name, enable_pdf=True)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_real_data_correlation_execution(self):
        """Verifies end-to-end correlation using real W2 and W3 repository scan outputs."""
        self.assertTrue(os.path.isfile(self.passive_file), f"Missing passive file: {self.passive_file}")
        self.assertTrue(os.path.isfile(self.active_file), f"Missing active file: {self.active_file}")

        # Capture file mtimes before correlation to guarantee read-only preservation
        mtime_passive = os.path.getmtime(self.passive_file)
        mtime_active = os.path.getmtime(self.active_file)

        result = self.engine.correlate(
            passive_files=[self.passive_file],
            active_files=[self.active_file]
        )

        self.assertEqual(result.overall_status, "SUCCESS")
        self.assertIn("SCAN-20261109-053636-b40a", result.source_scan_ids)
        self.assertIn("SCAN-20261109-082403-bdd8", result.source_scan_ids)

        # 1. Guarantee original scan files were not modified
        self.assertEqual(os.path.getmtime(self.passive_file), mtime_passive)
        self.assertEqual(os.path.getmtime(self.active_file), mtime_active)

        # 2. Verify asset resolution counts
        asset_ids = {a.asset_id: a for a in result.assets}
        self.assertIn("ASSET:DOMAIN:example.com", asset_ids)
        self.assertIn("ASSET:IPV4:192.168.56.111", asset_ids)

        # Check environment tags
        self.assertIn("lab", asset_ids["ASSET:IPV4:192.168.56.111"].tags)
        self.assertIn("target_domain", asset_ids["ASSET:DOMAIN:example.com"].tags)

        # 3. CRITICAL LAB ISOLATION ASSERTION:
        # Metasploitable2 (192.168.56.111) must NOT be connected to example.com
        for rel in result.relationships:
            is_lab_in_rel = "192.168.56.111" in rel.source_asset_id or "192.168.56.111" in rel.target_asset_id
            is_example_in_rel = "example.com" in rel.source_asset_id or "example.com" in rel.target_asset_id
            self.assertFalse(
                is_lab_in_rel and is_example_in_rel,
                f"Violation of lab isolation boundary: Relationship {rel.relationship_id} links 192.168.56.111 to example.com!"
            )

        # 4. Intelligence Graph Partitioning
        # example.com and 192.168.56.111 must belong to DIFFERENT connected components
        components = result.graph.get("components", [])
        self.assertGreaterEqual(len(components), 2)

        dom_comp = next((c for c in components if "ASSET:DOMAIN:example.com" in c), None)
        lab_comp = next((c for c in components if "ASSET:IPV4:192.168.56.111" in c), None)
        self.assertIsNotNone(dom_comp)
        self.assertIsNotNone(lab_comp)
        self.assertNotEqual(dom_comp, lab_comp)

        # 5. Asset Profiles
        profiles = {p.canonical_identity: p for p in result.profiles}
        self.assertIn("example.com", profiles)
        self.assertIn("192.168.56.111", profiles)

        prof_example = profiles["example.com"]
        self.assertEqual(prof_example.environment, "external")
        self.assertGreater(len(prof_example.related_ips), 0)

        prof_lab = profiles["192.168.56.111"]
        self.assertEqual(prof_lab.environment, "lab")
        self.assertEqual(len(prof_lab.open_ports), 18)
        self.assertIsNone(prof_lab.whois_information)

        # 6. Report Generation
        self.assertIsNotNone(result.json_report_path)
        self.assertTrue(os.path.isfile(result.json_report_path))
        self.assertIsNotNone(result.pdf_report_path)
        self.assertTrue(os.path.isfile(result.pdf_report_path))

    def test_cli_correlate_execution(self):
        """Verifies CLI execution with --correlate and --json-only."""
        python_bin = sys.executable
        cmd = [
            python_bin,
            os.path.join(PROJECT_ROOT, "main.py"),
            "--correlate",
            "--passive-input", self.passive_file,
            "--active-input", self.active_file,
            "--json-only"
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 0, f"CLI stderr: {proc.stderr}")

        # Parse stdout JSON
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["overall_status"], "SUCCESS")
        self.assertTrue(parsed["correlation_id"].startswith("CORR-"))
        self.assertGreater(len(parsed["assets"]), 0)


if __name__ == "__main__":
    unittest.main()

