"""
Unit Tests for Nmap Active Reconnaissance Collector Module
Validates binary detection, safe argument lists, subprocess error handling,
execution timeouts, and SHA256 evidence hashing using deterministic mocks.
"""

import unittest
from unittest.mock import patch, MagicMock
import subprocess
import os
import sys
import tempfile

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.collectors.nmap_collector import NmapCollector, NmapCollectorResult, compute_file_sha256
from src.schema import TargetAuthorizationRecord


def create_mock_auth_record(target: str = "192.168.56.111") -> TargetAuthorizationRecord:
    return TargetAuthorizationRecord(
        target=target,
        authorized=True,
        authorization_status="AUTHORIZED_LOCAL_LAB",
        category="intentionally_vulnerable_lab",
        scope=f"{target} scope",
        permitted_profiles=["lab-basic", "lab-safe-minimal", "lab-common-services"],
        scan_profile="lab-basic",
        operator="asip_ali",
        notes="Mock test record"
    )


class TestNmapCollector(unittest.TestCase):

    def setUp(self):
        self.collector = NmapCollector(timeout=15)
        self.auth = create_mock_auth_record()

    def test_binary_detection(self):
        """Verifies detection of installed Nmap binary."""
        self.assertTrue(os.path.exists(self.collector.binary_path))
        self.assertIn("nmap", self.collector.binary_path)

    @patch("subprocess.run")
    def test_subprocess_argument_safety(self, mock_run):
        """Verifies arguments are passed as explicit lists and never shell=True."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "Nmap scan report"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        with tempfile.TemporaryDirectory() as tmpdir:
            res = self.collector.execute_scan(self.auth, profile_name="lab-basic", output_dir=tmpdir)
            self.assertEqual(res.returncode, 0)
            mock_run.assert_called_once()
            args, kwargs = mock_run.call_args
            cmd_list = args[0]
            self.assertIsInstance(cmd_list, list)
            # Verify shell=True is NOT passed
            self.assertNotIn("shell", kwargs)
            self.assertIn("-sT", cmd_list)
            self.assertIn("-sV", cmd_list)
            self.assertIn("-Pn", cmd_list)
            self.assertIn("--top-ports", cmd_list)
            self.assertIn("192.168.56.111", cmd_list)

    @patch("subprocess.run")
    def test_timeout_handling(self, mock_run):
        """Verifies subprocess.TimeoutExpired is trapped and recorded safely."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmap"], timeout=10)

        with tempfile.TemporaryDirectory() as tmpdir:
            res = self.collector.execute_scan(self.auth, profile_name="lab-basic", output_dir=tmpdir)
            self.assertEqual(res.returncode, -1)
            self.assertIn("timed out", res.error_message)

    @patch("subprocess.run")
    def test_non_zero_exit_code_handling(self, mock_run):
        """Verifies non-zero exit code is recorded without throwing uncaught exceptions."""
        mock_proc = MagicMock()
        mock_proc.returncode = 2
        mock_proc.stdout = ""
        mock_proc.stderr = "QUITTING! Network error"
        mock_run.return_value = mock_proc

        with tempfile.TemporaryDirectory() as tmpdir:
            res = self.collector.execute_scan(self.auth, profile_name="lab-basic", output_dir=tmpdir)
            self.assertEqual(res.returncode, 2)
            self.assertIn("exited with non-zero code 2", res.error_message)

    def test_unsupported_profile_rejection(self):
        """Verifies invalid scan profile raises ValueError."""
        with self.assertRaises(ValueError):
            self.collector.execute_scan(self.auth, profile_name="invalid-hack-profile")

    def test_sha256_hash_computation(self):
        """Verifies SHA256 integrity hash function on files."""
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("OSINT-RECON-TEST-CONTENT")
            tf_path = tf.name

        try:
            h = compute_file_sha256(tf_path)
            self.assertEqual(len(h), 64)  # 64 hex characters for SHA256
        finally:
            os.remove(tf_path)


if __name__ == "__main__":
    unittest.main()

