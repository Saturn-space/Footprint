"""
FootprintIQ - Unit Tests for NSE Policy Service and Collector
"""

import unittest
from unittest.mock import patch, MagicMock
from src.services.nse_policy_service import NSEPolicyService
from src.collectors.nse_collector import NSECollector


class TestNSEPolicyAndCollector(unittest.TestCase):
    def test_approved_scripts_retrieval(self):
        safe_scripts = NSEPolicyService.get_allowed_scripts("discovery")
        self.assertIn("http-title", safe_scripts)
        self.assertIn("banner", safe_scripts)
        vuln_scripts = NSEPolicyService.get_allowed_scripts("vuln")
        self.assertIn("ftp-vsftpd-backdoor", vuln_scripts)

    def test_script_validation_and_sanitization(self):
        requested = ["http-title", "ftp-vsftpd-backdoor", "malicious_script; rm -rf /", "unlisted-tool"]
        approved, rejected = NSEPolicyService.validate_scripts(requested)
        self.assertIn("http-title", approved)
        self.assertIn("ftp-vsftpd-backdoor", approved)
        self.assertEqual(len(rejected), 2)

    def test_unauthorized_target_rejection(self):
        collector = NSECollector()
        with self.assertRaises(PermissionError):
            collector.scan_target(target="8.8.8.8", scripts=["http-title"])

    def test_empty_scripts_rejection(self):
        collector = NSECollector()
        with self.assertRaises(ValueError):
            collector.scan_target(target="192.168.56.111", scripts=["nonexistent-script"])


if __name__ == "__main__":
    unittest.main()

