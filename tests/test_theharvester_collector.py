"""
Unit Tests for theHarvester Collector
Validates argument formatting, artifact cleaning, email extraction, JSON parsing,
error handling, and timeout behavior with mocks.
"""

import unittest
from unittest.mock import patch, MagicMock
import subprocess
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.collectors.theharvester_collector import TheHarvesterCollector, clean_discovered_host
from src.schema import ReconRecord


SAMPLE_STDOUT_HARVESTER = """
*******************************************************************
* theHarvester 4.8.2                                              *
*******************************************************************
[*] Target: example.com 
[*] Searching Duckduckgo. 

[*] Emails found: 2
---------------------
security@example.com
admin@example.com

[*] Hosts found: 4
---------------------
api.example.com
dev.example.com
2Fdocs.example.com
vpn.example.com
"""

SAMPLE_STDOUT_EMPTY = """
*******************************************************************
* theHarvester 4.8.2                                              *
*******************************************************************
[*] Target: example.com 
[*] No IPs found.
[*] No emails found.
[*] No hosts found.
"""

SAMPLE_STDOUT_RATELIMIT = """
[*] Target: example.com 
An exception has occurred: 502, message='Attempt to decode JSON with unexpected mimetype'
[*] No hosts found.
"""


class TestTheHarvesterCollector(unittest.TestCase):

    def setUp(self):
        self.collector = TheHarvesterCollector(sources=["duckduckgo"], limit=20, timeout=5)

    def test_clean_discovered_host(self):
        self.assertEqual(clean_discovered_host("2Fdocs.example.com", "example.com"), "docs.example.com")
        self.assertEqual(clean_discovered_host("api.example.com", "example.com"), "api.example.com")
        self.assertEqual(clean_discovered_host("https://vpn.example.com:443/path", "example.com"), "vpn.example.com")
        self.assertIsNone(clean_discovered_host("otherdomain.org", "example.com"))
        self.assertIsNone(clean_discovered_host("invalid host @!#", "example.com"))

    def test_domain_validation_success(self):
        self.assertEqual(self.collector.validate_domain("EXAMPLE.COM."), "example.com")
        self.assertEqual(self.collector.validate_domain("https://sub.domain.org"), "sub.domain.org")

    def test_domain_validation_failure(self):
        with self.assertRaises(ValueError):
            self.collector.validate_domain("invalid domain")
        with self.assertRaises(ValueError):
            self.collector.validate_domain("")

    @patch("subprocess.run")
    def test_collect_valid_output(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = SAMPLE_STDOUT_HARVESTER
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        record = self.collector.collect("example.com", scan_id="SCAN-HARV-01")
        self.assertIsInstance(record, ReconRecord)
        self.assertEqual(record.scan_status, "SUCCESS")
        self.assertEqual(record.scan_id, "SCAN-HARV-01")

        # Subdomains check (including cleaned 2Fdocs.example.com -> docs.example.com)
        self.assertIn("api.example.com", record.discovered_domains)
        self.assertIn("dev.example.com", record.discovered_domains)
        self.assertIn("docs.example.com", record.discovered_domains)
        self.assertIn("vpn.example.com", record.discovered_domains)

        # Emails check
        self.assertIn("security@example.com", record.email_addresses)
        self.assertIn("admin@example.com", record.email_addresses)

    @patch("subprocess.run")
    def test_collect_empty_results(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = SAMPLE_STDOUT_EMPTY
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        record = self.collector.collect("example.com")
        self.assertEqual(record.scan_status, "SUCCESS")
        self.assertEqual(len(record.email_addresses), 0)

    @patch("subprocess.run")
    def test_collect_ratelimit_detection(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = SAMPLE_STDOUT_RATELIMIT
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        record = self.collector.collect("example.com")
        self.assertEqual(record.scan_status, "PARTIAL")
        self.assertTrue(any("rate-limiting" in err for err in record.errors_and_warnings))

    @patch("subprocess.run")
    def test_collect_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["theHarvester"], timeout=5)
        record = self.collector.collect("example.com")
        self.assertEqual(record.scan_status, "FAILED")
        self.assertTrue(any("timed out" in err for err in record.errors_and_warnings))

    @patch("subprocess.run")
    def test_collect_process_error(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "API error or crash"
        mock_run.return_value = mock_proc

        record = self.collector.collect("example.com")
        self.assertEqual(record.scan_status, "FAILED")
        self.assertIn("API error or crash", record.errors_and_warnings)


if __name__ == "__main__":
    unittest.main()

