"""
Unit Tests for WHOIS Collector
Validates parsing, error handling, date normalization, redaction, and timeouts with mocks.
"""

import unittest
from unittest.mock import patch, MagicMock
import subprocess
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.collectors.whois_collector import (
    WhoisCollector,
    normalize_iso8601,
    is_privacy_protected
)
from src.schema import ReconRecord


SAMPLE_WHOIS_VALID = """
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar: RESERVED-Internet Assigned Numbers Authority
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2027-08-13T04:00:00Z
Updated Date: 2026-08-14T07:01:38Z
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registrant Organization: Internet Assigned Numbers Authority
Registrant Country: US
DNSSEC: signedDelegation
"""

SAMPLE_WHOIS_REDACTED = """
Domain Name: PRIVATETEST.COM
Registrar: Example Registrar LLC
Creation Date: 2020-01-01T12:00:00Z
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization: Domains By Proxy, LLC
Registrant Country: US
"""


class TestWhoisCollector(unittest.TestCase):

    def setUp(self):
        self.collector = WhoisCollector(timeout=5)

    def test_domain_validation_success(self):
        self.assertEqual(self.collector.validate_domain("example.com"), "example.com")
        self.assertEqual(self.collector.validate_domain("https://SUB.DOMAIN.ORG/path"), "sub.domain.org")

    def test_domain_validation_failure(self):
        with self.assertRaises(ValueError):
            self.collector.validate_domain("not a domain")
        with self.assertRaises(ValueError):
            self.collector.validate_domain("")

    def test_date_normalization(self):
        iso_str = normalize_iso8601("1995-08-14T04:00:00Z")
        self.assertTrue(iso_str.startswith("1995-08-14T04:00:00"))
        self.assertIsNone(normalize_iso8601(None))
        self.assertIsNone(normalize_iso8601("N/A"))

    def test_privacy_detection(self):
        self.assertTrue(is_privacy_protected("REDACTED FOR PRIVACY"))
        self.assertTrue(is_privacy_protected("Domains By Proxy, LLC"))
        self.assertFalse(is_privacy_protected("Internet Assigned Numbers Authority"))

    @patch("subprocess.run")
    def test_collect_valid_domain(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = SAMPLE_WHOIS_VALID
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        record = self.collector.collect("example.com", scan_id="SCAN-TEST-01")
        self.assertIsInstance(record, ReconRecord)
        self.assertEqual(record.scan_status, "SUCCESS")
        self.assertEqual(record.scan_id, "SCAN-TEST-01")
        self.assertIsNotNone(record.whois_data)
        self.assertEqual(record.whois_data.registrar, "RESERVED-Internet Assigned Numbers Authority")
        self.assertIn("a.iana-servers.net", record.whois_data.name_servers)
        self.assertIn("clientdeleteprohibited", [s.lower() for s in record.whois_data.status])

    @patch("subprocess.run")
    def test_collect_redacted_domain(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = SAMPLE_WHOIS_REDACTED
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        record = self.collector.collect("privatetest.com")
        self.assertEqual(record.scan_status, "SUCCESS")
        self.assertEqual(record.whois_data.registrant_name, "[REDACTED FOR PRIVACY]")
        self.assertEqual(record.whois_data.registrant_organization, "[REDACTED FOR PRIVACY]")

    @patch("subprocess.run")
    def test_collect_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["whois"], timeout=5)
        record = self.collector.collect("example.com")
        self.assertEqual(record.scan_status, "FAILED")
        self.assertTrue(any("timed out" in err for err in record.errors_and_warnings))

    @patch("subprocess.run")
    def test_collect_execution_failure(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "Connection refused to whois server"
        mock_run.return_value = mock_proc

        record = self.collector.collect("example.com")
        self.assertEqual(record.scan_status, "FAILED")
        self.assertIn("Connection refused to whois server", record.errors_and_warnings)

    def test_collect_invalid_input(self):
        record = self.collector.collect("invalid domain name!@#")
        self.assertEqual(record.scan_status, "FAILED")
        self.assertTrue(any("Invalid domain format" in err for err in record.errors_and_warnings))


if __name__ == "__main__":
    unittest.main()

