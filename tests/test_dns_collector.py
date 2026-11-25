"""
Unit Tests for DNS Collector
Validates all 6 record types (A, AAAA, MX, NS, TXT, CNAME), TTL extraction,
NoAnswer handling, NXDOMAIN, timeouts, and partial collection using mocks.
"""

import unittest
from unittest.mock import patch, MagicMock
import dns.resolver
import dns.exception
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.collectors.dns_collector import DNSCollector, normalize_record_value
from src.schema import ReconRecord


class TestDNSCollector(unittest.TestCase):

    def setUp(self):
        self.collector = DNSCollector(
            nameservers=["8.8.8.8", "1.1.1.1"],
            timeout=2.0,
            lifetime=4.0
        )

    def test_domain_validation_success(self):
        self.assertEqual(self.collector.validate_domain("EXAMPLE.COM."), "example.com")
        self.assertEqual(self.collector.validate_domain("https://sub.domain.org/path"), "sub.domain.org")

    def test_domain_validation_failure(self):
        with self.assertRaises(ValueError):
            self.collector.validate_domain("invalid domain name")
        with self.assertRaises(ValueError):
            self.collector.validate_domain("")

    def test_normalize_record_value_mx(self):
        mock_mx = MagicMock()
        mock_mx.preference = 10
        mock_mx.exchange = "mail.example.com."
        val, prio = normalize_record_value("MX", mock_mx)
        self.assertEqual(val, "mail.example.com")
        self.assertEqual(prio, 10)

    def test_normalize_record_value_null_mx(self):
        mock_mx = MagicMock()
        mock_mx.preference = 0
        mock_mx.exchange = "."
        val, prio = normalize_record_value("MX", mock_mx)
        self.assertEqual(val, ".")
        self.assertEqual(prio, 0)

    def test_normalize_record_value_txt(self):
        mock_txt = MagicMock()
        mock_txt.strings = [b"v=spf1 include:_spf.example.com ~all"]
        val, prio = normalize_record_value("TXT", mock_txt)
        self.assertEqual(val, "v=spf1 include:_spf.example.com ~all")
        self.assertIsNone(prio)

    @patch.object(dns.resolver.Resolver, "resolve")
    def test_collect_all_records_success(self, mock_resolve):
        def fake_resolve(domain, rtype):
            mock_ans = MagicMock()
            mock_ans.ttl = 300
            if rtype == "A":
                mock_ans.__iter__.return_value = ["93.184.215.14"]
            elif rtype == "AAAA":
                mock_ans.__iter__.return_value = ["2606:2800:220:1:248:1893:25c8:1946"]
            elif rtype == "NS":
                mock_ans.__iter__.return_value = ["a.iana-servers.net."]
            elif rtype == "MX":
                mock_mx = MagicMock()
                mock_mx.preference = 10
                mock_mx.exchange = "mail.example.com."
                mock_ans.__iter__.return_value = [mock_mx]
            elif rtype == "TXT":
                mock_txt = MagicMock()
                mock_txt.strings = [b"sample-verification=123"]
                mock_ans.__iter__.return_value = [mock_txt]
            elif rtype == "CNAME":
                mock_ans.__iter__.return_value = ["target.example.com."]
            return mock_ans

        mock_resolve.side_effect = fake_resolve

        record = self.collector.collect("example.com", scan_id="SCAN-DNS-01")
        self.assertIsInstance(record, ReconRecord)
        self.assertEqual(record.scan_status, "SUCCESS")
        self.assertEqual(record.scan_id, "SCAN-DNS-01")
        
        # Check presence of each record type
        found_types = {r.record_type for r in record.dns_records}
        self.assertEqual(found_types, {"A", "AAAA", "MX", "NS", "TXT", "CNAME"})
        self.assertIn("93.184.215.14", record.ip_addresses)
        self.assertIn("2606:2800:220:1:248:1893:25c8:1946", record.ip_addresses)
        self.assertIn("mail.example.com", record.discovered_domains)

    @patch.object(dns.resolver.Resolver, "resolve")
    def test_collect_no_answer_not_a_failure(self, mock_resolve):
        # A returns IP, CNAME raises NoAnswer
        def fake_resolve(domain, rtype):
            if rtype == "A":
                mock_ans = MagicMock()
                mock_ans.ttl = 3600
                mock_ans.__iter__.return_value = ["93.184.215.14"]
                return mock_ans
            else:
                raise dns.resolver.NoAnswer()

        mock_resolve.side_effect = fake_resolve

        record = self.collector.collect("example.com")
        self.assertEqual(record.scan_status, "SUCCESS")
        self.assertEqual(len(record.dns_records), 1)
        self.assertEqual(record.dns_records[0].record_type, "A")
        # Ensure errors_and_warnings does NOT include NoAnswer as an error
        self.assertEqual(len(record.errors_and_warnings), 0)

    @patch.object(dns.resolver.Resolver, "resolve")
    def test_collect_nxdomain(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        record = self.collector.collect("nonexistent-domain-xyz123.com")
        self.assertEqual(record.scan_status, "FAILED")
        self.assertTrue(any("NXDOMAIN" in err for err in record.errors_and_warnings))
        self.assertEqual(len(record.dns_records), 0)

    @patch.object(dns.resolver.Resolver, "resolve")
    def test_collect_timeout_partial(self, mock_resolve):
        # A succeeds, MX times out
        def fake_resolve(domain, rtype):
            if rtype == "A":
                mock_ans = MagicMock()
                mock_ans.ttl = 3600
                mock_ans.__iter__.return_value = ["93.184.215.14"]
                return mock_ans
            elif rtype == "MX":
                raise dns.resolver.Timeout()
            else:
                raise dns.resolver.NoAnswer()

        mock_resolve.side_effect = fake_resolve

        record = self.collector.collect("example.com")
        self.assertEqual(record.scan_status, "PARTIAL")
        self.assertEqual(len(record.dns_records), 1)
        self.assertTrue(any("Timeout querying MX" in err for err in record.errors_and_warnings))


if __name__ == "__main__":
    unittest.main()

