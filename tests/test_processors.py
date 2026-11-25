"""
Unit Tests for Processors (Normalizer, Deduplicator, Correlator)
Validates atomicity, deduplication with provenance retention, and defensive correlation.
"""

import unittest
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.schema import ReconRecord, TargetInfo, ToolInfo, DNSRecord, WhoisData, NormalizedFinding
from src.processors.normalizer import FindingNormalizer, clean_domain
from src.processors.deduplicator import FindingDeduplicator
from src.processors.correlator import FindingCorrelator


class TestProcessors(unittest.TestCase):

    def setUp(self):
        self.normalizer = FindingNormalizer()
        self.deduplicator = FindingDeduplicator()
        self.correlator = FindingCorrelator()

    def test_clean_domain(self):
        self.assertEqual(clean_domain("2Fdocs.example.com."), "docs.example.com")
        self.assertEqual(clean_domain("https://API.EXAMPLE.COM:8080/v1"), "api.example.com")

    def test_normalize_record_whois(self):
        rec = ReconRecord(
            target_info=TargetInfo(
                target="example.com",
                category="normal_benchmark_domain",
                authorization_status="AUTHORIZED_PASSIVE_ONLY",
                scope="example.com"
            ),
            tool_info=ToolInfo(name="whois", version="5.6.5"),
            recon_category="whois",
            scan_id="SCAN-001",
            whois_data=WhoisData(
                domain_name="EXAMPLE.COM",
                registrar="Example Registrar Inc",
                name_servers=["ns1.example.com", "ns2.example.com"],
                emails=["abuse@example.com"]
            ),
            evidence_source="whois-raw"
        )
        findings = self.normalizer.normalize_record(rec)
        types = {f.finding_type for f in findings}
        self.assertIn("domain", types)
        self.assertIn("registrar", types)
        self.assertIn("nameserver", types)
        self.assertIn("email", types)

        reg_finding = next(f for f in findings if f.finding_type == "registrar")
        self.assertEqual(reg_finding.finding_value, "Example Registrar Inc")

    def test_deduplicator_source_attribution_preservation(self):
        f1 = NormalizedFinding(
            target="example.com",
            scan_id="SCAN-001",
            collector="whois",
            finding_type="subdomain",
            finding_value="mail.example.com",
            source_tools=["whois"],
            source_details={"source": "whois-ns"},
            evidence_reference="evidence-whois.txt"
        )
        f2 = NormalizedFinding(
            target="example.com",
            scan_id="SCAN-001",
            collector="dns",
            finding_type="subdomain",
            finding_value="mail.example.com",
            source_tools=["dnspython"],
            source_details={"record_type": "MX"},
            evidence_reference="evidence-dns.txt"
        )

        deduped = self.deduplicator.deduplicate([f1, f2])
        self.assertEqual(len(deduped), 1)
        merged = deduped[0]
        self.assertEqual(merged.finding_value, "mail.example.com")
        # Ensure BOTH tools are retained
        self.assertIn("whois", merged.source_tools)
        self.assertIn("dnspython", merged.source_tools)
        # Ensure combined evidence reference
        self.assertIn("evidence-whois.txt", merged.evidence_reference)
        self.assertIn("evidence-dns.txt", merged.evidence_reference)

    def test_correlator_defensive_insights(self):
        findings = [
            NormalizedFinding(
                target="example.com",
                scan_id="SCAN-001",
                collector="dns",
                finding_type="dns_record",
                finding_value="v=spf1 include:_spf.example.com -all",
                source_tools=["dnspython"],
                source_details={"record_type": "TXT"}
            ),
            NormalizedFinding(
                target="example.com",
                scan_id="SCAN-001",
                collector="theharvester",
                finding_type="email",
                finding_value="contact@example.com",
                source_tools=["theHarvester"]
            )
        ]
        summary, observations, actions = self.correlator.correlate("example.com", findings, [])
        self.assertEqual(summary["total_normalized_findings"], 2)
        self.assertEqual(summary["email_addresses_count"], 1)

        # Check SPF was detected
        self.assertTrue(any("SPF record detected" in obs for obs in observations))
        # Check DMARC missing action suggested
        self.assertTrue(any("DMARC" in act for act in actions))
        # Check email exposure observation
        self.assertTrue(any("Information Exposure" in obs for obs in observations))


if __name__ == "__main__":
    unittest.main()

