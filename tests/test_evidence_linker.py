"""
Unit Tests for Evidence Linker and Provenance Tracking (W4 Phase 5)
Tests cryptographic hashing, deterministic evidence IDs, and multi-collector linking.
"""

import os
import unittest
import tempfile

from src.correlation.evidence_linker import (
    EvidenceLinker,
    compute_file_sha256,
    generate_evidence_id
)
from src.schema import (
    ReconRecord,
    TargetInfo,
    ToolInfo,
    DNSRecord,
    WhoisData,
    ActiveReconResult,
    TargetAuthorizationRecord,
    NmapHost,
    NmapPort,
    NmapService
)


class TestEvidenceLinker(unittest.TestCase):

    def setUp(self):
        self.linker = EvidenceLinker()

    def test_compute_file_sha256(self):
        """Verifies file SHA256 calculation."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("hello world evidence\n")
            fpath = f.name
        try:
            h = compute_file_sha256(fpath)
            self.assertIsNotNone(h)
            self.assertEqual(len(h), 64)
        finally:
            os.remove(fpath)

    def test_deterministic_evidence_id(self):
        """Verifies stable evidence ID generation."""
        eid1 = generate_evidence_id("whois", "registrar", "SCAN-01:iana")
        eid2 = generate_evidence_id("whois", "registrar", "SCAN-01:iana")
        self.assertEqual(eid1, eid2)
        self.assertTrue(eid1.startswith("EVID-whois-registrar-"))

    def test_link_passive_records(self):
        """Verifies registering evidence from passive ReconRecord."""
        rec = ReconRecord(
            target_info=TargetInfo(
                target="example.com",
                category="normal_benchmark_domain",
                authorization_status="AUTHORIZED",
                scope="example.com"
            ),
            tool_info=ToolInfo(name="dnspython", version="2.0.0"),
            recon_category="dns",
            scan_id="SCAN-TEST-01",
            dns_records=[
                DNSRecord(record_type="A", value="93.184.216.34", ttl=300),
                DNSRecord(record_type="NS", value="a.iana-servers.net", ttl=3600)
            ],
            evidence_source="memory_stream"
        )
        linked = self.linker.link_passive_records("SCAN-TEST-01", [rec])
        self.assertEqual(len(linked), 2)
        types = [e.evidence_type for e in linked]
        self.assertIn("dns_a_record", types)
        self.assertIn("dns_ns_record", types)

    def test_link_active_result(self):
        """Verifies registering evidence from ActiveReconResult."""
        auth = TargetAuthorizationRecord(
            target="192.168.56.111",
            authorized=True,
            authorization_status="AUTHORIZED_LOCAL_LAB",
            category="intentionally_vulnerable_lab",
            scope="192.168.56.111",
            scan_profile="lab-basic",
            operator="tester"
        )
        active_res = ActiveReconResult(
            scan_id="SCAN-ACTIVE-01",
            target="192.168.56.111",
            authorization_record=auth,
            scan_profile="lab-basic",
            start_time_utc="2026-11-09T08:00:00Z",
            end_time_utc="2026-11-09T08:00:20Z",
            overall_status="SUCCESS",
            hosts=[
                NmapHost(
                    address="192.168.56.111",
                    addrtype="ipv4",
                    status="up",
                    hostnames=["metasploitable.localdomain"],
                    ports=[
                        NmapPort(
                            portid=21,
                            protocol="tcp",
                            state="open",
                            reason="syn-ack",
                            service=NmapService(
                                name="ftp",
                                product="vsftpd",
                                version="2.3.4",
                                cpe=["cpe:/a:vsftpd:vsftpd:2.3.4"]
                            )
                        )
                    ]
                )
            ],
            raw_files={"xml": "/fake/path/nmap.xml"},
            file_hashes={"xml": "a" * 64}
        )

        linked = self.linker.link_active_result(active_res)
        self.assertGreaterEqual(len(linked), 4)
        types = [e.evidence_type for e in linked]
        self.assertIn("nmap_host_status", types)
        self.assertIn("nmap_reverse_hostname", types)
        self.assertIn("nmap_open_port", types)
        self.assertIn("nmap_service_probe", types)
        self.assertIn("nmap_cpe_identifier", types)


if __name__ == "__main__":
    unittest.main()

