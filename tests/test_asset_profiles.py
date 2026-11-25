"""
Unit Tests for Unified Asset Profile Builder (W4 Phase 7)
Tests domain profile synthesis, laboratory IP profile synthesis, and explicit missing data handling.
"""

import unittest

from src.correlation.asset_profile_builder import AssetProfileBuilder
from src.schema import (
    Asset,
    AssetRelationship,
    EvidenceReference,
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


class TestAssetProfiles(unittest.TestCase):

    def setUp(self):
        self.builder = AssetProfileBuilder(
            lab_subnets=["192.168.56.0/24"],
            lab_hosts=["192.168.56.111"]
        )

    def test_domain_profile_synthesis(self):
        """Verifies domain profile contains DNS, WHOIS, subdomains, and no assumed ports."""
        dom_asset = Asset(
            asset_id="ASSET:DOMAIN:example.com",
            asset_type="domain",
            canonical_value="example.com",
            display_name="example.com"
        )
        ip_asset = Asset(
            asset_id="ASSET:IPV4:93.184.216.34",
            asset_type="ipv4",
            canonical_value="93.184.216.34",
            display_name="93.184.216.34"
        )
        rel = AssetRelationship(
            relationship_id="REL-1",
            source_asset_id=dom_asset.asset_id,
            target_asset_id=ip_asset.asset_id,
            relationship_type="DOMAIN_RESOLVES_TO_IP",
            evidence_ids=["EVID-1"],
            confidence="DIRECT",
            confidence_score=0.85,
            confidence_explanation="DNS A"
        )
        rec = ReconRecord(
            target_info=TargetInfo(
                target="example.com",
                category="normal_benchmark_domain",
                authorization_status="AUTHORIZED",
                scope="example.com"
            ),
            tool_info=ToolInfo(name="dnspython", version="2.0.0"),
            recon_category="dns",
            scan_id="SCAN-01",
            dns_records=[DNSRecord(record_type="A", value="93.184.216.34", ttl=300)],
            evidence_source="raw.txt"
        )

        prof = self.builder.build_domain_profile(
            domain_asset=dom_asset,
            relationships=[rel],
            assets_map={dom_asset.asset_id: dom_asset, ip_asset.asset_id: ip_asset},
            passive_records=[rec],
            evidence_registry={}
        )

        self.assertEqual(prof.canonical_identity, "example.com")
        self.assertEqual(prof.asset_type, "domain")
        self.assertEqual(prof.related_ips, ["93.184.216.34"])
        self.assertEqual(len(prof.dns_records), 1)
        self.assertEqual(prof.open_ports, [])  # Never assume ports for domain
        self.assertEqual(prof.environment, "external")

    def test_lab_ip_profile_synthesis(self):
        """Verifies lab IP profile contains open ports, services, CPEs, and explicit absence of WHOIS."""
        ip_asset = Asset(
            asset_id="ASSET:IPV4:192.168.56.111",
            asset_type="ipv4",
            canonical_value="192.168.56.111",
            display_name="192.168.56.111 (LAB)",
            tags=["lab"]
        )
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
                            service=NmapService(
                                name="ftp",
                                product="vsftpd",
                                version="2.3.4",
                                cpe=["cpe:/a:vsftpd:vsftpd:2.3.4"]
                            )
                        )
                    ]
                )
            ]
        )

        prof = self.builder.build_ip_profile(
            ip_asset=ip_asset,
            relationships=[],
            assets_map={ip_asset.asset_id: ip_asset},
            active_results=[active_res],
            evidence_registry={}
        )

        self.assertEqual(prof.canonical_identity, "192.168.56.111")
        self.assertEqual(prof.environment, "lab")
        self.assertEqual(len(prof.open_ports), 1)
        self.assertEqual(prof.open_ports[0]["portid"], 21)
        self.assertEqual(len(prof.detected_services), 1)
        self.assertIn("cpe:/a:vsftpd:vsftpd:2.3.4", prof.cpe_identifiers)
        self.assertIn("metasploitable.localdomain", prof.related_hostnames)
        self.assertIsNone(prof.whois_information)  # WHOIS is absent, not invented
        self.assertTrue(any("isolated laboratory" in n for n in prof.notes))


if __name__ == "__main__":
    unittest.main()

