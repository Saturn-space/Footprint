"""
Unit Tests for Asset Normalization and Entity Resolution (W4 Phase 3)
Tests entity normalization, deterministic asset IDs, duplicate merging,
and provenance preservation.
"""

import unittest
from datetime import datetime, timezone

from src.correlation.asset_resolver import (
    AssetResolver,
    normalize_domain_name,
    normalize_ip_address,
    normalize_email_address,
    normalize_cpe,
    normalize_service_name,
    generate_asset_id
)
from src.schema import NormalizedFinding, ReconRecord, TargetInfo, ToolInfo, DNSRecord, WhoisData


class TestAssetResolver(unittest.TestCase):

    def setUp(self):
        self.resolver = AssetResolver(
            lab_subnets=["192.168.56.0/24"],
            lab_hosts=["192.168.56.111"]
        )

    def test_domain_normalization(self):
        """Verifies domain normalization to lowercase, stripped FQDN."""
        self.assertEqual(normalize_domain_name("EXAMPLE.COM."), "example.com")
        self.assertEqual(normalize_domain_name("https://example.com/"), "example.com")
        self.assertEqual(normalize_domain_name("http://Sub.Example.com:8080/path"), "sub.example.com")

    def test_ipv4_normalization(self):
        """Verifies IPv4 address canonicalization using ipaddress."""
        canon, cat = normalize_ip_address("192.168.056.111")
        self.assertEqual(canon, "192.168.56.111")
        self.assertEqual(cat, "ipv4")

        # Invalid IP raises ValueError
        with self.assertRaises(ValueError):
            normalize_ip_address("999.999.999.999")

    def test_ipv6_normalization(self):
        """Verifies IPv6 canonicalization to exploded standard format."""
        canon, cat = normalize_ip_address("2606:4700:10::6814:179a")
        self.assertEqual(cat, "ipv6")
        self.assertEqual(canon, "2606:4700:0010:0000:0000:0000:6814:179a")

    def test_email_normalization(self):
        """Verifies email lowercases domain part and preserves local part."""
        self.assertEqual(normalize_email_address("John.Doe@EXAMPLE.COM."), "John.Doe@example.com")
        self.assertEqual(normalize_email_address("security@example.com"), "security@example.com")

    def test_cpe_normalization(self):
        """Verifies CPE string normalization."""
        self.assertEqual(
            normalize_cpe(" cpe:/a:OpenBSD:OpenSSH:4.7p1 "),
            "cpe:/a:openbsd:openssh:4.7p1"
        )

    def test_deterministic_asset_id_stability(self):
        """Verifies asset IDs are stable and deterministic across invocations."""
        id1 = generate_asset_id("domain", "example.com")
        id2 = generate_asset_id("domain", "example.com")
        self.assertEqual(id1, id2)
        self.assertEqual(id1, "ASSET:DOMAIN:example.com")

    def test_exact_duplicate_merging_preserves_provenance(self):
        """Verifies registering identical asset merges sources, updates timestamps, and preserves tags."""
        t1 = "2026-11-09T08:00:00Z"
        t2 = "2026-11-09T09:00:00Z"

        a1 = self.resolver.register_asset(
            asset_type="ipv4",
            canonical_value="192.168.56.111",
            source="nmap",
            tags=["lab"],
            observed_at=t1
        )
        self.assertEqual(a1.first_seen, t1)
        self.assertEqual(a1.last_seen, t1)
        self.assertEqual(a1.sources, ["nmap"])

        # Second observation of same IP from another tool later
        a2 = self.resolver.register_asset(
            asset_type="ipv4",
            canonical_value="192.168.56.111",
            source="arp_scan",
            tags=["host_up"],
            observed_at=t2
        )
        # Should be identical instance in registry
        self.assertEqual(a1.asset_id, a2.asset_id)
        self.assertEqual(a2.first_seen, t1)
        self.assertEqual(a2.last_seen, t2)
        self.assertIn("nmap", a2.sources)
        self.assertIn("arp_scan", a2.sources)
        self.assertIn("lab", a2.tags)
        self.assertIn("host_up", a2.tags)

    def test_distinct_entities_remain_separated(self):
        """Verifies distinct domains and IPs remain completely separated."""
        self.resolver.register_asset("domain", "example.com")
        self.resolver.register_asset("ipv4", "192.168.56.111")
        self.resolver.register_asset("ipv4", "127.0.0.1")

        all_assets = self.resolver.get_all_assets()
        self.assertEqual(len(all_assets), 3)
        ids = [a.asset_id for a in all_assets]
        self.assertIn("ASSET:DOMAIN:example.com", ids)
        self.assertIn("ASSET:IPV4:192.168.56.111", ids)
        self.assertIn("ASSET:IPV4:127.0.0.1", ids)

    def test_lab_asset_tagging(self):
        """Verifies lab IP addresses receive the 'lab' tag automatically."""
        a = self.resolver.register_asset("ipv4", "192.168.56.111")
        self.assertIn("lab", a.tags)
        self.assertNotIn("public_ip", a.tags)

    def test_public_asset_tagging(self):
        """Verifies public IP addresses receive the 'public_ip' tag automatically."""
        a = self.resolver.register_asset("ipv4", "93.184.216.34")
        self.assertIn("public_ip", a.tags)
        self.assertNotIn("lab", a.tags)


if __name__ == "__main__":
    unittest.main()

