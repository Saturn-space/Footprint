"""
Unit Tests for Relationship Correlation Builder (W4 Phase 4)
Tests evidence-backed relationship construction, duplicate relationship handling,
unsupported relationship rejection, and strict laboratory isolation.
"""

import unittest

from src.correlation.relationship_builder import RelationshipBuilder
from src.correlation.confidence_engine import ConfidenceEngine
from src.schema import Asset, EvidenceReference, ReconRecord, TargetInfo, ToolInfo, DNSRecord


class TestRelationshipBuilder(unittest.TestCase):

    def setUp(self):
        self.builder = RelationshipBuilder()
        self.domain_asset = Asset(
            asset_id="ASSET:DOMAIN:example.com",
            asset_type="domain",
            canonical_value="example.com",
            display_name="example.com",
            sources=["whois"]
        )
        self.ip_asset = Asset(
            asset_id="ASSET:IPV4:93.184.216.34",
            asset_type="ipv4",
            canonical_value="93.184.216.34",
            display_name="93.184.216.34",
            sources=["dnspython"]
        )
        self.lab_ip_asset = Asset(
            asset_id="ASSET:IPV4:192.168.56.111",
            asset_type="ipv4",
            canonical_value="192.168.56.111",
            display_name="192.168.56.111 (LAB)",
            tags=["lab"],
            sources=["nmap"]
        )

    def test_domain_resolves_to_ip_relationship(self):
        """Verifies DNS A evidence establishes DOMAIN_RESOLVES_TO_IP."""
        ev = EvidenceReference(
            evidence_id="EVID-DNS-A-1",
            source_module="dnspython",
            scan_id="SCAN-01",
            evidence_type="dns_a_record",
            original_value="93.184.216.34",
            normalized_value="93.184.216.34"
        )
        rel = self.builder.add_relationship(
            source_asset=self.domain_asset,
            target_asset=self.ip_asset,
            relationship_type="DOMAIN_RESOLVES_TO_IP",
            supporting_evidence=[ev]
        )
        self.assertIsNotNone(rel)
        self.assertEqual(rel.relationship_type, "DOMAIN_RESOLVES_TO_IP")
        self.assertEqual(rel.source_asset_id, "ASSET:DOMAIN:example.com")
        self.assertEqual(rel.target_asset_id, "ASSET:IPV4:93.184.216.34")
        self.assertEqual(rel.confidence, "DIRECT")

    def test_unsupported_relationship_rejected_without_evidence(self):
        """Verifies relationship without supporting evidence is rejected (returns None)."""
        rel = self.builder.add_relationship(
            source_asset=self.domain_asset,
            target_asset=self.lab_ip_asset,
            relationship_type="DOMAIN_RESOLVES_TO_IP",
            supporting_evidence=[]
        )
        self.assertIsNone(rel)
        self.assertEqual(len(self.builder.get_all_relationships()), 0)

    def test_lab_asset_isolation_enforced(self):
        """
        Verifies requirement: private lab asset 192.168.56.111 is NOT automatically linked
        to public target example.com in the absence of explicit DNS/source evidence.
        """
        assets_map = {
            self.domain_asset.asset_id: self.domain_asset,
            self.ip_asset.asset_id: self.ip_asset,
            self.lab_ip_asset.asset_id: self.lab_ip_asset
        }
        # Passive records only resolve example.com -> 93.184.216.34
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
            dns_records=[DNSRecord(record_type="A", value="93.184.216.34")],
            evidence_source="raw.txt"
        )
        evidence_registry = {
            "EVID-1": EvidenceReference(
                evidence_id="EVID-1",
                source_module="dnspython",
                scan_id="SCAN-01",
                evidence_type="dns_a_record",
                original_value="93.184.216.34",
                normalized_value="93.184.216.34"
            )
        }

        built = self.builder.build_passive_relationships(
            target_domain_asset=self.domain_asset,
            assets_map=assets_map,
            findings=[],
            records=[rec],
            evidence_registry=evidence_registry
        )

        target_ids = [r.target_asset_id for r in built]
        self.assertIn("ASSET:IPV4:93.184.216.34", target_ids)
        # CRITICAL ASSERTION: 192.168.56.111 must NOT be in target_ids
        self.assertNotIn("ASSET:IPV4:192.168.56.111", target_ids)

    def test_duplicate_relationship_merging(self):
        """Verifies repeated addition of the same relationship merges evidence IDs."""
        ev1 = EvidenceReference(
            evidence_id="EVID-1",
            source_module="dnspython",
            scan_id="SCAN-01",
            evidence_type="dns_a_record",
            original_value="93.184.216.34",
            normalized_value="93.184.216.34"
        )
        ev2 = EvidenceReference(
            evidence_id="EVID-2",
            source_module="whois",
            scan_id="SCAN-01",
            evidence_type="whois_record",
            original_value="93.184.216.34",
            normalized_value="93.184.216.34"
        )

        r1 = self.builder.add_relationship(self.domain_asset, self.ip_asset, "DOMAIN_RESOLVES_TO_IP", [ev1])
        r2 = self.builder.add_relationship(self.domain_asset, self.ip_asset, "DOMAIN_RESOLVES_TO_IP", [ev2])

        self.assertEqual(r1.relationship_id, r2.relationship_id)
        self.assertEqual(len(self.builder.get_all_relationships()), 1)
        self.assertIn("EVID-1", r2.evidence_ids)
        self.assertIn("EVID-2", r2.evidence_ids)


if __name__ == "__main__":
    unittest.main()

