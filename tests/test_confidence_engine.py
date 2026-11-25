"""
Unit Tests for Confidence Engine and Scoring (W4 Phase 5)
Tests multi-source corroboration, direct technical observation, indirect heuristics,
and duplicate source containment.
"""

import unittest

from src.correlation.confidence_engine import ConfidenceEngine, CONFIDENCE_LEVELS
from src.schema import EvidenceReference


class TestConfidenceEngine(unittest.TestCase):

    def setUp(self):
        self.engine = ConfidenceEngine()

    def test_direct_evidence_scoring(self):
        """Verifies single direct technical observation yields DIRECT (0.85)."""
        ev = EvidenceReference(
            evidence_id="EVID-1",
            source_module="dnspython",
            scan_id="SCAN-01",
            evidence_type="dns_a_record",
            original_value="93.184.216.34",
            normalized_value="93.184.216.34"
        )
        conf_class, conf_score, expl = self.engine.evaluate_relationship(
            relationship_type="DOMAIN_RESOLVES_TO_IP",
            evidence_list=[ev]
        )
        self.assertEqual(conf_class, "DIRECT")
        self.assertEqual(conf_score, 0.85)
        self.assertIn("DIRECT", expl)
        self.assertIn("dnspython", expl)

    def test_corroborated_multi_source_scoring(self):
        """Verifies multi-source independent confirmation yields CORROBORATED (0.95)."""
        ev1 = EvidenceReference(
            evidence_id="EVID-1",
            source_module="dnspython",
            scan_id="SCAN-01",
            evidence_type="dns_ns_record",
            original_value="a.iana-servers.net",
            normalized_value="a.iana-servers.net"
        )
        ev2 = EvidenceReference(
            evidence_id="EVID-2",
            source_module="whois",
            scan_id="SCAN-01",
            evidence_type="whois_nameserver",
            original_value="a.iana-servers.net",
            normalized_value="a.iana-servers.net"
        )
        conf_class, conf_score, expl = self.engine.evaluate_relationship(
            relationship_type="DOMAIN_USES_NAMESERVER",
            evidence_list=[ev1, ev2]
        )
        self.assertEqual(conf_class, "CORROBORATED")
        self.assertEqual(conf_score, 0.95)
        self.assertIn("CORROBORATED", expl)
        self.assertIn("dnspython", expl)
        self.assertIn("whois", expl)

    def test_duplicate_observations_from_same_source_do_not_corroborate(self):
        """Verifies repeated observations from the SAME tool do not inflate to CORROBORATED."""
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
            source_module="dnspython",
            scan_id="SCAN-02",
            evidence_type="dns_a_record",
            original_value="93.184.216.34",
            normalized_value="93.184.216.34"
        )
        conf_class, conf_score, expl = self.engine.evaluate_relationship(
            relationship_type="DOMAIN_RESOLVES_TO_IP",
            evidence_list=[ev1, ev2]
        )
        self.assertEqual(conf_class, "DIRECT")
        self.assertEqual(conf_score, 0.85)

    def test_indirect_evidence_scoring(self):
        """Verifies associative heuristics yield INDIRECT (0.65)."""
        ev = EvidenceReference(
            evidence_id="EVID-1",
            source_module="whois",
            scan_id="SCAN-01",
            evidence_type="whois_email",
            original_value="contact@example.com",
            normalized_value="contact@example.com"
        )
        conf_class, conf_score, expl = self.engine.evaluate_relationship(
            relationship_type="EMAIL_DOMAIN_ASSOCIATION",
            evidence_list=[ev]
        )
        self.assertEqual(conf_class, "INDIRECT")
        self.assertEqual(conf_score, 0.65)
        self.assertIn("INDIRECT", expl)

    def test_empty_evidence_handling(self):
        """Verifies empty evidence list yields UNCONFIRMED with low score."""
        conf_class, conf_score, expl = self.engine.evaluate_relationship(
            relationship_type="DOMAIN_RESOLVES_TO_IP",
            evidence_list=[]
        )
        self.assertEqual(conf_class, "UNCONFIRMED")
        self.assertLessEqual(conf_score, 0.40)


if __name__ == "__main__":
    unittest.main()

