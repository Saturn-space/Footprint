"""
FootprintIQ - Unit Tests for Exposure Scoring and Risk Prioritization Engine
"""

import unittest
from src.services.exposure_scoring import ExposureScoringEngine


class TestExposureScoringEngine(unittest.TestCase):
    def test_empty_findings_exposure(self):
        result = ExposureScoringEngine.calculate_investigation_exposure([])
        self.assertEqual(result["exposure_score"], 0.0)
        self.assertEqual(result["exposure_level"], "Minimal")
        self.assertEqual(result["total_findings"], 0)

    def test_single_critical_finding_risk(self):
        finding = {
            "finding_id": "V-001",
            "severity": "Critical",
            "cvss_score": 9.8,
            "confidence": 0.95,
            "verification_status": "verified"
        }
        risk = ExposureScoringEngine.calculate_finding_risk(finding)
        self.assertGreaterEqual(risk["risk_score"], 80.0)
        self.assertEqual(risk["score_source"], "CVSS 9.8")

    def test_multi_scanner_corroboration_boost(self):
        findings = [
            {
                "finding_id": "F-001",
                "target_ip": "192.168.56.111",
                "cve_identifiers": "CVE-2011-2523",
                "detection_source": "nse",
                "cvss_score": 9.8,
                "severity": "Critical",
                "confidence": 0.90,
                "verification_status": "verified"
            },
            {
                "finding_id": "F-002",
                "target_ip": "192.168.56.111",
                "cve_identifiers": "CVE-2011-2523",
                "detection_source": "nessus",
                "cvss_score": 9.8,
                "severity": "Critical",
                "confidence": 0.90,
                "verification_status": "verified"
            }
        ]
        result = ExposureScoringEngine.calculate_investigation_exposure(findings)
        self.assertEqual(result["total_findings"], 2)
        self.assertEqual(result["severity_counts"]["Critical"], 2)
        self.assertGreater(result["exposure_score"], 65.0)
        # Check corroboration flag
        self.assertTrue(result["prioritized_findings"][0]["corroborated"])

    def test_qualitative_exposure_levels(self):
        # High count of criticals
        findings = [
            {"finding_id": f"C-{i}", "severity": "Critical", "cvss_score": 9.8, "confidence": 1.0, "verification_status": "verified"}
            for i in range(5)
        ]
        result = ExposureScoringEngine.calculate_investigation_exposure(findings)
        self.assertEqual(result["exposure_level"], "Critical")
        self.assertGreaterEqual(result["exposure_score"], 80.0)


if __name__ == "__main__":
    unittest.main()

