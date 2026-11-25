"""
Unit and Integration Tests for FootprintIQ Demo Investigation Seeder
Verifies that the 5 demo combined scanning investigations are seeded idempotently,
with multiple completed runs, discovered ports, normalized findings, and exposure scores.
"""

import unittest
from src.db.repository import FootprintIQRepository
from src.services.demo_seeder import seed_demo_investigations, DEMO_CAMPAIGNS_DEF
from src.services.report_analysis_service import build_report_analysis


class TestDemoInvestigationSeeder(unittest.TestCase):
    def setUp(self):
        self.repo = FootprintIQRepository()

    def test_seed_demo_investigations_creates_five_campaigns(self):
        ids = seed_demo_investigations(repo=self.repo, force=True)
        self.assertEqual(len(ids), 5)

        for rid in ids:
            camp = self.repo.get_recon_campaign(rid)
            self.assertIsNotNone(camp)
            self.assertEqual(camp.get("status"), "Completed")
            self.assertEqual(camp.get("progress"), 100)

            # Verify at least 2 completed scan executions per campaign (multi-run trend requirement)
            scans = self.repo.list_scans(investigation_id=rid)
            self.assertGreaterEqual(len(scans), 2)
            for sc in scans:
                self.assertEqual(sc.get("status"), "completed")
                self.assertIsNotNone(sc.get("result_summary_json"))

            # Verify findings exist
            findings = self.repo.list_findings(rid)
            self.assertGreater(len(findings), 0)

            # Verify report analysis datasets
            analysis = build_report_analysis(rid, self.repo)
            analytics = analysis.get("analytics", {})
            self.assertGreater(len(analytics.get("exposed_services", [])), 0)
            self.assertGreaterEqual(analytics.get("trend_completed_count", 0), 2)
            self.assertGreaterEqual(len(analytics.get("historical_trend", [])), 2)

    def test_demo_investigations_idempotency(self):
        # Run seeding twice; verify no duplicates are created
        first_ids = seed_demo_investigations(repo=self.repo, force=False)
        second_ids = seed_demo_investigations(repo=self.repo, force=False)
        self.assertEqual(first_ids, second_ids)


if __name__ == "__main__":
    unittest.main()
