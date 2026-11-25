"""
FootprintIQ - Unit Tests for Nessus Scanner Collector Adapter
"""

import unittest
from src.collectors.nessus_collector import NessusCollector


class TestNessusCollector(unittest.TestCase):
    def test_nessus_offline_status_detection(self):
        collector = NessusCollector(base_url="https://127.0.0.1:8834")
        status = collector.check_status()
        self.assertIn(status["status"], ("ONLINE", "OFFLINE"))
        if status["status"] == "OFFLINE":
            self.assertEqual(status["live_integration_status"], "NOT TESTED")

    def test_nessus_simulation_fallback(self):
        collector = NessusCollector()
        res = collector.scan_target(target="192.168.56.111", investigation_id="INV-TEST")
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["target"], "192.168.56.111")
        self.assertGreater(res["vulnerabilities_found"], 0)
        # Verify vsftpd backdoor finding structure
        findings = res["findings"]
        vsftpd = next((f for f in findings if f["port"] == 21), None)
        self.assertIsNotNone(vsftpd)
        self.assertEqual(vsftpd["cve_identifiers"], "CVE-2011-2523")
        self.assertEqual(vsftpd["severity"], "Critical")
        self.assertEqual(vsftpd["detection_source"], "nessus")


if __name__ == "__main__":
    unittest.main()

