"""
FootprintIQ - Unit Tests for SeaweedFS Client
"""

import unittest
import hashlib
from src.storage.seaweedfs_client import SeaweedFSClient


class TestSeaweedFSClient(unittest.TestCase):
    def setUp(self):
        self.client = SeaweedFSClient()

    def test_health_check(self):
        health = self.client.check_health()
        self.assertIn("status", health)
        self.assertIn(health["status"], ("ONLINE", "DEGRADED", "OFFLINE"))

    def test_upload_and_download_loop(self):
        test_bytes = b"FootprintIQ Cryptographic Evidence Payload 2026"
        expected_hash = hashlib.sha256(test_bytes).hexdigest()

        meta = self.client.upload_content(
            content=test_bytes,
            file_name="unit_test_evidence.bin",
            investigation_id="INV-UNIT-01",
            evidence_type="unit_test"
        )
        self.assertEqual(meta["file_name"], "unit_test_evidence.bin")
        self.assertEqual(meta["sha256_hash"], expected_hash)
        self.assertEqual(meta["file_size"], len(test_bytes))

        # Retrieve
        retrieved = self.client.download_content(
            seaweed_fid=meta.get("seaweed_fid"),
            local_path=meta.get("local_path")
        )
        self.assertEqual(retrieved, test_bytes)


if __name__ == "__main__":
    unittest.main()

