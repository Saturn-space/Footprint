"""
Integration Tests for Active Reconnaissance Pipeline
Validates end-to-end orchestration, target authorization enforcement,
schema validation, evidence persistence, and dual JSON/PDF reporting with mocks.
"""

import unittest
from unittest.mock import patch, MagicMock
import os
import sys
import json
import tempfile
import jsonschema

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.orchestration.active_pipeline import ActiveReconPipeline, generate_scan_id
from src.collectors.nmap_collector import NmapCollectorResult
from src.schema import ActiveReconResult

MOCK_METASPLOITABLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV 192.168.56.111" start="1700000000" version="7.99">
<scaninfo type="connect" protocol="tcp" numservices="2" services="21,22"/>
<host starttime="1700000000" endtime="1700000002">
  <status state="up" reason="syn-ack"/>
  <address addr="192.168.56.111" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="21">
      <state state="open" reason="syn-ack"/>
      <service name="ftp" product="vsftpd" version="2.3.4" method="probed">
        <cpe>cpe:/a:vsftpd:vsftpd:2.3.4</cpe>
      </service>
    </port>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="4.7p1 Debian" method="probed">
        <cpe>cpe:/a:openbsd:openssh:4.7p1</cpe>
      </service>
    </port>
  </ports>
</host>
<runstats>
  <finished time="1700000002" elapsed="2.0" exit="success"/>
  <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
"""


class TestActivePipelineIntegration(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.pipeline = ActiveReconPipeline(
            base_dir=self.tmp_dir.name,
            timeout=10,
            enable_pdf=True
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_scan_id_generation(self):
        """Verifies unique, timestamped scan ID format."""
        sid1 = generate_scan_id()
        sid2 = generate_scan_id()
        self.assertNotEqual(sid1, sid2)
        self.assertTrue(sid1.startswith("SCAN-"))

    def test_unauthorized_target_pipeline_rejection(self):
        """Verifies pipeline immediately rejects unauthorized target with FAILED status."""
        result = self.pipeline.run(target="8.8.8.8")
        self.assertEqual(result.overall_status, "FAILED")
        self.assertFalse(result.authorization_record.authorized)
        self.assertTrue(any("public routable" in err for err in result.errors))

    @patch("src.authorization.target_authorizer.TargetAuthorizer.verify_target_connectivity")
    def test_offline_target_marks_blocked(self, mock_conn):
        """Verifies offline lab target is cleanly trapped and marked BLOCKED."""
        mock_conn.return_value = (False, "Target 192.168.56.111 is unreachable")
        result = self.pipeline.run(target="192.168.56.111")
        self.assertEqual(result.overall_status, "BLOCKED")
        self.assertTrue(any("UNREACHABLE or OFFLINE" in err for err in result.errors))
        self.assertEqual(len(result.hosts), 0)

    @patch("src.collectors.nmap_collector.NmapCollector.execute_scan")
    @patch("src.authorization.target_authorizer.TargetAuthorizer.verify_target_connectivity")
    def test_full_active_pipeline_success(self, mock_conn, mock_exec):
        """Verifies end-to-end active pipeline with mocked XML output."""
        mock_conn.return_value = (True, "Target is UP")

        def fake_scan(auth_record, profile_name="lab-basic", output_dir=None, timeout=None):
            xml_file = os.path.join(output_dir, "nmap_scan.xml")
            with open(xml_file, "w", encoding="utf-8") as f:
                f.write(MOCK_METASPLOITABLE_XML)
            return NmapCollectorResult(
                command_list=["nmap", "-sT", "-sV", auth_record.target],
                returncode=0,
                stdout="Nmap done",
                stderr="",
                xml_path=xml_file,
                stdout_path=os.path.join(output_dir, "nmap_stdout.txt"),
                stderr_path=os.path.join(output_dir, "nmap_stderr.txt"),
                metadata_path=os.path.join(output_dir, "scan_metadata.json"),
                duration_seconds=2.0,
                file_hashes={"xml": "mockhash"}
            )

        mock_exec.side_effect = fake_scan

        result = self.pipeline.run(target="192.168.56.111", profile="lab-basic")

        self.assertEqual(result.overall_status, "SUCCESS")
        self.assertEqual(result.target, "192.168.56.111")
        self.assertEqual(len(result.hosts), 1)

        # Check discovered ports
        host = result.hosts[0]
        self.assertEqual(len(host.ports), 2)
        port_ids = [p.portid for p in host.ports]
        self.assertIn(21, port_ids)
        self.assertIn(22, port_ids)

        # Check ReconRecord schema compliance
        self.assertIsNotNone(result.recon_record)
        self.assertEqual(result.recon_record.recon_category, "port_scan")
        self.assertEqual(result.recon_record.open_ports, [21, 22])

        # Validate ReconRecord against recon_schema.json
        if self.pipeline.json_schema:
            rec_dict = json.loads(result.recon_record.model_dump_json())
            jsonschema.validate(instance=rec_dict, schema=self.pipeline.json_schema)

        # Check JSON report on disk
        self.assertIsNotNone(result.json_report_path)
        self.assertTrue(os.path.isfile(result.json_report_path))
        with open(result.json_report_path, "r", encoding="utf-8") as jf:
            loaded_json = json.load(jf)
            self.assertEqual(loaded_json["scan_id"], result.scan_id)
            self.assertEqual(loaded_json["target"], "192.168.56.111")

        # Check PDF report on disk
        self.assertIsNotNone(result.pdf_report_path)
        self.assertTrue(os.path.isfile(result.pdf_report_path))
        self.assertGreater(os.path.getsize(result.pdf_report_path), 1000)


if __name__ == "__main__":
    unittest.main()

