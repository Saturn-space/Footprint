"""
Unit tests for Greenbone Report XML Parser (W5).
Verifies parsing of GMP XML reports, extraction of CVEs, CVSS scores, QoD metrics,
remediation solutions, metadata, and error handling for malformed or empty inputs.
"""

import unittest
from src.parsers.greenbone_parser import (
    GreenboneReportParser,
    GreenboneXMLParseError,
    parse_port_protocol,
    parse_nvt_tags
)

SAMPLE_GMP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<report id="rep-001-mock" format_id="d5da9f67-e111-11e0-80fb-406186ea4fc5">
  <task id="task-100-mock">
    <name>OSINT-RECON Assessment</name>
  </task>
  <scan_start>2026-11-09T10:00:00Z</scan_start>
  <scan_end>2026-11-09T10:15:30Z</scan_end>
  <config id="daba56c8-73ec-11df-a475-002264764cea">
    <name>Full and fast</name>
  </config>
  <results>
    <result id="res-101">
      <name>vsftpd 2.3.4 Backdoor Execution</name>
      <host>192.168.56.111</host>
      <port>21/tcp</port>
      <threat>Critical</threat>
      <severity>10.0</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.103185">
        <name>vsftpd 2.3.4 Backdoor Execution</name>
        <cve>CVE-2011-2523</cve>
        <cvss_base>10.0</cvss_base>
        <cvss_version>2.0</cvss_version>
        <tags>summary=The remote FTP server contains a backdoor.|insight=vsftpd 2.3.4 contains a malicious backdoor.|solution_type=VendorFix</tags>
        <solution>Upgrade vsftpd to version 2.3.5 or later.</solution>
        <xref>
          <type>URL</type>
          <value>https://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html</value>
        </xref>
      </nvt>
      <description>The remote vsftpd daemon is compromised with an intentional backdoor.</description>
      <qod>
        <value>97</value>
        <type>remote_vul</type>
      </qod>
      <creation_time>2026-11-09T10:05:00Z</creation_time>
    </result>
    <result id="res-102">
      <name>Apache Tomcat Default Credentials</name>
      <host>192.168.56.111</host>
      <port>8180/tcp</port>
      <threat>High</threat>
      <severity>7.5</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.103001">
        <name>Apache Tomcat Default Credentials</name>
        <cve>NOCVE</cve>
        <cvss_base>7.5</cvss_base>
        <cvss_version>2.0</cvss_version>
        <tags>summary=Tomcat manager has default password.|solution=Change default credentials.|solution_type=Workaround</tags>
      </nvt>
      <description>Default admin credentials found on Apache Tomcat.</description>
      <qod>
        <value>80</value>
        <type>remote_active</type>
      </qod>
      <creation_time>2026-11-09T10:07:00Z</creation_time>
    </result>
    <result id="res-103">
      <name>ICMP Timestamp Reply Information Disclosure</name>
      <host>192.168.56.111</host>
      <port>general/icmp</port>
      <threat>Low</threat>
      <severity>2.1</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.80001">
        <name>ICMP Timestamp Reply Information Disclosure</name>
        <cve>CVE-1999-0524</cve>
        <cvss_base>2.1</cvss_base>
        <cvss_version>2.0</cvss_version>
        <tags>summary=ICMP timestamp reply information leakage.</tags>
      </nvt>
      <description>The remote host responds to ICMP timestamp requests.</description>
      <creation_time>2026-11-09T10:08:00Z</creation_time>
    </result>
  </results>
</report>
"""


class TestGreenboneParser(unittest.TestCase):
    """Tests GreenboneReportParser and helper parsing routines."""

    def setUp(self):
        self.parser = GreenboneReportParser()

    def test_parse_port_protocol_helpers(self):
        """Test parsing various port and protocol formats."""
        self.assertEqual(parse_port_protocol("21/tcp"), (21, "tcp"))
        self.assertEqual(parse_port_protocol("80/udp"), (80, "udp"))
        self.assertEqual(parse_port_protocol("8080"), (8080, "tcp"))
        self.assertEqual(parse_port_protocol("general/tcp"), (0, "tcp"))
        self.assertEqual(parse_port_protocol("general/icmp"), (0, "icmp"))
        self.assertEqual(parse_port_protocol(""), (0, "general"))
        self.assertEqual(parse_port_protocol(None), (0, "general"))

    def test_parse_nvt_tags_helper(self):
        """Test pipe-delimited tag parsing."""
        tag_str = "summary=Test Summary|insight=Deep Insight|solution_type=VendorFix"
        tags = parse_nvt_tags(tag_str)
        self.assertEqual(tags.get("summary"), "Test Summary")
        self.assertEqual(tags.get("insight"), "Deep Insight")
        self.assertEqual(tags.get("solution_type"), "VendorFix")

        self.assertEqual(parse_nvt_tags(None), {})
        self.assertEqual(parse_nvt_tags(""), {})

    def test_parse_sample_report_xml(self):
        """Test full parsing of canonical GMP XML report."""
        findings, metadata = self.parser.parse_report_xml(SAMPLE_GMP_XML, default_host="192.168.56.111")

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.task_id, "task-100-mock")
        self.assertEqual(metadata.report_id, "rep-001-mock")
        self.assertEqual(metadata.config_name, "Full and fast")
        self.assertEqual(metadata.status, "Done")

        self.assertEqual(len(findings), 3)

        # Check Finding 1 (Critical)
        f1 = findings[0]
        self.assertEqual(f1.finding_id, "res-101")
        self.assertEqual(f1.name, "vsftpd 2.3.4 Backdoor Execution")
        self.assertEqual(f1.host, "192.168.56.111")
        self.assertEqual(f1.port, 21)
        self.assertEqual(f1.protocol, "tcp")
        self.assertEqual(f1.threat, "Critical")
        self.assertEqual(f1.severity, 10.0)
        self.assertEqual(f1.cvss_base, 10.0)
        self.assertEqual(f1.cve_ids, ["CVE-2011-2523"])
        self.assertEqual(f1.qod, 97)
        self.assertEqual(f1.qod_type, "remote_vul")
        self.assertEqual(f1.solution, "Upgrade vsftpd to version 2.3.5 or later.")
        self.assertEqual(f1.solution_type, "VendorFix")
        self.assertEqual(len(f1.references), 1)
        self.assertIn("scarybeastsecurity", f1.references[0])

        # Check Finding 2 (High, NOCVE handled)
        f2 = findings[1]
        self.assertEqual(f2.finding_id, "res-102")
        self.assertEqual(f2.port, 8180)
        self.assertEqual(f2.threat, "High")
        self.assertEqual(f2.cve_ids, [])
        self.assertEqual(f2.solution, "Change default credentials.")
        self.assertEqual(f2.solution_type, "Workaround")

        # Check Finding 3 (Low, General ICMP port)
        f3 = findings[2]
        self.assertEqual(f3.finding_id, "res-103")
        self.assertEqual(f3.port, 0)
        self.assertEqual(f3.protocol, "icmp")
        self.assertEqual(f3.threat, "Low")
        self.assertEqual(f3.cve_ids, ["CVE-1999-0524"])

    def test_parse_empty_xml_raises_error(self):
        """Test empty XML string raises GreenboneXMLParseError."""
        with self.assertRaises(GreenboneXMLParseError):
            self.parser.parse_report_xml("")

        with self.assertRaises(GreenboneXMLParseError):
            self.parser.parse_report_xml("   ")

    def test_parse_malformed_xml_raises_error(self):
        """Test malformed XML structure raises GreenboneXMLParseError."""
        with self.assertRaises(GreenboneXMLParseError):
            self.parser.parse_report_xml("<report><unclosed_tag></report>")

    def test_parse_no_report_tag_raises_error(self):
        """Test XML without <report> or <results> raises GreenboneXMLParseError."""
        with self.assertRaises(GreenboneXMLParseError):
            self.parser.parse_report_xml("<some_other_root><data>hello</data></some_other_root>")


if __name__ == "__main__":
    unittest.main()

