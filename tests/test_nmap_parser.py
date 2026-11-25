"""
Unit Tests for Nmap XML Parser Module
Validates extraction of scan metadata, open/closed/filtered ports, services,
versions, CPE identifiers, empty/malformed XML handling, and defensive fidelity.
"""

import unittest
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.parsers.nmap_xml_parser import NmapXMLParser, NmapXMLParseError
from src.schema import NmapHost, NmapScanMetadata

SAMPLE_VALID_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV -p 21,22,80 192.168.56.111" start="1700000000" version="7.99" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="3" services="21,22,80"/>
<host starttime="1700000000" endtime="1700000005">
  <status state="up" reason="syn-ack"/>
  <address addr="192.168.56.111" addrtype="ipv4"/>
  <hostnames>
    <hostname name="metasploitable2.local" type="PTR"/>
  </hostnames>
  <ports>
    <extraports state="closed" count="97"/>
    <port protocol="tcp" portid="21">
      <state state="open" reason="syn-ack"/>
      <service name="ftp" product="vsftpd" version="2.3.4" conf="10" method="probed">
        <cpe>cpe:/a:vsftpd:vsftpd:2.3.4</cpe>
      </service>
    </port>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="4.7p1 Debian 8ubuntu1" extrainfo="protocol 2.0" conf="10" method="probed">
        <cpe>cpe:/a:openbsd:openssh:4.7p1</cpe>
        <cpe>cpe:/o:linux:linux_kernel</cpe>
      </service>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="Apache httpd" version="2.2.8" extrainfo="(Ubuntu)" conf="10" method="probed">
        <cpe>cpe:/a:apache:http_server:2.2.8</cpe>
      </service>
    </port>
  </ports>
</host>
<runstats>
  <finished time="1700000005" elapsed="5.2" exit="success"/>
  <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
"""

SAMPLE_FILTERED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -p 445 192.168.56.111" start="1700000000" version="7.99">
<host starttime="1700000000" endtime="1700000002">
  <status state="up" reason="localhost-response"/>
  <address addr="192.168.56.111" addrtype="ipv4"/>
  <ports>
    <extraports state="filtered" count="99"/>
    <port protocol="tcp" portid="445">
      <state state="filtered" reason="no-response"/>
      <service name="microsoft-ds"/>
    </port>
  </ports>
</host>
<runstats>
  <finished time="1700000002" elapsed="2.0" exit="success"/>
  <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
"""

SAMPLE_HOST_DOWN_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT 192.168.56.111" start="1700000000" version="7.99">
<host starttime="1700000000" endtime="1700000001">
  <status state="down" reason="no-response"/>
  <address addr="192.168.56.111" addrtype="ipv4"/>
</host>
<runstats>
  <finished time="1700000001" elapsed="1.0" exit="success"/>
  <hosts up="0" down="1" total="1"/>
</runstats>
</nmaprun>
"""


class TestNmapXMLParser(unittest.TestCase):

    def setUp(self):
        self.parser = NmapXMLParser()

    def test_parse_valid_xml(self):
        """Verifies parsing of standard valid Nmap XML with open ports and services."""
        hosts, meta = self.parser.parse_xml_string(SAMPLE_VALID_XML, profile_name="lab-basic")
        self.assertEqual(len(hosts), 1)
        self.assertEqual(meta.scanner, "nmap")
        self.assertEqual(meta.version, "7.99")
        self.assertEqual(meta.profile, "lab-basic")
        self.assertEqual(meta.exit_code, 0)

        host = hosts[0]
        self.assertEqual(host.address, "192.168.56.111")
        self.assertEqual(host.status, "up")
        self.assertIn("metasploitable2.local", host.hostnames)
        self.assertEqual(host.closed_ports_count, 97)

        # Ports
        self.assertEqual(len(host.ports), 3)
        port_ids = [p.portid for p in host.ports]
        self.assertEqual(port_ids, [21, 22, 80])

        # SSH service check
        ssh_port = next(p for p in host.ports if p.portid == 22)
        self.assertEqual(ssh_port.state, "open")
        self.assertIsNotNone(ssh_port.service)
        self.assertEqual(ssh_port.service.name, "ssh")
        self.assertEqual(ssh_port.service.product, "OpenSSH")
        self.assertEqual(ssh_port.service.version, "4.7p1 Debian 8ubuntu1")
        self.assertIn("cpe:/a:openbsd:openssh:4.7p1", ssh_port.service.cpe)

    def test_parse_filtered_ports(self):
        """Verifies parsing of filtered ports and extraports counts."""
        hosts, meta = self.parser.parse_xml_string(SAMPLE_FILTERED_XML)
        self.assertEqual(len(hosts), 1)
        host = hosts[0]
        self.assertEqual(host.filtered_ports_count, 99)
        self.assertEqual(len(host.ports), 1)
        p = host.ports[0]
        self.assertEqual(p.portid, 445)
        self.assertEqual(p.state, "filtered")
        self.assertEqual(p.service.name, "microsoft-ds")
        # Ensure missing version is None (not invented)
        self.assertIsNone(p.service.version)

    def test_parse_host_down(self):
        """Verifies handling of a host that is reported down."""
        hosts, meta = self.parser.parse_xml_string(SAMPLE_HOST_DOWN_XML)
        self.assertEqual(len(hosts), 1)
        host = hosts[0]
        self.assertEqual(host.status, "down")
        self.assertEqual(len(host.ports), 0)

    def test_malformed_xml_handling(self):
        """Verifies that malformed XML raises NmapXMLParseError."""
        bad_xml = "<nmaprun><host><address addr='1.2.3.4'></host>"  # unclosed tags
        with self.assertRaises(NmapXMLParseError):
            self.parser.parse_xml_string(bad_xml)

    def test_empty_xml_handling(self):
        """Verifies that empty string raises NmapXMLParseError."""
        with self.assertRaises(NmapXMLParseError):
            self.parser.parse_xml_string("")
        with self.assertRaises(NmapXMLParseError):
            self.parser.parse_xml_string("   ")

    def test_wrong_root_tag_handling(self):
        """Verifies that non-nmap XML raises NmapXMLParseError."""
        wrong_xml = "<html xmlns='http://www.w3.org/1999/xhtml'><body>Not Nmap</body></html>"
        with self.assertRaises(NmapXMLParseError):
            self.parser.parse_xml_string(wrong_xml)


if __name__ == "__main__":
    unittest.main()

