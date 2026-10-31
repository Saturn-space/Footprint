"""Unit tests for safe Nmap XML parsing, element extraction, and error handling."""

import pytest
from app.services.active.xml_parser import (
    parse_nmap_xml,
    NmapXmlParseError,
    ParsedNmapResult,
)

SAMPLE_VALID_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -T3 --top-ports 100 -Pn 192.168.1.10" start="1700000000" startstr="Wed Oct 28 00:00:00 2026" version="7.94" xmloutputversion="1.05">
  <scaninfo type="connect" protocol="tcp" numservices="100" services="1-100"/>
  <verbose level="0"/>
  <debugging level="0"/>
  <host starttime="1700000001" endtime="1700000005">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="lab-host.internal" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu" method="probed" conf="10">
          <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http" product="nginx" version="1.18.0" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="filtered" reason="no-response" reason_ttl="0"/>
        <service name="https" method="table" conf="3"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed" reason="conn-refused" reason_ttl="0"/>
        <service name="http-proxy" method="table" conf="3"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.15" accuracy="95"/>
    </os>
  </host>
  <runstats>
    <finished time="1700000005" timestr="Wed Oct 28 00:00:05 2026" elapsed="5.00" summary="Nmap done at Wed Oct 28 00:00:05 2026; 1 IP address (1 host up) scanned in 5.00 seconds" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
"""

SAMPLE_IPV6_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94" args="nmap -sT -6 fe80::1">
  <host>
    <status state="up"/>
    <address addr="fe80::1" addrtype="ipv6"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

SAMPLE_NO_SERVICES_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94" args="nmap -sT 10.0.0.1">
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

SAMPLE_EMPTY_SCAN_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94" args="nmap -sn 10.0.0.1">
  <runstats>
    <hosts up="0" down="1" total="1"/>
  </runstats>
</nmaprun>
"""


def test_parse_valid_nmap_xml():
    """Verify parsing of valid Nmap XML with open, closed, filtered ports and service detection."""
    result: ParsedNmapResult = parse_nmap_xml(SAMPLE_VALID_XML)
    assert result.scanner == "nmap"
    assert result.version == "7.94"
    assert result.total_hosts == 1
    assert result.hosts_up == 1
    assert len(result.hosts) == 1

    host = result.hosts[0]
    assert host.address == "192.168.1.10"
    assert host.address_type == "ipv4"
    assert host.status == "up"
    assert host.hostnames == ["lab-host.internal"]
    assert host.os_match == "Linux 5.15"
    assert host.os_accuracy == 95

    # Check ports
    assert len(host.ports) == 4
    p22 = host.ports[0]
    assert p22.port == 22
    assert p22.protocol == "tcp"
    assert p22.state == "open"
    assert p22.service.name == "ssh"
    assert p22.service.product == "OpenSSH"
    assert p22.service.version == "8.9p1"
    assert p22.service.cpe == "cpe:/a:openbsd:openssh:8.9p1"

    p80 = host.ports[1]
    assert p80.port == 80
    assert p80.state == "open"
    assert p80.service.product == "nginx"

    p443 = host.ports[2]
    assert p443.port == 443
    assert p443.state == "filtered"

    p8080 = host.ports[3]
    assert p8080.port == 8080
    assert p8080.state == "closed"


def test_parse_ipv6_host():
    """Verify IPv6 address extraction and parsing."""
    result = parse_nmap_xml(SAMPLE_IPV6_XML)
    assert result.total_hosts == 1
    host = result.hosts[0]
    assert host.address == "fe80::1"
    assert host.address_type == "ipv6"
    assert host.status == "up"
    assert len(host.ports) == 1
    assert host.ports[0].port == 80


def test_parse_missing_service_metadata():
    """Verify parser handles ports without <service> subelement gracefully."""
    result = parse_nmap_xml(SAMPLE_NO_SERVICES_XML)
    assert result.total_hosts == 1
    host = result.hosts[0]
    assert len(host.ports) == 1
    port = host.ports[0]
    assert port.port == 3389
    assert port.state == "open"
    assert port.service.name == "unknown"
    assert port.service.product is None


def test_parse_empty_scan():
    """Verify parser handles empty scans with 0 hosts up."""
    result = parse_nmap_xml(SAMPLE_EMPTY_SCAN_XML)
    assert result.total_hosts == 0
    assert result.hosts == []


def test_parse_malformed_xml():
    """Verify malformed XML triggers NmapXmlParseError."""
    with pytest.raises(NmapXmlParseError, match="Malformed or truncated"):
        parse_nmap_xml("<nmaprun><host><status state='up'")


def test_parse_truncated_xml():
    """Verify truncated XML triggers NmapXmlParseError."""
    with pytest.raises(NmapXmlParseError, match="Malformed or truncated"):
        parse_nmap_xml("<nmaprun><host></nmaprun>")


def test_parse_wrong_root_element():
    """Verify XML with incorrect root element is rejected."""
    with pytest.raises(NmapXmlParseError, match="Root element is <scanreport>"):
        parse_nmap_xml("<scanreport></scanreport>")


def test_parse_xxe_rejection():
    """Verify XXE entity injection is detected and blocked."""
    xxe_xml = """<?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <nmaprun>&xxe;</nmaprun>
    """
    with pytest.raises(NmapXmlParseError, match="Security violation: External XML Entities"):
        parse_nmap_xml(xxe_xml)


def test_parse_oversized_xml():
    """Verify oversized XML (>10MB) is rejected."""
    huge_xml = "<nmaprun>" + (" " * (11 * 1024 * 1024)) + "</nmaprun>"
    with pytest.raises(NmapXmlParseError, match="exceeds maximum size limit"):
        parse_nmap_xml(huge_xml)


def test_parse_empty_string():
    """Verify empty string is rejected cleanly."""
    with pytest.raises(NmapXmlParseError, match="empty"):
        parse_nmap_xml("")
