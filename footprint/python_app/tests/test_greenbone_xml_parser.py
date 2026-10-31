"""Unit tests for safe Greenbone XML vulnerability report parsing and normalization."""

from pathlib import Path
import pytest

from app.services.vuln.normalizer import (
    generate_finding_deduplication_key,
    normalize_severity,
    parse_port_protocol,
)
from app.services.vuln.xml_parser import (
    MalformedReportError,
    ParsedReport,
    ReportNotCompletedError,
    ReportSecurityError,
    ReportSizeExceededError,
    parse_greenbone_xml_report,
)


def test_parse_real_greenbone_sample_report():
    """Verify parsing of real Greenbone XML report fixture."""
    fixture_path = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "scans"
        / "greenbone"
        / "inv-test-vuln-01"
        / "gvm-imp-31efbea759.xml"
    )
    assert fixture_path.exists(), "Sample XML fixture must exist"

    xml_content = fixture_path.read_text(encoding="utf-8")
    parsed = parse_greenbone_xml_report(xml_content)

    assert parsed.report_id == "rep-gvm-1234"
    assert parsed.scan_run_status == "Done"
    assert parsed.is_completed is True
    assert parsed.is_empty is False
    assert len(parsed.findings) == 4

    # Finding 1: Log4j
    f1 = parsed.findings[0]
    assert "Log4j" in f1.name
    assert f1.host == "192.168.1.50"
    assert f1.port_str == "80/tcp"
    assert f1.threat == "High"
    assert f1.severity_score == 9.8
    assert f1.qod == 80
    assert "CVE-2021-44228" in f1.cve_list
    assert f1.solution is not None and "2.16.0" in f1.solution
    assert f1.insight is not None and "JNDI lookups" in f1.insight

    # Finding 2: Deprecated TLS
    f2 = parsed.findings[1]
    assert "TLSv1.0" in f2.name
    assert f2.port_str == "443/tcp"
    assert f2.severity_score == 4.3
    assert "CVE-2011-3389" in f2.cve_list

    # Finding 3: OS End of Life
    f3 = parsed.findings[2]
    assert "OS End of Life" in f3.name
    assert f3.port_str == "general/tcp"
    assert f3.severity_score == 2.6
    assert len(f3.cve_list) == 0  # No CVE invented!

    # Finding 4: Log finding
    f4 = parsed.findings[3]
    assert f4.threat == "Log"
    assert f4.severity_score == 0.0


def test_parse_empty_completed_report():
    """Verify that a valid scan report with zero results is parsed as empty without errors."""
    empty_xml = """<?xml version="1.0" encoding="UTF-8"?>
<report id="rep-empty-01">
    <scan_run_status>Done</scan_run_status>
    <results>
    </results>
</report>
"""
    parsed = parse_greenbone_xml_report(empty_xml)
    assert parsed.report_id == "rep-empty-01"
    assert parsed.is_completed is True
    assert parsed.is_empty is True
    assert len(parsed.findings) == 0


def test_parse_running_report_rejected():
    """Verify that reports with in-progress scan_run_status raise ReportNotCompletedError."""
    running_xml = """<?xml version="1.0" encoding="UTF-8"?>
<report id="rep-running-01">
    <scan_run_status>Running</scan_run_status>
    <results></results>
</report>
"""
    with pytest.raises(ReportNotCompletedError, match="still in progress"):
        parse_greenbone_xml_report(running_xml)


def test_parse_malformed_xml():
    """Verify that syntax errors raise MalformedReportError."""
    bad_xml = "<report><scan_run_status>Done</scan_run_status><results><result>"
    with pytest.raises(MalformedReportError):
        parse_greenbone_xml_report(bad_xml)


def test_xxe_and_entity_defense():
    """Verify that DOCTYPE and ENTITY declarations are rejected for security."""
    xxe_xml = """<?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <report id="xxe-rep">
        <scan_run_status>Done</scan_run_status>
        <results></results>
    </report>
    """
    with pytest.raises(ReportSecurityError, match="DOCTYPE or ENTITY"):
        parse_greenbone_xml_report(xxe_xml)


def test_oversized_report_rejected():
    """Verify that XML exceeding size limits raises ReportSizeExceededError."""
    # 26 MB dummy payload
    oversized = b"<report>" + b" " * (26 * 1024 * 1024) + b"</report>"
    with pytest.raises(ReportSizeExceededError, match="exceeds maximum permitted size"):
        parse_greenbone_xml_report(oversized)


def test_severity_normalization_rules():
    """Verify strict severity normalization and refusal to convert unknown to low."""
    # CVSS numeric thresholds
    assert normalize_severity(9.8, "High") == "critical"
    assert normalize_severity(7.5, "High") == "high"
    assert normalize_severity(5.0, "Medium") == "medium"
    assert normalize_severity(2.5, "Low") == "low"
    assert normalize_severity(0.0, "Log") == "info"

    # Threat string fallbacks when CVSS is None
    assert normalize_severity(None, "Critical") == "critical"
    assert normalize_severity(None, "High") == "high"
    assert normalize_severity(None, "Medium") == "medium"
    assert normalize_severity(None, "Low") == "low"
    assert normalize_severity(None, "Log") == "info"
    assert normalize_severity(None, "Informational") == "info"

    # Unknown must NOT silently become low
    assert normalize_severity(None, None) == "unknown"
    assert normalize_severity(None, "Uncertain") == "unknown"


def test_port_protocol_parsing():
    """Verify robust port and protocol parsing across diverse GVM outputs."""
    assert parse_port_protocol("80/tcp") == (80, "tcp")
    assert parse_port_protocol("443/tcp") == (443, "tcp")
    assert parse_port_protocol("53/udp") == (53, "udp")
    assert parse_port_protocol("general/tcp") == (None, "tcp")
    assert parse_port_protocol("general/general") == (None, None)
    assert parse_port_protocol("8080") == (8080, "tcp")
    assert parse_port_protocol(None) == (None, None)
    assert parse_port_protocol("999999/tcp") == (None, "tcp")  # Invalid port number clamped


def test_deduplication_key_generation():
    """Verify deterministic deduplication key generation."""
    key1 = generate_finding_deduplication_key(
        host="192.168.1.50",
        port=80,
        protocol="tcp",
        name="Apache Log4j RCE",
        nvt_oid="1.3.6.1.4.1.25623.1.0.147205",
        primary_cve="CVE-2021-44228",
    )
    key2 = generate_finding_deduplication_key(
        host="192.168.1.50",
        port=80,
        protocol="tcp",
        name="Apache Log4j RCE",
        nvt_oid="1.3.6.1.4.1.25623.1.0.147205",
        primary_cve="CVE-2021-44228",
    )
    assert key1 == key2
    assert len(key1) == 32

    # Different port must yield different key
    key3 = generate_finding_deduplication_key(
        host="192.168.1.50",
        port=443,
        protocol="tcp",
        name="Apache Log4j RCE",
        nvt_oid="1.3.6.1.4.1.25623.1.0.147205",
        primary_cve="CVE-2021-44228",
    )
    assert key1 != key3
