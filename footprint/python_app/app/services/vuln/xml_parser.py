"""Safe XML report parser for Greenbone Vulnerability Management (GVM) reports."""

from dataclasses import dataclass, field
import logging
import re
from typing import List, Optional
import xml.etree.ElementTree as ET

logger = logging.getLogger("footprintiq.services.vuln.xml_parser")

# 25 MB safety limit on incoming XML reports
MAX_REPORT_SIZE_BYTES = 25 * 1024 * 1024

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class VulnerabilityReportError(Exception):
    """Base exception for report retrieval or parsing failures."""
    pass


class ReportSizeExceededError(VulnerabilityReportError):
    """Raised when XML report exceeds safe size bounds."""
    pass


class MalformedReportError(VulnerabilityReportError):
    """Raised when XML content is malformed or invalid."""
    pass


class ReportNotCompletedError(VulnerabilityReportError):
    """Raised when parsing a report whose scan run status is not completed."""
    pass


class ReportSecurityError(VulnerabilityReportError):
    """Raised when dangerous XML features (such as DTD entity expansion) are detected."""
    pass


@dataclass
class RawVulnFinding:
    """Extracted raw finding from Greenbone XML result tag."""

    result_id: Optional[str]
    name: str
    host: str
    port_str: str
    threat: Optional[str]
    severity_score: Optional[float]
    qod: Optional[int]
    description: Optional[str]
    nvt_oid: Optional[str]
    cve_list: List[str] = field(default_factory=list)
    solution: Optional[str] = None
    insight: Optional[str] = None


@dataclass
class ParsedReport:
    """Parsed Greenbone report metadata and collection of raw findings."""

    report_id: str
    scan_run_status: str
    is_completed: bool
    is_empty: bool
    findings: List[RawVulnFinding]


def parse_greenbone_xml_report(xml_data: str | bytes) -> ParsedReport:
    """Parses Greenbone XML vulnerability report with security defenses and validation.
    
    Args:
        xml_data: Raw XML report string or bytes.
        
    Returns:
        ParsedReport containing validated report status and extracted findings.
        
    Raises:
        ReportSizeExceededError: If payload exceeds 25 MB.
        ReportSecurityError: If DOCTYPE or ENTITY definitions are present.
        MalformedReportError: If XML syntax is invalid.
        ReportNotCompletedError: If the report run status indicates scan is still running or failed.
    """
    if isinstance(xml_data, str):
        xml_bytes = xml_data.encode("utf-8")
    else:
        xml_bytes = xml_data

    # 1. Enforce size limit
    if len(xml_bytes) > MAX_REPORT_SIZE_BYTES:
        raise ReportSizeExceededError(
            f"Report payload of {len(xml_bytes)} bytes exceeds maximum permitted size of {MAX_REPORT_SIZE_BYTES} bytes."
        )

    # 2. Defend against XXE and Billion Laughs attack
    # Reject documents declaring DOCTYPE or external ENTITY
    header_sample = xml_bytes[:2048].lower()
    if b"<!doctype" in header_sample or b"<!entity" in header_sample:
        raise ReportSecurityError("XML reports containing DOCTYPE or ENTITY declarations are rejected for security.")

    # 3. Parse XML safely
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        raise MalformedReportError(f"Failed to parse XML report: {e}") from e

    # 4. Locate inner or root report element
    report_elem = root.find(".//report") if root.tag != "report" else root
    if report_elem is None:
        raise MalformedReportError("Invalid Greenbone XML report: missing <report> element.")

    report_id = report_elem.get("id") or root.get("id") or "unknown-report"

    # 5. Extract scan_run_status
    status_elem = report_elem.find(".//scan_run_status")
    status_text = status_elem.text.strip() if status_elem is not None and status_elem.text else "Done"

    # Distinguish running/incomplete states
    if status_text.lower() in ("running", "requested", "stop requested"):
        raise ReportNotCompletedError(
            f"Greenbone report '{report_id}' is still in progress (scan_run_status: {status_text})."
        )

    is_completed = status_text.lower() in ("done", "stopped", "finished")

    # 6. Extract result nodes
    results_container = report_elem.find(".//results")
    result_nodes = results_container.findall("result") if results_container is not None else []
    
    findings: List[RawVulnFinding] = []
    for r in result_nodes:
        res_id = r.get("id")
        name_elem = r.find("name")
        name = name_elem.text.strip() if name_elem is not None and name_elem.text else "Unnamed Vulnerability"

        host_elem = r.find("host")
        host = host_elem.text.strip() if host_elem is not None and host_elem.text else "unknown-host"

        port_elem = r.find("port")
        port_str = port_elem.text.strip() if port_elem is not None and port_elem.text else "general/tcp"

        threat_elem = r.find("threat")
        threat = threat_elem.text.strip() if threat_elem is not None and threat_elem.text else None

        severity_elem = r.find("severity")
        severity_score: Optional[float] = None
        if severity_elem is not None and severity_elem.text:
            try:
                score_val = float(severity_elem.text.strip())
                if 0.0 <= score_val <= 10.0:
                    severity_score = score_val
            except ValueError:
                severity_score = None

        qod_elem = r.find(".//qod/value")
        qod: Optional[int] = None
        if qod_elem is not None and qod_elem.text:
            try:
                qod = int(qod_elem.text.strip())
            except ValueError:
                qod = None

        desc_elem = r.find("description")
        description = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else None

        # Extract NVT details (CVE, solution, insight, oid)
        nvt_elem = r.find(".//nvt")
        nvt_oid = nvt_elem.get("oid") if nvt_elem is not None else None

        cve_list: List[str] = []
        solution: Optional[str] = None
        insight: Optional[str] = None

        if nvt_elem is not None:
            cve_elem = nvt_elem.find("cve")
            if cve_elem is not None and cve_elem.text:
                found_cves = CVE_PATTERN.findall(cve_elem.text)
                for cve in found_cves:
                    normalized_cve = cve.upper()
                    if normalized_cve not in cve_list:
                        cve_list.append(normalized_cve)

            sol_elem = nvt_elem.find("solution")
            if sol_elem is not None and sol_elem.text:
                solution = sol_elem.text.strip()

            insight_elem = nvt_elem.find("insight")
            if insight_elem is not None and insight_elem.text:
                insight = insight_elem.text.strip()

        # Also search description for CVE references if none found in NVT
        if not cve_list and description:
            found_cves = CVE_PATTERN.findall(description)
            for cve in found_cves:
                normalized_cve = cve.upper()
                if normalized_cve not in cve_list:
                    cve_list.append(normalized_cve)

        findings.append(
            RawVulnFinding(
                result_id=res_id,
                name=name,
                host=host,
                port_str=port_str,
                threat=threat,
                severity_score=severity_score,
                qod=qod,
                description=description,
                nvt_oid=nvt_oid,
                cve_list=cve_list,
                solution=solution,
                insight=insight,
            )
        )

    is_empty = (len(findings) == 0)

    logger.info(
        "Parsed Greenbone report '%s': status=%s, total_findings=%d, is_empty=%s",
        report_id,
        status_text,
        len(findings),
        is_empty,
    )

    return ParsedReport(
        report_id=report_id,
        scan_run_status=status_text,
        is_completed=is_completed,
        is_empty=is_empty,
        findings=findings,
    )
