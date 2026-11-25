"""
OSINT-RECON Greenbone Report XML Parser Module
Extracts structured vulnerability findings, CVE identifiers, CVSS metrics, QoD,
remediation solutions, and technical insights from canonical Greenbone GMP XML reports.
"""

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from src.schema import VulnerabilityFinding, GreenboneScanMetadata


class GreenboneXMLParseError(Exception):
    """Raised when Greenbone report XML is malformed or unparseable."""
    pass


def parse_port_protocol(raw_port: str) -> Tuple[int, str]:
    """
    Parses Greenbone port string (e.g. '21/tcp', 'general/tcp', '80/udp')
    into (integer_port, protocol). Host-level or general returns (0, protocol).
    """
    if not raw_port:
        return 0, "general"
    cleaned = raw_port.strip().lower()
    if "/" in cleaned:
        p_part, proto_part = cleaned.split("/", 1)
        proto = proto_part.strip()
        if p_part.isdigit():
            return int(p_part), proto
        return 0, proto
    if cleaned.isdigit():
        return int(cleaned), "tcp"
    return 0, "general"


def parse_nvt_tags(tag_str: Optional[str]) -> Dict[str, str]:
    """
    Parses Greenbone pipe-delimited NVT tags (e.g. 'summary=...|insight=...|solution_type=...')
    into a structured key-value dictionary.
    """
    if not tag_str:
        return {}
    tags: Dict[str, str] = {}
    items = tag_str.split("|")
    for item in items:
        if "=" in item:
            k, v = item.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


class GreenboneReportParser:
    """
    Parses Greenbone / OpenVAS XML reports into typed VulnerabilityFinding objects.
    """

    def parse_report_xml(
        self,
        xml_content: str,
        default_host: Optional[str] = None
    ) -> Tuple[List[VulnerabilityFinding], Optional[GreenboneScanMetadata]]:
        """
        Parses GMP report XML string.
        Returns: (findings_list, scan_metadata)
        """
        if not xml_content or not xml_content.strip():
            raise GreenboneXMLParseError("Greenbone report XML content is empty.")

        try:
            root = ET.fromstring(xml_content.strip())
        except ET.ParseError as pe:
            raise GreenboneXMLParseError(f"Malformed Greenbone report XML: {str(pe)}") from pe

        # Locate root report element
        report_elem = root.find(".//report") if root.tag != "report" else root
        if report_elem is None:
            # Check if root contains <results> directly
            results_elem = root.find(".//results")
            if results_elem is None:
                raise GreenboneXMLParseError("No <report> or <results> root tag found in Greenbone XML.")
            report_elem = root

        # 1. Parse Scan Metadata
        metadata = self._extract_metadata(report_elem)

        # 2. Parse Results / Vulnerabilities
        findings: List[VulnerabilityFinding] = []
        results = report_elem.findall(".//results/result")
        for res in results:
            finding = self._parse_single_result(res, default_host)
            if finding:
                findings.append(finding)

        return findings, metadata

    def _extract_metadata(self, report_elem: ET.Element) -> GreenboneScanMetadata:
        """Extracts task, report, and scanner metadata from report XML."""
        report_id = report_elem.get("id") or ""
        task_elem = report_elem.find(".//task")
        task_id = task_elem.get("id") if task_elem is not None else None

        # Start and end timestamps
        scan_start = report_elem.findtext(".//scan_start") or report_elem.findtext(".//timestamp")
        scan_end = report_elem.findtext(".//scan_end")
        now_ts = datetime.now(timezone.utc).isoformat()

        start_ts = scan_start if scan_start else now_ts
        end_ts = scan_end if scan_end else now_ts

        # Config details
        config_elem = report_elem.find(".//config")
        config_name = config_elem.findtext("name") if config_elem is not None else "Full and fast"
        config_id = config_elem.get("id") if config_elem is not None else None

        return GreenboneScanMetadata(
            task_id=task_id,
            report_id=report_id,
            config_name=config_name or "Full and fast",
            config_id=config_id,
            scanner_name="OpenVAS",
            start_time_utc=start_ts,
            end_time_utc=end_ts,
            status="Done"
        )

    def _parse_single_result(
        self,
        res_elem: ET.Element,
        default_host: Optional[str] = None
    ) -> Optional[VulnerabilityFinding]:
        """Parses a single <result> XML element into a VulnerabilityFinding."""
        result_id = res_elem.get("id") or f"RES-{datetime.now(timezone.utc).strftime('%H%M%S%f')}"
        name = res_elem.findtext("name") or "Unnamed Vulnerability"

        # Host
        host = res_elem.findtext("host") or default_host or "127.0.0.1"

        # Port & Protocol
        raw_port = res_elem.findtext("port") or "0/general"
        port_num, protocol = parse_port_protocol(raw_port)

        # Threat and Severity
        threat = (res_elem.findtext("threat") or "Log").capitalize()
        if threat not in ("Critical", "High", "Medium", "Low", "Log", "Unknown"):
            threat = "Unknown"

        severity_str = res_elem.findtext("severity") or "0.0"
        try:
            severity = float(severity_str)
        except ValueError:
            severity = 0.0

        # NVT Details
        nvt_elem = res_elem.find(".//nvt")
        nvt_oid = nvt_elem.get("oid") if nvt_elem is not None else "0"
        tag_dict = {}
        cve_ids: List[str] = []
        references: List[str] = []
        cvss_base: Optional[float] = None
        cvss_ver: Optional[str] = None
        solution = None
        solution_type = None

        if nvt_elem is not None:
            # CVE extraction
            raw_cves = nvt_elem.findtext("cve")
            if raw_cves and raw_cves.strip() != "NOCVE":
                cve_matches = re.findall(r"CVE-\d{4}-\d+", raw_cves, re.IGNORECASE)
                cve_ids = [c.upper() for c in cve_matches]

            # CVSS
            cvss_raw = nvt_elem.findtext("cvss_base")
            if cvss_raw:
                try:
                    cvss_base = float(cvss_raw)
                    cvss_ver = nvt_elem.findtext("cvss_version") or "2.0"
                except ValueError:
                    pass

            # Parse tags
            raw_tags = nvt_elem.findtext("tags")
            tag_dict = parse_nvt_tags(raw_tags)

            # Solution & References
            solution = nvt_elem.findtext("solution") or tag_dict.get("solution")
            solution_type = tag_dict.get("solution_type")

            for xref in nvt_elem.findall(".//xref"):
                ref_text = xref.findtext("value") or xref.text
                if ref_text:
                    references.append(ref_text.strip())

        # Description / Summary / Insight
        desc = res_elem.findtext("description") or tag_dict.get("summary")
        summary = tag_dict.get("summary") or name
        insight = tag_dict.get("insight") or res_elem.findtext(".//detection/result")

        # QoD (Quality of Detection)
        qod_val = None
        qod_type = None
        qod_elem = res_elem.find(".//qod")
        if qod_elem is not None:
            val_text = qod_elem.findtext("value")
            if val_text and val_text.isdigit():
                qod_val = int(val_text)
            qod_type = qod_elem.findtext("type")

        # Observation timestamp
        ts = res_elem.findtext("creation_time") or datetime.now(timezone.utc).isoformat()

        return VulnerabilityFinding(
            finding_id=result_id,
            nvt_oid=nvt_oid,
            name=name,
            host=host,
            port=port_num,
            protocol=protocol,
            threat=threat,  # type: ignore
            original_threat=threat,
            severity=severity,
            cvss_version=cvss_ver,
            cvss_base=cvss_base,
            cve_ids=sorted(list(set(cve_ids))),
            qod=qod_val,
            qod_type=qod_type,
            solution=solution,
            solution_type=solution_type,
            description=desc,
            summary=summary,
            insight=insight,
            references=sorted(list(set(references))),
            timestamp_utc=ts,
            source_tool="greenbone_openvas"
        )

