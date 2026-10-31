"""Safe Nmap XML output parser for FootprintIQ."""

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
import logging

logger = logging.getLogger("footprintiq.nmap.parser")

MAX_NMAP_XML_BYTES = 10 * 1024 * 1024  # 10 MB


class NmapXmlParseError(Exception):
    """Raised when Nmap XML output is malformed, oversized, or fails safety checks."""
    pass


@dataclass
class ParsedService:
    name: str = "unknown"
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    cpe: Optional[str] = None
    confidence: Optional[int] = None
    method: Optional[str] = None


@dataclass
class ParsedPort:
    port: int
    protocol: str  # "tcp" or "udp"
    state: str  # "open", "closed", "filtered"
    reason: Optional[str] = None
    service: ParsedService = field(default_factory=ParsedService)


@dataclass
class ParsedHost:
    address: str
    address_type: str = "ipv4"  # "ipv4", "ipv6", or "mac"
    status: str = "up"  # "up" or "down"
    hostnames: List[str] = field(default_factory=list)
    ports: List[ParsedPort] = field(default_factory=list)
    os_match: Optional[str] = None
    os_accuracy: Optional[int] = None


@dataclass
class ParsedNmapResult:
    scanner: str = "nmap"
    version: str = "unknown"
    args: str = ""
    start_str: Optional[str] = None
    hosts: List[ParsedHost] = field(default_factory=list)
    total_hosts: int = 0
    hosts_up: int = 0
    hosts_down: int = 0


def parse_nmap_xml(xml_content: str) -> ParsedNmapResult:
    """Parses raw Nmap XML string into structured finding models.

    Enforces XXE defense, bounds checking, and graceful handling of missing elements.
    """
    if not xml_content or not xml_content.strip():
        raise NmapXmlParseError("Nmap XML output is empty")

    xml_bytes = xml_content.encode("utf-8")
    if len(xml_bytes) > MAX_NMAP_XML_BYTES:
        raise NmapXmlParseError(
            f"Nmap XML output exceeds maximum size limit ({len(xml_bytes)} > {MAX_NMAP_XML_BYTES} bytes)"
        )

    # XXE & Entity Expansion Defense
    if re.search(r"<!ENTITY", xml_content, re.IGNORECASE) or re.search(
        r"SYSTEM\s+[\"'][^\"']+[\"']", xml_content, re.IGNORECASE
    ) or re.search(r"PUBLIC\s+[\"'][^\"']+[\"']", xml_content, re.IGNORECASE):
        raise NmapXmlParseError("Security violation: External XML Entities (XXE) are strictly prohibited")

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as pe:
        raise NmapXmlParseError(f"Malformed or truncated Nmap XML: {pe}") from pe

    if root.tag != "nmaprun":
        raise NmapXmlParseError(f"Invalid Nmap XML: Root element is <{root.tag}> instead of <nmaprun>")

    scanner = root.get("scanner", "nmap")
    version = root.get("version", "unknown")
    args = root.get("args", "")
    start_str = root.get("startstr")

    hosts: List[ParsedHost] = []
    hosts_up = 0
    hosts_down = 0

    for host_elem in root.findall("host"):
        # Status
        status_elem = host_elem.find("status")
        status_val = status_elem.get("state", "unknown") if status_elem is not None else "unknown"
        if status_val == "up":
            hosts_up += 1
        elif status_val == "down":
            hosts_down += 1

        # Address resolution: ipv4, ipv6, mac
        ip_addr = None
        addr_type = "ipv4"
        for addr_elem in host_elem.findall("address"):
            atype = addr_elem.get("addrtype", "ipv4")
            if atype in ("ipv4", "ipv6"):
                ip_addr = addr_elem.get("addr")
                addr_type = atype
                break

        if not ip_addr:
            # Fallback if no ipv4/ipv6 found
            first_addr = host_elem.find("address")
            if first_addr is not None:
                ip_addr = first_addr.get("addr", "unknown")
                addr_type = first_addr.get("addrtype", "ipv4")
            else:
                ip_addr = "unknown"

        # Hostnames
        hostnames = []
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn_elem in hostnames_elem.findall("hostname"):
                name = hn_elem.get("name")
                if name:
                    hostnames.append(name.strip())

        # Ports
        ports: List[ParsedPort] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                try:
                    port_id = int(port_elem.get("portid", "0"))
                except ValueError:
                    continue

                proto = port_elem.get("protocol", "tcp").lower()

                state_elem = port_elem.find("state")
                state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
                reason = state_elem.get("reason") if state_elem is not None else None

                # Service details
                service_info = ParsedService()
                svc_elem = port_elem.find("service")
                if svc_elem is not None:
                    service_info.name = svc_elem.get("name", "unknown")
                    service_info.product = svc_elem.get("product")
                    service_info.version = svc_elem.get("version")
                    service_info.extrainfo = svc_elem.get("extrainfo")
                    service_info.method = svc_elem.get("method")
                    conf_str = svc_elem.get("conf")
                    if conf_str and conf_str.isdigit():
                        service_info.confidence = int(conf_str)

                    cpe_elem = svc_elem.find("cpe")
                    if cpe_elem is not None and cpe_elem.text:
                        service_info.cpe = cpe_elem.text.strip()

                ports.append(
                    ParsedPort(
                        port=port_id,
                        protocol=proto,
                        state=state,
                        reason=reason,
                        service=service_info,
                    )
                )

        # OS detection
        os_match_name = None
        os_match_accuracy = None
        os_elem = host_elem.find("os")
        if os_elem is not None:
            match_elem = os_elem.find("osmatch")
            if match_elem is not None:
                os_match_name = match_elem.get("name")
                acc_str = match_elem.get("accuracy")
                if acc_str and acc_str.isdigit():
                    os_match_accuracy = int(acc_str)

        hosts.append(
            ParsedHost(
                address=ip_addr,
                address_type=addr_type,
                status=status_val,
                hostnames=hostnames,
                ports=ports,
                os_match=os_match_name,
                os_accuracy=os_match_accuracy,
            )
        )

    return ParsedNmapResult(
        scanner=scanner,
        version=version,
        args=args,
        start_str=start_str,
        hosts=hosts,
        total_hosts=len(hosts),
        hosts_up=hosts_up,
        hosts_down=hosts_down,
    )
