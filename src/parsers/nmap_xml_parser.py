"""
OSINT-RECON Nmap XML Parser Module
Extracts structured metadata, host status, open/closed/filtered ports,
service banners, products, versions, and CPE identifiers from canonical Nmap XML.
"""

import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any

from src.schema import NmapHost, NmapPort, NmapService, NmapScanMetadata


class NmapXMLParseError(ValueError):
    """Raised when Nmap XML content is empty, incomplete, or malformed."""
    pass


class NmapXMLParser:
    """
    Parses Nmap XML output (-oX) into standardized Pydantic models.
    Preserves exact scanner findings without fabricating missing data or labeling ports as vulnerabilities.
    """

    def __init__(self):
        pass

    @staticmethod
    def _parse_timestamp(epoch_str: Optional[str]) -> str:
        """Converts unix epoch string to ISO 8601 UTC string."""
        if not epoch_str:
            return datetime.now(timezone.utc).isoformat()
        try:
            dt = datetime.fromtimestamp(int(epoch_str), tz=timezone.utc)
            return dt.isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()

    def parse_xml_string(
        self, xml_content: str, profile_name: str = "lab-basic"
    ) -> Tuple[List[NmapHost], NmapScanMetadata]:
        """
        Parses XML string content and returns (hosts_list, scan_metadata).
        """
        if not xml_content or not xml_content.strip():
            raise NmapXMLParseError("Nmap XML output is empty.")

        try:
            root = ET.fromstring(xml_content.strip())
        except ET.ParseError as pe:
            raise NmapXMLParseError(f"Malformed Nmap XML output: {pe}")

        if root.tag != "nmaprun":
            raise NmapXMLParseError(f"Expected root tag <nmaprun>, got <{root.tag}>")

        # 1. Parse Scan Metadata
        scanner = root.attrib.get("scanner", "nmap")
        version = root.attrib.get("version", "unknown")
        args = root.attrib.get("args", "")
        start_epoch = root.attrib.get("start")
        xml_version = root.attrib.get("xmloutputversion")

        start_time_utc = self._parse_timestamp(start_epoch)

        # Finished tag
        finished_elem = root.find("runstats/finished")
        end_time_utc = start_time_utc
        elapsed_seconds = None
        exit_str = "success"

        if finished_elem is not None:
            end_epoch = finished_elem.attrib.get("time")
            end_time_utc = self._parse_timestamp(end_epoch)
            try:
                elapsed_seconds = float(finished_elem.attrib.get("elapsed", 0.0))
            except (ValueError, TypeError):
                elapsed_seconds = None
            exit_str = finished_elem.attrib.get("exit", "success")

        metadata = NmapScanMetadata(
            scanner=scanner,
            version=version,
            profile=profile_name,
            command_args=args,
            start_time_utc=start_time_utc,
            end_time_utc=end_time_utc,
            elapsed_seconds=elapsed_seconds,
            xml_version=xml_version,
            exit_code=0 if exit_str == "success" else 1
        )

        # 2. Parse Hosts
        hosts: List[NmapHost] = []
        host_elements = root.findall("host")

        for host_elem in host_elements:
            # Address
            addr_elem = host_elem.find("address")
            if addr_elem is None:
                continue
            address = addr_elem.attrib.get("addr", "")
            addrtype = addr_elem.attrib.get("addrtype", "ipv4")

            # Status
            status_elem = host_elem.find("status")
            status = "up"
            status_reason = None
            if status_elem is not None:
                status = status_elem.attrib.get("state", "up")
                status_reason = status_elem.attrib.get("reason")

            # Hostnames
            hostnames: List[str] = []
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                for hn in hostnames_elem.findall("hostname"):
                    hname = hn.attrib.get("name")
                    if hname and hname not in hostnames:
                        hostnames.append(hname)

            # Extraports (closed/filtered counts)
            closed_count = 0
            filtered_count = 0
            for ep in host_elem.findall("ports/extraports"):
                state = ep.attrib.get("state", "")
                try:
                    count = int(ep.attrib.get("count", 0))
                except ValueError:
                    count = 0
                if state == "closed":
                    closed_count += count
                elif state == "filtered":
                    filtered_count += count

            # Ports
            ports: List[NmapPort] = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for p_elem in ports_elem.findall("port"):
                    try:
                        portid = int(p_elem.attrib.get("portid", 0))
                    except ValueError:
                        continue
                    protocol = p_elem.attrib.get("protocol", "tcp")

                    # Port State
                    state_elem = p_elem.find("state")
                    state = "unknown"
                    reason = None
                    reason_ttl = None
                    if state_elem is not None:
                        state = state_elem.attrib.get("state", "unknown")
                        reason = state_elem.attrib.get("reason")
                        try:
                            reason_ttl = int(state_elem.attrib.get("reason_ttl", 0))
                        except (ValueError, TypeError):
                            reason_ttl = None

                    # Service
                    service: Optional[NmapService] = None
                    service_elem = p_elem.find("service")
                    if service_elem is not None:
                        s_name = service_elem.attrib.get("name", "unknown")
                        product = service_elem.attrib.get("product")
                        s_version = service_elem.attrib.get("version")
                        extrainfo = service_elem.attrib.get("extrainfo")
                        ostype = service_elem.attrib.get("ostype")
                        method = service_elem.attrib.get("method")
                        servicefp = service_elem.attrib.get("servicefp")
                        conf = None
                        try:
                            conf = int(service_elem.attrib.get("conf", 0))
                        except (ValueError, TypeError):
                            conf = None

                        # CPEs
                        cpes: List[str] = []
                        for cpe_elem in service_elem.findall("cpe"):
                            if cpe_elem.text:
                                cpes.append(cpe_elem.text.strip())

                        service = NmapService(
                            name=s_name,
                            product=product,
                            version=s_version,
                            extrainfo=extrainfo,
                            ostype=ostype,
                            method=method,
                            conf=conf,
                            cpe=cpes,
                            servicefp=servicefp
                        )

                    ports.append(NmapPort(
                        portid=portid,
                        protocol=protocol,
                        state=state,
                        reason=reason,
                        reason_ttl=reason_ttl,
                        service=service
                    ))

            hosts.append(NmapHost(
                address=address,
                addrtype=addrtype,
                status=status,
                status_reason=status_reason,
                hostnames=hostnames,
                ports=ports,
                closed_ports_count=closed_count,
                filtered_ports_count=filtered_count
            ))

        return hosts, metadata

    def parse_xml_file(
        self, xml_path: str, profile_name: str = "lab-basic"
    ) -> Tuple[List[NmapHost], NmapScanMetadata]:
        """
        Reads XML file from disk and parses it.
        """
        if not os.path.exists(xml_path):
            raise FileNotFoundError(f"Nmap XML file not found at: {xml_path}")

        try:
            with open(xml_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except IOError as e:
            raise NmapXMLParseError(f"Failed to read XML file at {xml_path}: {e}")

        return self.parse_xml_string(content, profile_name=profile_name)

