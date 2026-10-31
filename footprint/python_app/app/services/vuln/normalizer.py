"""Normalization, deduplication, and severity mapping for Greenbone vulnerability findings."""

import hashlib
import logging
from typing import Optional, Tuple
from app.services.vuln.xml_parser import RawVulnFinding

logger = logging.getLogger("footprintiq.services.vuln.normalizer")


def parse_port_protocol(port_str: Optional[str]) -> Tuple[Optional[int], Optional[str]]:
    """Extracts integer port number and protocol from Greenbone port string.
    
    Examples:
        '80/tcp' -> (80, 'tcp')
        '443/tcp' -> (443, 'tcp')
        '53/udp' -> (53, 'udp')
        'general/tcp' -> (None, 'tcp')
        'general/general' -> (None, None)
        None -> (None, None)
    """
    if not port_str:
        return None, None

    cleaned = port_str.strip().lower()
    if "/" not in cleaned:
        if cleaned.isdigit():
            port_num = int(cleaned)
            return (port_num if 1 <= port_num <= 65535 else None), "tcp"
        return None, None

    parts = cleaned.split("/", 1)
    port_part, proto_part = parts[0].strip(), parts[1].strip()

    port_val: Optional[int] = None
    if port_part.isdigit():
        p = int(port_part)
        if 1 <= p <= 65535:
            port_val = p

    proto_val: Optional[str] = proto_part if proto_part != "general" else None

    return port_val, proto_val


def normalize_severity(severity_score: Optional[float], threat: Optional[str]) -> str:
    """Normalizes vulnerability severity to a standard tier.
    
    Tiers: 'critical', 'high', 'medium', 'low', 'info', or 'unknown'.
    Never silently coerces unknown severity into 'low'.
    """
    # 1. Evaluate explicit CVSS score
    if severity_score is not None:
        if severity_score >= 9.0:
            return "critical"
        if severity_score >= 7.0:
            return "high"
        if severity_score >= 4.0:
            return "medium"
        if severity_score > 0.0:
            return "low"
        if severity_score == 0.0:
            return "info"

    # 2. Evaluate scanner threat label
    if threat:
        t = threat.strip().lower()
        if t in ("critical", "crit"):
            return "critical"
        if t in ("high", "h"):
            return "high"
        if t in ("medium", "med", "m"):
            return "medium"
        if t in ("low", "l"):
            return "low"
        if t in ("log", "none", "info", "informational"):
            return "info"

    # Retain honest unknown rating
    return "unknown"


def generate_finding_deduplication_key(
    host: str,
    port: Optional[int],
    protocol: Optional[str],
    name: str,
    nvt_oid: Optional[str],
    primary_cve: Optional[str] = None,
) -> str:
    """Generates a stable composite key for deduplicating repeated findings.
    
    Composite format:
        host:port:protocol:name:nvt_oid:cve
    """
    host_clean = host.strip().lower()
    port_clean = str(port) if port is not None else "general"
    proto_clean = protocol.strip().lower() if protocol else "any"
    name_clean = name.strip().lower()
    oid_clean = nvt_oid.strip() if nvt_oid else "no-oid"
    cve_clean = primary_cve.strip().upper() if primary_cve else "no-cve"

    raw_key = f"{host_clean}:{port_clean}:{proto_clean}:{name_clean}:{oid_clean}:{cve_clean}"
    # Use deterministic SHA-256 for stable indexed storage
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:32]
