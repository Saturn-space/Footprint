"""
OSINT-RECON Normalizer Module
Converts raw collector records into atomic, validated NormalizedFinding objects.
Standardizes domain names, IP addresses, email formats, and timestamps.
"""

import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from src.schema import ReconRecord, NormalizedFinding


def clean_domain(domain_str: str) -> str:
    """Normalizes domain strings to lowercase, stripped FQDN format."""
    cleaned = domain_str.strip().lower().rstrip(".")
    cleaned = re.sub(r"^(?:https?://|2f|252f|//)", "", cleaned)
    return cleaned.split(":")[0].split("/")[0]


class FindingNormalizer:
    """
    Transforms ReconRecord instances from WHOIS, DNS, and theHarvester
    into structured NormalizedFinding entities.
    """

    def __init__(self):
        pass

    def normalize_record(self, record: ReconRecord) -> List[NormalizedFinding]:
        """Extracts and normalizes all atomic findings from a ReconRecord."""
        findings: List[NormalizedFinding] = []
        target = record.target_info.target
        scan_id = record.scan_id or "SCAN-UNKNOWN"
        tool_name = record.tool_info.name
        evidence = record.evidence_source
        timestamp = record.timestamp_utc or datetime.now(timezone.utc).isoformat()

        # 1. Base Target Domain Finding
        findings.append(NormalizedFinding(
            target=target,
            scan_id=scan_id,
            collector=record.recon_category,
            finding_type="domain",
            finding_value=clean_domain(target),
            source_tools=[tool_name],
            source_details={"category": record.recon_category, "scope": record.target_info.scope},
            timestamp_utc=timestamp,
            status="VALID" if record.scan_status != "FAILED" else "PARTIAL",
            evidence_reference=evidence,
            verification_state="unverified"
        ))

        # 2. WHOIS Findings (Registrar, Nameservers, Emails)
        if record.whois_data:
            wdata = record.whois_data
            if wdata.registrar:
                findings.append(NormalizedFinding(
                    target=target,
                    scan_id=scan_id,
                    collector=record.recon_category,
                    finding_type="registrar",
                    finding_value=wdata.registrar.strip(),
                    source_tools=[tool_name],
                    source_details={"creation_date": wdata.creation_date, "expiration_date": wdata.expiration_date},
                    timestamp_utc=timestamp,
                    status="VALID",
                    evidence_reference=evidence,
                    verification_state="unverified"
                ))

            for ns in wdata.name_servers:
                clean_ns = clean_domain(ns)
                if clean_ns:
                    findings.append(NormalizedFinding(
                        target=target,
                        scan_id=scan_id,
                        collector=record.recon_category,
                        finding_type="nameserver",
                        finding_value=clean_ns,
                        source_tools=[tool_name],
                        source_details={"source_field": "whois_nameservers"},
                        timestamp_utc=timestamp,
                        status="VALID",
                        evidence_reference=evidence,
                        verification_state="unverified"
                    ))

            for w_em in wdata.emails:
                clean_wem = w_em.strip().lower()
                if clean_wem:
                    findings.append(NormalizedFinding(
                        target=target,
                        scan_id=scan_id,
                        collector=record.recon_category,
                        finding_type="email",
                        finding_value=clean_wem,
                        source_tools=[tool_name],
                        source_details={"source_field": "whois_emails"},
                        timestamp_utc=timestamp,
                        status="VALID",
                        evidence_reference=evidence,
                        verification_state="unverified"
                    ))

        # 3. DNS Record Findings
        for drec in record.dns_records:
            finding_type = "ip_address" if drec.record_type in ("A", "AAAA") else "dns_record"
            findings.append(NormalizedFinding(
                target=target,
                scan_id=scan_id,
                collector=record.recon_category,
                finding_type=finding_type,
                finding_value=drec.value.strip(),
                source_tools=[tool_name],
                source_details={
                    "record_type": drec.record_type,
                    "ttl": drec.ttl,
                    "priority": drec.priority
                },
                timestamp_utc=timestamp,
                status="VALID",
                evidence_reference=evidence,
                verification_state="unverified"
            ))

        # 4. Discovered Domains / Subdomains
        for ddom in record.discovered_domains:
            clean_d = clean_domain(ddom)
            if clean_d and clean_d != clean_domain(target):
                findings.append(NormalizedFinding(
                    target=target,
                    scan_id=scan_id,
                    collector=record.recon_category,
                    finding_type="subdomain",
                    finding_value=clean_d,
                    source_tools=[tool_name],
                    source_details={"collector": record.recon_category},
                    timestamp_utc=timestamp,
                    status="VALID",
                    evidence_reference=evidence,
                    verification_state="unverified"
                ))

        # 5. Email Address Findings (avoid intra-record duplication)
        existing_emails = {f.finding_value.lower() for f in findings if f.finding_type == "email"}
        for em in record.email_addresses:
            clean_em = em.strip().lower()
            if clean_em and clean_em not in existing_emails:
                existing_emails.add(clean_em)
                findings.append(NormalizedFinding(
                    target=target,
                    scan_id=scan_id,
                    collector=record.recon_category,
                    finding_type="email",
                    finding_value=clean_em,
                    source_tools=[tool_name],
                    source_details={"collector": record.recon_category},
                    timestamp_utc=timestamp,
                    status="VALID",
                    evidence_reference=evidence,
                    verification_state="unverified"
                ))

        # 6. Direct IP Addresses (if not already added via DNS records)
        existing_ips = {f.finding_value for f in findings if f.finding_type == "ip_address"}
        for ip in record.ip_addresses:
            clean_ip = ip.strip()
            if clean_ip and clean_ip not in existing_ips:
                findings.append(NormalizedFinding(
                    target=target,
                    scan_id=scan_id,
                    collector=record.recon_category,
                    finding_type="ip_address",
                    finding_value=clean_ip,
                    source_tools=[tool_name],
                    source_details={"collector": record.recon_category},
                    timestamp_utc=timestamp,
                    status="VALID",
                    evidence_reference=evidence,
                    verification_state="unverified"
                ))

        return findings
