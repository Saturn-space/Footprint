"""
OSINT-RECON DNS Collector Module
Performs passive DNS enumeration across A, AAAA, MX, NS, TXT, and CNAME records
using dnspython with configurable timeouts, robust fallbacks, and raw evidence preservation.
"""

import os
import re
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
import dns.resolver
import dns.rdatatype
import dns.exception

from src.schema import ReconRecord, TargetInfo, ToolInfo, DNSRecord


SUPPORTED_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
DEFAULT_FALLBACK_NAMESERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


def normalize_record_value(rtype: str, rdata: Any) -> Tuple[str, Optional[int]]:
    """
    Normalizes DNS record value and extracts priority/preference where appropriate.
    Returns: (normalized_value, priority_or_none)
    """
    priority = None
    if rtype == "MX":
        preference = getattr(rdata, "preference", None)
        raw_exchange = str(getattr(rdata, "exchange", "")).strip().lower()
        # Handle RFC 7505 Null MX record ("0 .")
        exchange = "." if raw_exchange == "." else raw_exchange.rstrip(".")
        priority = int(preference) if preference is not None else None
        value = exchange
    elif rtype == "TXT":
        # dnspython represents TXT strings as bytes tuples or joined strings
        if hasattr(rdata, "strings") and rdata.strings:
            value = "".join([s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s) for s in rdata.strings])
        else:
            value = str(rdata).strip('"')
    elif rtype in ("NS", "CNAME"):
        raw_val = str(rdata).strip().lower()
        value = "." if raw_val == "." else raw_val.rstrip(".")
    else:
        value = str(rdata).strip()

    return value, priority


class DNSCollector:
    """
    Automated DNS Enumeration collector.
    Queries A, AAAA, MX, NS, TXT, and CNAME records, captures TTLs, and handles errors.
    """

    def __init__(
        self,
        nameservers: Optional[List[str]] = None,
        timeout: float = 4.0,
        lifetime: float = 8.0,
        raw_dir: Optional[str] = None
    ):
        self.nameservers = nameservers or DEFAULT_FALLBACK_NAMESERVERS
        self.timeout = timeout
        self.lifetime = lifetime
        self.raw_dir = raw_dir
        self.resolver = self._build_resolver()

    def _build_resolver(self) -> dns.resolver.Resolver:
        """Constructs and configures a dnspython Resolver instance."""
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(self.nameservers)
        resolver.timeout = self.timeout
        resolver.lifetime = self.lifetime
        return resolver

    def validate_domain(self, domain: str) -> str:
        """Validates and standardizes domain name format."""
        if not domain or not isinstance(domain, str):
            raise ValueError("Target domain must be a non-empty string")
        clean = domain.strip().lower().rstrip(".")
        clean = re.sub(r"^https?://", "", clean)
        clean = clean.split("/")[0].split(":")[0]
        if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", clean):
            raise ValueError(f"Invalid domain format for DNS lookup: '{domain}'")
        return clean

    def query_record_type(
        self, domain: str, rtype: str
    ) -> Tuple[List[DNSRecord], List[str], Optional[str]]:
        """
        Queries a specific record type for the target domain.
        Returns: (records_list, raw_lines, error_message_or_none)
        """
        records: List[DNSRecord] = []
        raw_lines: List[str] = []
        error: Optional[str] = None

        try:
            answers = self.resolver.resolve(domain, rtype)
            ttl = answers.ttl
            for rdata in answers:
                val, priority = normalize_record_value(rtype, rdata)
                record = DNSRecord(
                    record_type=rtype,
                    value=val,
                    ttl=ttl,
                    priority=priority
                )
                records.append(record)
                raw_lines.append(f"{domain}. {ttl} IN {rtype} {val}")
        except dns.resolver.NoAnswer:
            # Query completed successfully, but no records of this type exist
            raw_lines.append(f";; {rtype} query for {domain} returned NoAnswer (0 records)")
        except dns.resolver.NXDOMAIN:
            error = f"NXDOMAIN: Domain '{domain}' does not exist"
            raw_lines.append(f";; ERROR: NXDOMAIN for {domain} on {rtype}")
        except dns.resolver.Timeout:
            error = f"Timeout querying {rtype} records for '{domain}' after {self.lifetime}s"
            raw_lines.append(f";; ERROR: Query timeout for {rtype} on {domain}")
        except dns.resolver.NoNameservers:
            error = f"No nameservers answered query for {rtype} on '{domain}'"
            raw_lines.append(f";; ERROR: NoNameservers for {rtype} on {domain}")
        except dns.exception.DNSException as de:
            error = f"DNS resolution error on {rtype} for '{domain}': {str(de)}"
            raw_lines.append(f";; ERROR: {error}")
        except Exception as e:
            error = f"Unexpected error querying {rtype} on '{domain}': {str(e)}"
            raw_lines.append(f";; ERROR: {error}")

        return records, raw_lines, error

    def collect(
        self,
        domain: str,
        record_types: Optional[List[str]] = None,
        scan_id: Optional[str] = None
    ) -> ReconRecord:
        """
        Performs full DNS enumeration across all specified record types.
        Preserves raw output and returns a standardized ReconRecord.
        """
        errors: List[str] = []
        raw_output_path = None
        rtypes = record_types or SUPPORTED_RECORD_TYPES

        try:
            clean_domain = self.validate_domain(domain)
        except ValueError as ve:
            return ReconRecord(
                target_info=TargetInfo(
                    target=str(domain),
                    category="normal_benchmark_domain",
                    authorization_status="AUTHORIZED_PASSIVE_ONLY",
                    scope=str(domain)
                ),
                tool_info=ToolInfo(
                    name="dnspython",
                    version="2.9.2",
                    execution_args="dns.resolver.resolve"
                ),
                recon_category="dns",
                scan_id=scan_id,
                scan_status="FAILED",
                errors_and_warnings=[str(ve)],
                evidence_source="dns_collector"
            )

        all_dns_records: List[DNSRecord] = []
        raw_evidence_lines: List[str] = [
            f";; OSINT-RECON DNS Enumeration for: {clean_domain}",
            f";; Timestamp UTC: {datetime.now(timezone.utc).isoformat()}",
            f";; Nameservers used: {', '.join(self.nameservers)}",
            f";; Query timeout: {self.timeout}s, Lifetime: {self.lifetime}s",
            ";; ------------------------------------------------------------------"
        ]

        query_success_count = 0
        nxdomain_detected = False

        for rtype in rtypes:
            records, lines, err = self.query_record_type(clean_domain, rtype)
            raw_evidence_lines.extend(lines)
            if records:
                all_dns_records.extend(records)
                query_success_count += 1
            if err:
                errors.append(err)
                if "NXDOMAIN" in err:
                    nxdomain_detected = True
                    break
            elif not records:
                # NoAnswer is still considered a successful query completion
                query_success_count += 1

        # Extract discovered IP addresses and subdomains/nameservers
        ip_addresses: List[str] = []
        discovered_domains: List[str] = [clean_domain]

        for rec in all_dns_records:
            if rec.record_type in ("A", "AAAA"):
                if rec.value not in ip_addresses:
                    ip_addresses.append(rec.value)
            elif rec.record_type in ("NS", "MX", "CNAME"):
                if rec.value and rec.value not in discovered_domains:
                    discovered_domains.append(rec.value)

        # Determine overall collection status
        if nxdomain_detected:
            scan_status = "FAILED"
        elif all_dns_records:
            scan_status = "SUCCESS" if not errors else "PARTIAL"
        elif query_success_count > 0:
            scan_status = "SUCCESS"  # Valid domain that returned NoAnswer for queried types
        else:
            scan_status = "FAILED"

        # Preserve raw evidence file if raw_dir is specified
        if self.raw_dir:
            os.makedirs(self.raw_dir, exist_ok=True)
            filename = f"{scan_id}_dns_raw.txt" if scan_id else f"dns_{clean_domain}_raw.txt"
            raw_output_path = os.path.join(self.raw_dir, filename)
            try:
                with open(raw_output_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(raw_evidence_lines) + "\n")
            except IOError as ioe:
                errors.append(f"Failed to write DNS raw evidence file: {ioe}")

        return ReconRecord(
            target_info=TargetInfo(
                target=clean_domain,
                category="normal_benchmark_domain",
                authorization_status="AUTHORIZED_PASSIVE_ONLY",
                scope=f"{clean_domain} (Passive DNS Enumeration)"
            ),
            tool_info=ToolInfo(
                name="dnspython",
                version="2.9.2",
                execution_args=f"resolver.resolve [{', '.join(rtypes)}]"
            ),
            recon_category="dns",
            scan_id=scan_id,
            discovered_domains=discovered_domains,
            ip_addresses=ip_addresses,
            dns_records=all_dns_records,
            evidence_source=raw_output_path or f"dnspython query ({clean_domain})",
            scan_status=scan_status,
            errors_and_warnings=errors,
            raw_output_reference=raw_output_path
        )

