"""DNS record collection engine using dnspython with typed exception handling."""

import asyncio
from typing import Dict, Any, List, Optional
import dns.resolver
import dns.exception
import dns.rdatatype

from app.config import settings
from app.services.collectors.base import BaseCollector, CollectorResult, DiscoveredFinding


class DNSCollector(BaseCollector):
    """Gathers standard DNS resource records (A, AAAA, MX, NS, CNAME, TXT, SOA)."""

    name: str = "dns_collector"
    source_type: str = "DNS"
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA"]

    def __init__(self, nameservers: Optional[List[str]] = None, timeout_seconds: Optional[int] = None):
        self.timeout_seconds = timeout_seconds or settings.RECON_TIMEOUT_SECONDS
        self.custom_nameservers = nameservers

    async def collect(self, target: str) -> CollectorResult:
        clean_target = target.strip().rstrip(".").lower()
        if not clean_target:
            return CollectorResult(
                collector_name=self.name,
                source_type=self.source_type,
                source_name="dns_resolver",
                target=target,
                status="FAILED",
                raw_content={},
                content_format="json",
                error_category="INVALID_TARGET",
                error_message="Empty domain target specified",
            )

        # Execute queries in a threadpool to keep async loop non-blocking
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._collect_sync, clean_target)

    def _collect_sync(self, target: str) -> CollectorResult:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = float(self.timeout_seconds)
        resolver.timeout = float(self.timeout_seconds)
        if self.custom_nameservers:
            resolver.nameservers = self.custom_nameservers

        raw_results: Dict[str, Any] = {
            "target": target,
            "nameservers": resolver.nameservers,
            "records": {},
            "status_by_type": {},
        }
        findings: List[DiscoveredFinding] = []
        authoritative_target_found = False
        transient_failures = 0

        for rtype in self.RECORD_TYPES:
            try:
                answers = resolver.resolve(target, rtype)
                authoritative_target_found = True
                raw_results["status_by_type"][rtype] = "SUCCESS"
                type_records = []

                for rdata in answers:
                    val = rdata.to_text().strip('"')
                    ttl = answers.rrset.ttl if answers.rrset else None
                    rec_entry = {"value": val, "ttl": ttl, "type": rtype}
                    type_records.append(rec_entry)

                    # Extract findings based on type
                    record_desc = f"{rtype}: {val}"
                    findings.append(
                        DiscoveredFinding(
                            entity_type="DNS_RECORD",
                            raw_value=record_desc,
                            metadata={"record_type": rtype, "value": val, "ttl": ttl, "domain": target},
                        )
                    )

                    if rtype in ("A", "AAAA"):
                        findings.append(
                            DiscoveredFinding(
                                entity_type="IP_ADDRESS",
                                raw_value=val,
                                metadata={"source": "dns", "record_type": rtype, "associated_domain": target},
                            )
                        )
                    elif rtype == "MX":
                        # MX format: "preference exchange"
                        parts = val.split(None, 1)
                        host = (parts[1] if len(parts) > 1 else parts[0]).rstrip(".")
                        findings.append(
                            DiscoveredFinding(
                                entity_type="HOST",
                                raw_value=host.lower(),
                                metadata={"role": "mail_exchanger", "source": "dns_mx"},
                            )
                        )
                    elif rtype == "NS":
                        ns_host = val.rstrip(".")
                        findings.append(
                            DiscoveredFinding(
                                entity_type="HOST",
                                raw_value=ns_host.lower(),
                                metadata={"role": "nameserver", "source": "dns_ns"},
                            )
                        )
                    elif rtype == "CNAME":
                        cname_host = val.rstrip(".")
                        findings.append(
                            DiscoveredFinding(
                                entity_type="HOST",
                                raw_value=cname_host.lower(),
                                metadata={"role": "cname_target", "source": "dns_cname"},
                            )
                        )

                raw_results["records"][rtype] = type_records

            except dns.resolver.NXDOMAIN:
                raw_results["status_by_type"][rtype] = "NXDOMAIN"
            except dns.resolver.NoAnswer:
                raw_results["status_by_type"][rtype] = "NO_ANSWER"
                authoritative_target_found = True
            except dns.resolver.NoNameservers:
                raw_results["status_by_type"][rtype] = "NO_NAMESERVERS"
                transient_failures += 1
            except dns.exception.Timeout:
                raw_results["status_by_type"][rtype] = "TIMEOUT"
                transient_failures += 1
            except Exception as exc:
                raw_results["status_by_type"][rtype] = f"ERROR: {exc}"
                transient_failures += 1

        # Also add target DOMAIN finding if we resolved anything or target exists
        if authoritative_target_found or findings:
            findings.append(
                DiscoveredFinding(
                    entity_type="DOMAIN",
                    raw_value=target,
                    metadata={"source": "dns_resolution"},
                )
            )
            overall_status = "SUCCESS" if transient_failures == 0 else "PARTIAL"
        elif transient_failures == len(self.RECORD_TYPES):
            overall_status = "FAILED"
        else:
            overall_status = "SUCCESS"  # cleanly authoritative NXDOMAIN / NoAnswer across queries

        return CollectorResult(
            collector_name=self.name,
            source_type=self.source_type,
            source_name="dns_resolver",
            target=target,
            status=overall_status,
            raw_content=raw_results,
            content_format="json",
            findings=findings,
            source_metadata={
                "nameservers": resolver.nameservers,
                "timeout_seconds": self.timeout_seconds,
                "transient_failures": transient_failures,
            },
        )
