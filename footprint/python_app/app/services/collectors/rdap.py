"""RDAP and WHOIS fallback collector."""

import re
import httpx
from typing import Dict, Any, List, Optional
from app.config import settings
from app.services.collectors.base import BaseCollector, CollectorResult, DiscoveredFinding
from app.services.collectors.whois_client import query_whois_with_fallback


class RDAPCollector(BaseCollector):
    """Domain registration collector using RDAP with RFC 3912 WHOIS fallback."""

    name: str = "rdap_whois_collector"
    source_type: str = "RDAP"

    def __init__(self, bootstrap_url: Optional[str] = None, timeout_seconds: Optional[int] = None):
        self.bootstrap_url = (bootstrap_url or settings.RDAP_BOOTSTRAP_URL).rstrip("/")
        self.timeout_seconds = timeout_seconds or settings.RECON_TIMEOUT_SECONDS

    async def collect(self, target: str) -> CollectorResult:
        clean_target = target.strip().lower()
        if not clean_target:
            return CollectorResult(
                collector_name=self.name,
                source_type=self.source_type,
                source_name=self.bootstrap_url,
                target=target,
                status="FAILED",
                raw_content="",
                content_format="text",
                error_category="INVALID_TARGET",
                error_message="Empty domain target specified",
            )

        rdap_url = f"{self.bootstrap_url}/domain/{clean_target}"
        headers = {"Accept": "application/rdap+json, application/json"}

        # 1. Attempt RDAP query
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
                resp = await client.get(rdap_url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    findings = self._parse_rdap_data(clean_target, data)
                    return CollectorResult(
                        collector_name=self.name,
                        source_type="RDAP",
                        source_name=self.bootstrap_url,
                        target=clean_target,
                        status="SUCCESS",
                        raw_content=data,
                        content_format="json",
                        findings=findings,
                        source_metadata={
                            "status_code": resp.status_code,
                            "url": str(resp.url),
                            "protocol": "RDAP",
                        },
                    )
                elif resp.status_code == 404:
                    # Domain not found in RDAP, try WHOIS fallback
                    return await self._fallback_whois(clean_target, reason=f"RDAP 404 Not Found from {rdap_url}")
                else:
                    return await self._fallback_whois(clean_target, reason=f"RDAP returned HTTP {resp.status_code}")
        except (httpx.TimeoutException, httpx.RequestError) as exc:
            return await self._fallback_whois(clean_target, reason=f"RDAP connection error: {exc}")
        except Exception as exc:
            return await self._fallback_whois(clean_target, reason=f"RDAP unexpected error: {exc}")

    async def _fallback_whois(self, target: str, reason: str) -> CollectorResult:
        """Executes fallback WHOIS lookup when RDAP is unavailable or unpopulated."""
        success, raw_whois, server = query_whois_with_fallback(target, timeout=self.timeout_seconds)

        if not success or not raw_whois:
            return CollectorResult(
                collector_name=self.name,
                source_type="WHOIS",
                source_name=server,
                target=target,
                status="FAILED",
                raw_content=raw_whois or "",
                content_format="text",
                error_category="FALLBACK_WHOIS_FAILED",
                error_message=f"{reason}; WHOIS fallback failed: {raw_whois}",
                source_metadata={"fallback_reason": reason, "server": server},
            )

        findings = self._parse_whois_text(target, raw_whois)
        return CollectorResult(
            collector_name=self.name,
            source_type="WHOIS",
            source_name=server,
            target=target,
            status="SUCCESS" if findings else "PARTIAL",
            raw_content=raw_whois,
            content_format="text",
            findings=findings,
            source_metadata={
                "fallback_reason": reason,
                "server": server,
                "protocol": "RFC3912_WHOIS",
            },
        )

    def _parse_rdap_data(self, target: str, data: Dict[str, Any]) -> List[DiscoveredFinding]:
        """Extracts structured entities from RFC 7483 RDAP response."""
        findings: List[DiscoveredFinding] = []

        # Target Domain finding
        domain_name = data.get("ldhName") or data.get("handle") or target
        findings.append(
            DiscoveredFinding(
                entity_type="DOMAIN",
                raw_value=domain_name,
                metadata={
                    "status": data.get("status", []),
                    "port43": data.get("port43"),
                },
            )
        )

        # Registrar / Entities
        entities = data.get("entities", [])
        for ent in entities:
            roles = ent.get("roles", [])
            vcard_array = ent.get("vcardArray")
            org_name = None
            if vcard_array and len(vcard_array) > 1:
                for prop in vcard_array[1]:
                    if prop and prop[0] in ("fn", "org"):
                        org_name = prop[3]
                        break

            if "registrar" in roles and org_name:
                findings.append(
                    DiscoveredFinding(
                        entity_type="ORGANIZATION",
                        raw_value=str(org_name),
                        metadata={"role": "registrar", "handle": ent.get("handle")},
                    )
                )

        # Nameservers
        nameservers = data.get("nameservers", [])
        for ns in nameservers:
            ns_name = ns.get("ldhName") or ns.get("handle")
            if ns_name:
                findings.append(
                    DiscoveredFinding(
                        entity_type="HOST",
                        raw_value=str(ns_name).lower(),
                        metadata={"role": "nameserver"},
                    )
                )

        return findings

    def _parse_whois_text(self, target: str, text: str) -> List[DiscoveredFinding]:
        """Extracts entities from freeform WHOIS output."""
        findings: List[DiscoveredFinding] = [
            DiscoveredFinding(entity_type="DOMAIN", raw_value=target, metadata={"source": "whois_fallback"})
        ]

        # Extract Registrar
        registrar_match = re.search(r"Registrar:\s*([^\r\n]+)", text, re.IGNORECASE)
        if registrar_match:
            registrar = registrar_match.group(1).strip()
            if registrar:
                findings.append(
                    DiscoveredFinding(
                        entity_type="ORGANIZATION",
                        raw_value=registrar,
                        metadata={"role": "registrar", "source": "whois"},
                    )
                )

        # Extract Name Servers
        ns_matches = re.findall(r"Name Server:\s*([^\r\n\s]+)", text, re.IGNORECASE)
        for ns in ns_matches:
            clean_ns = ns.strip().rstrip(".").lower()
            if clean_ns:
                findings.append(
                    DiscoveredFinding(
                        entity_type="HOST",
                        raw_value=clean_ns,
                        metadata={"role": "nameserver", "source": "whois"},
                    )
                )

        return findings
