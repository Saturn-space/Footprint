"""Certificate Transparency log collector querying crt.sh API."""

import httpx
from typing import Dict, Any, List, Optional, Set
from app.config import settings
from app.services.collectors.base import BaseCollector, CollectorResult, DiscoveredFinding


class CertificateTransparencyCollector(BaseCollector):
    """Collects TLS certificate transparency evidence from public CT logs via crt.sh."""

    name: str = "crtsh_collector"
    source_type: str = "CERTIFICATE_TRANSPARENCY"

    def __init__(self, base_url: Optional[str] = None, timeout_seconds: Optional[int] = None):
        if base_url is not None:
            self.base_url = base_url.strip().rstrip("/")
        else:
            self.base_url = settings.CRTSH_BASE_URL.strip().rstrip("/")
        self.timeout_seconds = timeout_seconds or settings.RECON_TIMEOUT_SECONDS

    async def collect(self, target: str) -> CollectorResult:
        if not self.base_url:
            return CollectorResult(
                collector_name=self.name,
                source_type=self.source_type,
                source_name="crt.sh",
                target=target,
                status="NOT_CONFIGURED",
                raw_content=[],
                content_format="json",
                error_category="UNCONFIGURED",
                error_message="CRTSH_BASE_URL is not configured",
            )

        clean_target = target.strip().lower().lstrip("*.")
        if not clean_target:
            return CollectorResult(
                collector_name=self.name,
                source_type=self.source_type,
                source_name=self.base_url,
                target=target,
                status="FAILED",
                raw_content=[],
                content_format="json",
                error_category="INVALID_TARGET",
                error_message="Empty target domain specified",
            )

        # Query crt.sh for wildcards
        url = f"{self.base_url}/"
        params = {"q": f"%.{clean_target}", "output": "json"}
        headers = {"User-Agent": "FootprintIQ-Recon/2.0 (Security OSINT Investigation)"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
                resp = await client.get(url, params=params, headers=headers)
                if resp.status_code == 429:
                    return CollectorResult(
                        collector_name=self.name,
                        source_type=self.source_type,
                        source_name=self.base_url,
                        target=clean_target,
                        status="PARTIAL",
                        raw_content=[],
                        content_format="json",
                        error_category="RATE_LIMITED",
                        error_message="crt.sh returned HTTP 429 Rate Limited",
                    )
                if resp.status_code != 200:
                    return CollectorResult(
                        collector_name=self.name,
                        source_type=self.source_type,
                        source_name=self.base_url,
                        target=clean_target,
                        status="FAILED",
                        raw_content=[],
                        content_format="json",
                        error_category="UPSTREAM_HTTP_ERROR",
                        error_message=f"crt.sh returned HTTP {resp.status_code}",
                    )

                data = resp.json()
                if not isinstance(data, list):
                    data = []

                findings = self._parse_certificates(clean_target, data)
                return CollectorResult(
                    collector_name=self.name,
                    source_type=self.source_type,
                    source_name=self.base_url,
                    target=clean_target,
                    status="SUCCESS",
                    raw_content=data,
                    content_format="json",
                    findings=findings,
                    source_metadata={
                        "query_url": str(resp.url),
                        "total_certificates_found": len(data),
                        "total_findings_extracted": len(findings),
                    },
                )
        except (httpx.TimeoutException, httpx.RequestError) as exc:
            return CollectorResult(
                collector_name=self.name,
                source_type=self.source_type,
                source_name=self.base_url,
                target=clean_target,
                status="FAILED",
                raw_content=[],
                content_format="json",
                error_category="NETWORK_TIMEOUT",
                error_message=f"Network error communicating with crt.sh: {exc}",
            )
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_type=self.source_type,
                source_name=self.base_url,
                target=clean_target,
                status="FAILED",
                raw_content=[],
                content_format="json",
                error_category="PARSE_ERROR",
                error_message=f"Failed to parse crt.sh response: {exc}",
            )

    def _parse_certificates(self, target: str, cert_list: List[Dict[str, Any]]) -> List[DiscoveredFinding]:
        findings: List[DiscoveredFinding] = []
        seen_hosts: Set[str] = set()

        for cert in cert_list:
            crtsh_id = cert.get("id")
            issuer = cert.get("issuer_name")
            entry_timestamp = cert.get("entry_timestamp")

            # Record certificate entry
            if crtsh_id:
                findings.append(
                    DiscoveredFinding(
                        entity_type="CERTIFICATE",
                        raw_value=f"crt.sh ID: {crtsh_id}",
                        metadata={
                            "crtsh_id": crtsh_id,
                            "issuer": issuer,
                            "entry_timestamp": entry_timestamp,
                            "not_before": cert.get("not_before"),
                            "not_after": cert.get("not_after"),
                        },
                    )
                )

            # Extract hostnames from common_name and name_value (SANs)
            names_raw = []
            if cert.get("common_name"):
                names_raw.append(str(cert["common_name"]))
            if cert.get("name_value"):
                names_raw.extend(str(cert["name_value"]).split("\n"))

            for raw_name in names_raw:
                host = raw_name.strip().lower().lstrip("*.")
                if not host or host in seen_hosts:
                    continue
                seen_hosts.add(host)

                # Classify as SUBDOMAIN if it ends with target and is strictly longer, else DOMAIN
                if host == target:
                    findings.append(
                        DiscoveredFinding(
                            entity_type="DOMAIN",
                            raw_value=host,
                            metadata={"source": "crtsh", "issuer": issuer},
                        )
                    )
                elif host.endswith(f".{target}"):
                    findings.append(
                        DiscoveredFinding(
                            entity_type="SUBDOMAIN",
                            raw_value=host,
                            metadata={"source": "crtsh", "parent_domain": target, "issuer": issuer},
                        )
                    )
                else:
                    findings.append(
                        DiscoveredFinding(
                            entity_type="HOST",
                            raw_value=host,
                            metadata={"source": "crtsh_san", "associated_target": target},
                        )
                    )

        return findings
