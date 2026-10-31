"""Collector abstractions and result structures for passive reconnaissance."""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple


@dataclass
class DiscoveredFinding:
    """An individual entity discovered during collector execution."""
    entity_type: str  # DOMAIN, SUBDOMAIN, IP_ADDRESS, HOST, EMAIL, ORGANIZATION, DNS_RECORD, CERTIFICATE
    raw_value: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectorResult:
    """Standardized output produced by all passive reconnaissance collectors."""
    collector_name: str
    source_type: str  # RDAP, WHOIS, DNS, CERTIFICATE_TRANSPARENCY, THEHARVESTER
    source_name: str  # e.g. rdap.org, local_resolver, crt.sh
    target: str
    status: str  # SUCCESS, PARTIAL, FAILED, NOT_CONFIGURED
    raw_content: Any  # string or dict/list
    content_format: str  # "json" or "text"
    findings: List[DiscoveredFinding] = field(default_factory=list)
    source_metadata: Dict[str, Any] = field(default_factory=dict)
    error_category: Optional[str] = None
    error_message: Optional[str] = None


class BaseCollector:
    """Abstract base class for all passive reconnaissance collectors."""

    name: str = "base_collector"
    source_type: str = "GENERIC"

    async def collect(self, target: str) -> CollectorResult:
        """Executes passive reconnaissance against target domain or host."""
        raise NotImplementedError
