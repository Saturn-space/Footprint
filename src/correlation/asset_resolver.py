"""
OSINT-RECON Asset Resolver Module
Normalizes entities, enforces deterministic asset IDs, and resolves exact duplicates
while preserving provenance and multi-source observations over time.
"""

import ipaddress
import re
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone

from src.schema import Asset, ReconRecord, NormalizedFinding, ActiveReconResult, NmapHost, NmapPort


def normalize_domain_name(raw: str) -> str:
    """Normalizes domain / FQDN to lowercase stripped format without trailing dots or protocols."""
    if not raw:
        return ""
    val = raw.strip().lower()
    val = re.sub(r"^(?:https?://|ftps?://|//)", "", val)
    val = val.rstrip(".")
    val = val.split(":")[0].split("/")[0]
    return val


def normalize_ip_address(raw: str) -> Tuple[str, str]:
    """
    Normalizes an IP address using python ipaddress.
    Strips leading zeros from octets to prevent ambiguity.
    Returns: (canonical_ip_str, 'ipv4' | 'ipv6')
    Raises ValueError if invalid IP.
    """
    cleaned = raw.strip()
    # Strip port if present e.g. 192.168.1.1:80
    if ":" in cleaned and not cleaned.startswith("[") and cleaned.count(":") == 1:
        cleaned = cleaned.split(":")[0]

    # Handle IPv4 leading zeros (e.g. 192.168.056.111 -> 192.168.56.111)
    if "." in cleaned and ":" not in cleaned:
        parts = cleaned.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            try:
                cleaned = ".".join(str(int(p)) for p in parts)
            except ValueError:
                pass

    ip_obj = ipaddress.ip_address(cleaned)
    addr_type = "ipv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "ipv6"
    return ip_obj.exploded if addr_type == "ipv6" else str(ip_obj), addr_type


def normalize_email_address(raw: str) -> str:
    """Normalizes an email address (lowercasing domain part, preserving local part)."""
    val = raw.strip()
    if "@" in val:
        local, domain = val.rsplit("@", 1)
        return f"{local}@{domain.lower().rstrip('.')}"
    return val.lower()


def normalize_cpe(raw: str) -> str:
    """Normalizes a Common Platform Enumeration (CPE) string."""
    cleaned = raw.strip().lower()
    return cleaned


def normalize_service_name(raw: str) -> str:
    """Normalizes a network service name."""
    return raw.strip().lower()


def generate_asset_id(asset_type: str, canonical_value: str) -> str:
    """Generates a stable, deterministic asset ID."""
    clean_type = asset_type.upper()
    return f"ASSET:{clean_type}:{canonical_value}"


class AssetResolver:
    """
    Resolves, normalizes, and deduplicates assets across passive and active reconnaissance.
    Maintains deterministic asset identities and tracks observations over time.
    """

    def __init__(self, lab_subnets: Optional[List[str]] = None, lab_hosts: Optional[List[str]] = None):
        self.registry: Dict[str, Asset] = {}
        self.lab_subnets = lab_subnets or ["192.168.56.0/24"]
        self.lab_hosts = set(lab_hosts or ["192.168.56.111"])

    def is_lab_asset(self, ip_str: str) -> bool:
        """Determines if an IP address belongs to the authorized laboratory environment."""
        if ip_str in self.lab_hosts:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for subnet in self.lab_subnets:
                if ip_obj in ipaddress.ip_network(subnet, strict=False):
                    return True
        except ValueError:
            pass
        return False

    def is_loopback(self, ip_str: str) -> bool:
        """Determines if an IP address is loopback."""
        try:
            return ipaddress.ip_address(ip_str).is_loopback
        except ValueError:
            return ip_str in ("127.0.0.1", "::1", "localhost")

    def register_asset(
        self,
        asset_type: str,
        canonical_value: str,
        display_name: Optional[str] = None,
        source: Optional[str] = None,
        tags: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None,
        observed_at: Optional[str] = None
    ) -> Asset:
        """
        Creates or merges an asset in the registry.
        Deduplicates exact matches and updates observation time windows.
        """
        asset_id = generate_asset_id(asset_type, canonical_value)
        ts = observed_at or datetime.now(timezone.utc).isoformat()
        disp = display_name or canonical_value
        src_list = [source] if source else []
        tag_list = list(tags) if tags else []
        attr_dict = dict(attributes) if attributes else {}

        # Add environment tags if IP
        if asset_type in ("ipv4", "ipv6"):
            if self.is_lab_asset(canonical_value):
                if "lab" not in tag_list:
                    tag_list.append("lab")
            elif self.is_loopback(canonical_value):
                if "loopback" not in tag_list:
                    tag_list.append("loopback")
            else:
                if "public_ip" not in tag_list:
                    tag_list.append("public_ip")

        if asset_id in self.registry:
            existing = self.registry[asset_id]
            # Update time bounds
            if ts < existing.first_seen:
                existing.first_seen = ts
            if ts > existing.last_seen:
                existing.last_seen = ts

            # Merge sources
            for s in src_list:
                if s and s not in existing.sources:
                    existing.sources.append(s)

            # Merge tags
            for t in tag_list:
                if t and t not in existing.tags:
                    existing.tags.append(t)

            # Merge attributes
            for k, v in attr_dict.items():
                if k not in existing.attributes:
                    existing.attributes[k] = v
                elif existing.attributes[k] != v:
                    if isinstance(existing.attributes[k], list):
                        if v not in existing.attributes[k]:
                            existing.attributes[k].append(v)
                    else:
                        existing.attributes[k] = [existing.attributes[k], v]

            return existing

        asset = Asset(
            asset_id=asset_id,
            asset_type=asset_type,  # type: ignore
            canonical_value=canonical_value,
            display_name=disp,
            first_seen=ts,
            last_seen=ts,
            sources=src_list,
            tags=tag_list,
            attributes=attr_dict
        )
        self.registry[asset_id] = asset
        return asset

    def resolve_passive_findings(
        self,
        target_domain: str,
        findings: List[NormalizedFinding],
        records: List[ReconRecord]
    ) -> List[Asset]:
        """Resolves assets from W2 passive findings and records."""
        resolved: List[Asset] = []
        clean_target = normalize_domain_name(target_domain)

        # 1. Base Target Domain Asset
        target_asset = self.register_asset(
            asset_type="domain",
            canonical_value=clean_target,
            display_name=clean_target,
            source="passive_pipeline",
            tags=["target_domain", "public_asset"],
            attributes={"is_primary_target": True}
        )
        resolved.append(target_asset)

        # 2. Iterate Normalized Findings
        for finding in findings:
            ftype = finding.finding_type
            fval = finding.finding_value
            tool = finding.collector
            ts = finding.timestamp_utc

            if ftype == "domain":
                cdom = normalize_domain_name(fval)
                if cdom:
                    a = self.register_asset("domain", cdom, source=tool, observed_at=ts)
                    resolved.append(a)

            elif ftype == "subdomain":
                csub = normalize_domain_name(fval)
                if csub:
                    # Distinguish domain from subdomain
                    atype = "subdomain" if csub != clean_target and csub.endswith(clean_target) else "domain"
                    a = self.register_asset(atype, csub, source=tool, observed_at=ts)
                    resolved.append(a)

            elif ftype == "nameserver":
                cns = normalize_domain_name(fval)
                if cns:
                    a = self.register_asset("nameserver", cns, source=tool, tags=["nameserver"], observed_at=ts)
                    resolved.append(a)

            elif ftype == "ip_address":
                try:
                    norm_ip, ip_cat = normalize_ip_address(fval)
                    a = self.register_asset(ip_cat, norm_ip, source=tool, observed_at=ts)
                    resolved.append(a)
                except ValueError:
                    pass

            elif ftype == "email":
                cemail = normalize_email_address(fval)
                if "@" in cemail:
                    a = self.register_asset("email", cemail, source=tool, tags=["osint_email"], observed_at=ts)
                    resolved.append(a)

        # 3. Direct DNS Records from ReconRecord
        for rec in records:
            tool = rec.tool_info.name
            ts = rec.timestamp_utc
            for dns_rec in rec.dns_records:
                rtype = dns_rec.record_type.upper()
                rval = dns_rec.value
                if rtype == "A":
                    try:
                        norm_ip, _ = normalize_ip_address(rval)
                        a = self.register_asset("ipv4", norm_ip, source=tool, tags=["dns_resolved"], observed_at=ts)
                        resolved.append(a)
                    except ValueError:
                        pass
                elif rtype == "AAAA":
                    try:
                        norm_ip, _ = normalize_ip_address(rval)
                        a = self.register_asset("ipv6", norm_ip, source=tool, tags=["dns_resolved"], observed_at=ts)
                        resolved.append(a)
                    except ValueError:
                        pass
                elif rtype == "NS":
                    cns = normalize_domain_name(rval)
                    if cns:
                        a = self.register_asset("nameserver", cns, source=tool, tags=["nameserver"], observed_at=ts)
                        resolved.append(a)

        return list({a.asset_id: a for a in resolved}.values())

    def resolve_active_findings(self, active_result: ActiveReconResult) -> List[Asset]:
        """Resolves assets from W3 active scan result."""
        resolved: List[Asset] = []
        scan_id = active_result.scan_id
        tool = f"nmap:{active_result.scan_profile}"
        ts = active_result.start_time_utc

        for host in active_result.hosts:
            try:
                norm_ip, ip_cat = normalize_ip_address(host.address)
                env_tag = "lab" if self.is_lab_asset(norm_ip) else ("loopback" if self.is_loopback(norm_ip) else "public")
                host_asset = self.register_asset(
                    asset_type=ip_cat,
                    canonical_value=norm_ip,
                    display_name=f"{norm_ip} ({env_tag.upper()})",
                    source=tool,
                    tags=[env_tag, "active_scanned", f"status:{host.status}"],
                    attributes={
                        "addrtype": host.addrtype,
                        "status": host.status,
                        "status_reason": host.status_reason,
                        "scan_id": scan_id
                    },
                    observed_at=ts
                )
                resolved.append(host_asset)
            except ValueError:
                continue

            # Hostnames
            for hn in host.hostnames:
                chn = normalize_domain_name(hn)
                if chn:
                    hn_asset = self.register_asset(
                        asset_type="hostname",
                        canonical_value=chn,
                        source=tool,
                        tags=["reverse_dns", env_tag],
                        attributes={"resolved_from_ip": norm_ip},
                        observed_at=ts
                    )
                    resolved.append(hn_asset)

            # Ports, Services & CPEs
            for port in host.ports:
                if port.state == "open":
                    port_canon = f"{port.protocol}:{port.portid}"
                    port_asset = self.register_asset(
                        asset_type="port",
                        canonical_value=port_canon,
                        display_name=f"Port {port.portid}/{port.protocol.upper()}",
                        source=tool,
                        tags=["open_port", port.protocol],
                        attributes={"portid": port.portid, "protocol": port.protocol, "reason": port.reason},
                        observed_at=ts
                    )
                    resolved.append(port_asset)

                    if port.service:
                        svc = port.service
                        csvc = normalize_service_name(svc.name)
                        svc_asset = self.register_asset(
                            asset_type="service",
                            canonical_value=csvc,
                            display_name=f"Service: {csvc}",
                            source=tool,
                            tags=["network_service"],
                            attributes={
                                "product": svc.product,
                                "version": svc.version,
                                "extrainfo": svc.extrainfo,
                                "confidence": svc.conf,
                                "ostype": svc.ostype
                            },
                            observed_at=ts
                        )
                        resolved.append(svc_asset)

                        for cpe_str in svc.cpe:
                            ccpe = normalize_cpe(cpe_str)
                            cpe_asset = self.register_asset(
                                asset_type="cpe",
                                canonical_value=ccpe,
                                display_name=ccpe,
                                source=tool,
                                tags=["cpe_identifier"],
                                observed_at=ts
                            )
                            resolved.append(cpe_asset)

        return list({a.asset_id: a for a in resolved}.values())

    def get_all_assets(self) -> List[Asset]:
        """Returns all registered assets sorted by asset_id."""
        return sorted(self.registry.values(), key=lambda a: a.asset_id)

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        """Retrieves asset by deterministic asset_id."""
        return self.registry.get(asset_id)
