"""
OSINT-RECON Unified Asset Profile Builder Module
Synthesizes verified passive records, active scan results, and correlated relationships
into comprehensive, self-contained UnifiedAssetProfile entities without inventing missing data.
"""

from typing import Dict, List, Optional, Any, Set
from src.schema import (
    Asset,
    AssetRelationship,
    EvidenceReference,
    UnifiedAssetProfile,
    ReconRecord,
    ActiveReconResult
)


class AssetProfileBuilder:
    """
    Builds structured, factual asset profiles for primary targets (domains, hostnames, IPs).
    Distinguishes lab targets from public targets and explicitly notes unobserved properties.
    """

    def __init__(self, lab_subnets: Optional[List[str]] = None, lab_hosts: Optional[List[str]] = None):
        self.lab_subnets = lab_subnets or ["192.168.56.0/24"]
        self.lab_hosts = set(lab_hosts or ["192.168.56.111"])

    def build_domain_profile(
        self,
        domain_asset: Asset,
        relationships: List[AssetRelationship],
        assets_map: Dict[str, Asset],
        passive_records: List[ReconRecord],
        evidence_registry: Dict[str, EvidenceReference]
    ) -> UnifiedAssetProfile:
        """Constructs a unified profile for a target domain asset."""
        target_domain = domain_asset.canonical_value

        # Collect relationships where this domain is source or target
        rel_domains: Set[str] = set()
        rel_hostnames: Set[str] = set()
        rel_ips: Set[str] = set()
        subdomains: Set[str] = set()
        emails: Set[str] = set()
        evid_ids: Set[str] = set()

        for r in relationships:
            if r.source_asset_id == domain_asset.asset_id:
                evid_ids.update(r.evidence_ids)
                tgt = assets_map.get(r.target_asset_id)
                if tgt:
                    if tgt.asset_type in ("ipv4", "ipv6"):
                        rel_ips.add(tgt.canonical_value)
                    elif tgt.asset_type == "nameserver":
                        rel_domains.add(tgt.canonical_value)
            elif r.target_asset_id == domain_asset.asset_id:
                evid_ids.update(r.evidence_ids)
                src = assets_map.get(r.source_asset_id)
                if src:
                    if src.asset_type == "subdomain":
                        subdomains.add(src.canonical_value)
                    elif src.asset_type == "email":
                        emails.add(src.canonical_value)

        # Extract structured DNS and WHOIS from passive records
        dns_records: List[Dict[str, Any]] = []
        whois_info: Optional[Dict[str, Any]] = None

        for rec in passive_records:
            if rec.recon_category == "dns":
                for d in rec.dns_records:
                    dns_records.append({
                        "record_type": d.record_type,
                        "value": d.value,
                        "ttl": d.ttl,
                        "priority": d.priority
                    })
            elif rec.recon_category == "whois" and rec.whois_data:
                w = rec.whois_data
                whois_info = {
                    "domain_name": w.domain_name or target_domain,
                    "registrar": w.registrar or "Not disclosed / Redacted",
                    "creation_date": w.creation_date,
                    "expiration_date": w.expiration_date,
                    "updated_date": w.updated_date,
                    "status": w.status,
                    "name_servers": w.name_servers,
                    "registrant_organization": w.registrant_organization or "Privacy Redacted",
                    "dnssec": w.dnssec or "Unsigned / Unconfirmed"
                }

        env = "lab" if "lab" in domain_asset.tags else "external"

        notes = [
            f"Primary public domain profile synthesized across {len(passive_records)} passive collector stream(s)."
        ]
        if not rel_ips:
            notes.append("No resolving IP addresses identified in analyzed passive DNS records.")

        return UnifiedAssetProfile(
            asset_id=domain_asset.asset_id,
            asset_type="domain",
            canonical_identity=target_domain,
            display_name=domain_asset.display_name,
            environment=env,
            related_domains=sorted(list(rel_domains)),
            related_hostnames=sorted(list(rel_hostnames)),
            related_ips=sorted(list(rel_ips)),
            dns_records=dns_records,
            whois_information=whois_info,
            discovered_subdomains=sorted(list(subdomains)),
            associated_email_evidence=sorted(list(emails)),
            open_ports=[],  # Active scanning not conducted against this domain in passive mode
            detected_services=[],
            detected_versions=[],
            cpe_identifiers=[],
            evidence_references=sorted(list(evid_ids)),
            correlation_confidence="DIRECT" if rel_ips else "CORROBORATED",
            unresolved_relationships=[],
            notes=notes
        )

    def build_ip_profile(
        self,
        ip_asset: Asset,
        relationships: List[AssetRelationship],
        assets_map: Dict[str, Asset],
        active_results: List[ActiveReconResult],
        evidence_registry: Dict[str, EvidenceReference]
    ) -> UnifiedAssetProfile:
        """Constructs a unified profile for an IPv4/IPv6 asset."""
        ip_str = ip_asset.canonical_value
        is_lab = ip_str in self.lab_hosts or "lab" in ip_asset.tags
        is_loop = ip_str in ("127.0.0.1", "::1", "localhost") or "loopback" in ip_asset.tags
        env = "lab" if is_lab else ("local" if is_loop else "external")

        rel_domains: Set[str] = set()
        rel_hostnames: Set[str] = set()
        open_ports: List[Dict[str, Any]] = []
        detected_services: List[Dict[str, Any]] = []
        detected_versions: Set[str] = set()
        cpe_identifiers: Set[str] = set()
        evid_ids: Set[str] = set()

        # Check relationships
        for r in relationships:
            if r.source_asset_id == ip_asset.asset_id:
                evid_ids.update(r.evidence_ids)
                tgt = assets_map.get(r.target_asset_id)
                if tgt:
                    if tgt.asset_type == "port":
                        pass  # Handled below via active_results or attributes
                    elif tgt.asset_type == "service":
                        pass
            elif r.target_asset_id == ip_asset.asset_id:
                evid_ids.update(r.evidence_ids)
                src = assets_map.get(r.source_asset_id)
                if src:
                    if src.asset_type == "domain":
                        rel_domains.add(src.canonical_value)
                    elif src.asset_type == "hostname":
                        rel_hostnames.add(src.canonical_value)

        # Extract active findings from ActiveReconResult matching this IP
        active_found = False
        for a_res in active_results:
            for host in a_res.hosts:
                if host.address == ip_str:
                    active_found = True
                    for hn in host.hostnames:
                        rel_hostnames.add(hn.strip().lower())
                    for port in host.ports:
                        if port.state == "open":
                            open_ports.append({
                                "portid": port.portid,
                                "protocol": port.protocol,
                                "state": port.state,
                                "reason": port.reason
                            })
                            if port.service:
                                svc = port.service
                                detected_services.append({
                                    "port": port.portid,
                                    "protocol": port.protocol,
                                    "service_name": svc.name,
                                    "product": svc.product,
                                    "version": svc.version,
                                    "extrainfo": svc.extrainfo,
                                    "ostype": svc.ostype,
                                    "confidence": svc.conf
                                })
                                if svc.product:
                                    ver_str = f"{svc.product} {svc.version or ''}".strip()
                                    detected_versions.add(ver_str)
                                for cpe_str in svc.cpe:
                                    cpe_identifiers.add(cpe_str)

        notes: List[str] = []
        if is_lab:
            notes.append(
                f"Private isolated laboratory asset ({ip_str}) within authorized assessment scope. "
                "Public WHOIS and public DNS resolution are not applicable to RFC1918 private addresses."
            )
        elif is_loop:
            notes.append(f"Diagnostic loopback interface ({ip_str}) on local host.")
        else:
            notes.append(f"Public IP address asset ({ip_str}).")

        if active_found:
            notes.append(f"Active reconnaissance identified {len(open_ports)} open TCP port(s) and {len(detected_services)} service(s).")
        else:
            notes.append("No active port scan performed directly on this IP in provided scan sessions.")

        return UnifiedAssetProfile(
            asset_id=ip_asset.asset_id,
            asset_type=ip_asset.asset_type,
            canonical_identity=ip_str,
            display_name=ip_asset.display_name,
            environment=env,
            related_domains=sorted(list(rel_domains)),
            related_hostnames=sorted(list(rel_hostnames)),
            related_ips=[],
            dns_records=[],
            whois_information=None,  # Not applicable or unobserved for private lab / unqueried IPs
            discovered_subdomains=[],
            associated_email_evidence=[],
            open_ports=open_ports,
            detected_services=detected_services,
            detected_versions=sorted(list(detected_versions)),
            cpe_identifiers=sorted(list(cpe_identifiers)),
            evidence_references=sorted(list(evid_ids)),
            correlation_confidence="DIRECT" if active_found else "INDIRECT",
            unresolved_relationships=[],
            notes=notes
        )

