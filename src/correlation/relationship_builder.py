"""
OSINT-RECON Relationship Correlation Builder Module
Constructs evidence-backed relationships between resolved assets across
passive and active intelligence sources while strictly enforcing evidence provenance
and laboratory isolation boundaries.
"""

import hashlib
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone

from src.schema import (
    Asset,
    AssetRelationship,
    EvidenceReference,
    ReconRecord,
    NormalizedFinding,
    ActiveReconResult
)
from src.correlation.confidence_engine import ConfidenceEngine
from src.correlation.asset_resolver import normalize_domain_name, normalize_ip_address, normalize_email_address


def generate_relationship_id(source_id: str, target_id: str, rel_type: str) -> str:
    """Generates a stable deterministic relationship identifier."""
    seed = f"{source_id}->{rel_type}->{target_id}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
    return f"REL-{rel_type}-{digest}"


class RelationshipBuilder:
    """
    Builds and evaluates evidence-supported relationships between assets.
    """

    def __init__(self, confidence_engine: Optional[ConfidenceEngine] = None):
        self.confidence_engine = confidence_engine or ConfidenceEngine()
        self.registry: Dict[str, AssetRelationship] = {}

    def add_relationship(
        self,
        source_asset: Asset,
        target_asset: Asset,
        relationship_type: str,
        supporting_evidence: List[EvidenceReference],
        observed_at: Optional[str] = None
    ) -> Optional[AssetRelationship]:
        """
        Creates, deduplicates, and registers an AssetRelationship backed by evidence.
        Enforces rule: A relationship MUST have at least 1 supporting evidence reference.
        """
        if not supporting_evidence:
            return None

        rel_id = generate_relationship_id(source_asset.asset_id, target_asset.asset_id, relationship_type)
        ts = observed_at or datetime.now(timezone.utc).isoformat()
        evid_ids = [e.evidence_id for e in supporting_evidence]

        if rel_id in self.registry:
            existing = self.registry[rel_id]
            # Merge evidence IDs
            for eid in evid_ids:
                if eid not in existing.evidence_ids:
                    existing.evidence_ids.append(eid)

            # Re-evaluate confidence with merged evidence
            merged_evidence_objs = list(supporting_evidence)  # We will keep existing evidence objects in mind
            conf_class, conf_score, conf_expl = self.confidence_engine.evaluate_relationship(
                relationship_type, merged_evidence_objs
            )
            existing.confidence = conf_class  # type: ignore
            existing.confidence_score = conf_score
            existing.confidence_explanation = conf_expl

            if ts > existing.last_observed:
                existing.last_observed = ts
            if ts < existing.first_observed:
                existing.first_observed = ts

            return existing

        conf_class, conf_score, conf_expl = self.confidence_engine.evaluate_relationship(
            relationship_type, supporting_evidence
        )

        rel = AssetRelationship(
            relationship_id=rel_id,
            source_asset_id=source_asset.asset_id,
            target_asset_id=target_asset.asset_id,
            relationship_type=relationship_type,  # type: ignore
            evidence_ids=evid_ids,
            confidence=conf_class,  # type: ignore
            confidence_score=conf_score,
            confidence_explanation=conf_expl,
            first_observed=ts,
            last_observed=ts
        )
        self.registry[rel_id] = rel
        return rel

    def build_passive_relationships(
        self,
        target_domain_asset: Asset,
        assets_map: Dict[str, Asset],
        findings: List[NormalizedFinding],
        records: List[ReconRecord],
        evidence_registry: Dict[str, EvidenceReference]
    ) -> List[AssetRelationship]:
        """
        Builds relationships derived strictly from passive reconnaissance findings.
        """
        built: List[AssetRelationship] = []

        # 1. DNS Records to IP / Nameserver
        for rec in records:
            tool = rec.tool_info.name
            ts = rec.timestamp_utc

            for dns_rec in rec.dns_records:
                rtype = dns_rec.record_type.upper()
                rval = dns_rec.value.strip().lower().rstrip(".")

                if rtype in ("A", "AAAA"):
                    try:
                        norm_ip, ip_cat = normalize_ip_address(rval)
                        ip_asset_id = f"ASSET:{ip_cat.upper()}:{norm_ip}"
                        ip_asset = assets_map.get(ip_asset_id)

                        if ip_asset:
                            # Match supporting evidence
                            ev_matches = [
                                e for e in evidence_registry.values()
                                if e.source_module == tool and e.normalized_value == norm_ip
                            ]
                            rel = self.add_relationship(
                                source_asset=target_domain_asset,
                                target_asset=ip_asset,
                                relationship_type="DOMAIN_RESOLVES_TO_IP",
                                supporting_evidence=ev_matches,
                                observed_at=ts
                            )
                            if rel:
                                built.append(rel)
                    except ValueError:
                        pass

                elif rtype == "NS":
                    cns = normalize_domain_name(rval)
                    ns_asset_id = f"ASSET:NAMESERVER:{cns}"
                    ns_asset = assets_map.get(ns_asset_id)
                    if ns_asset:
                        ev_matches = [
                            e for e in evidence_registry.values()
                            if e.source_module == tool and e.normalized_value == cns
                        ]
                        rel = self.add_relationship(
                            source_asset=target_domain_asset,
                            target_asset=ns_asset,
                            relationship_type="DOMAIN_USES_NAMESERVER",
                            supporting_evidence=ev_matches,
                            observed_at=ts
                        )
                        if rel:
                            built.append(rel)

        # 2. Subdomains
        for asset in assets_map.values():
            if asset.asset_type == "subdomain":
                sub_val = asset.canonical_value
                if sub_val != target_domain_asset.canonical_value and sub_val.endswith(target_domain_asset.canonical_value):
                    ev_matches = [
                        e for e in evidence_registry.values()
                        if e.normalized_value == sub_val
                    ]
                    rel = self.add_relationship(
                        source_asset=asset,
                        target_asset=target_domain_asset,
                        relationship_type="SUBDOMAIN_OF",
                        supporting_evidence=ev_matches,
                        observed_at=asset.first_seen
                    )
                    if rel:
                        built.append(rel)

        # 3. Emails
        for asset in assets_map.values():
            if asset.asset_type == "email":
                email_val = asset.canonical_value
                ev_matches = [
                    e for e in evidence_registry.values()
                    if e.normalized_value == email_val
                ]
                rel = self.add_relationship(
                    source_asset=asset,
                    target_asset=target_domain_asset,
                    relationship_type="EMAIL_DOMAIN_ASSOCIATION",
                    supporting_evidence=ev_matches,
                    observed_at=asset.first_seen
                )
                if rel:
                    built.append(rel)

        return built

    def build_active_relationships(
        self,
        active_result: ActiveReconResult,
        assets_map: Dict[str, Asset],
        evidence_registry: Dict[str, EvidenceReference]
    ) -> List[AssetRelationship]:
        """
        Builds relationships derived strictly from active reconnaissance (Nmap).
        """
        built: List[AssetRelationship] = []
        scan_id = active_result.scan_id
        ts = active_result.start_time_utc

        for host in active_result.hosts:
            try:
                norm_ip, ip_cat = normalize_ip_address(host.address)
                host_asset_id = f"ASSET:{ip_cat.upper()}:{norm_ip}"
                host_asset = assets_map.get(host_asset_id)
                if not host_asset:
                    continue
            except ValueError:
                continue

            # Hostnames -> IP
            for hn in host.hostnames:
                chn = normalize_domain_name(hn)
                hn_asset_id = f"ASSET:HOSTNAME:{chn}"
                hn_asset = assets_map.get(hn_asset_id)
                if hn_asset:
                    ev_matches = [
                        e for e in evidence_registry.values()
                        if e.scan_id == scan_id and e.evidence_type == "nmap_reverse_hostname" and e.normalized_value == chn
                    ]
                    rel_hn = self.add_relationship(
                        source_asset=hn_asset,
                        target_asset=host_asset,
                        relationship_type="HOSTNAME_OBSERVED_ON_SCAN",
                        supporting_evidence=ev_matches,
                        observed_at=ts
                    )
                    if rel_hn:
                        built.append(rel_hn)

            # Ports & Services
            for port in host.ports:
                if port.state == "open":
                    port_canon = f"{port.protocol}:{port.portid}"
                    port_asset_id = f"ASSET:PORT:{port_canon}"
                    port_asset = assets_map.get(port_asset_id)

                    if port_asset:
                        ev_port = [
                            e for e in evidence_registry.values()
                            if e.scan_id == scan_id and e.evidence_type == "nmap_open_port" and e.normalized_value == port_canon
                        ]
                        rel_port = self.add_relationship(
                            source_asset=host_asset,
                            target_asset=port_asset,
                            relationship_type="IP_HAS_OPEN_PORT",
                            supporting_evidence=ev_port,
                            observed_at=ts
                        )
                        if rel_port:
                            built.append(rel_port)

                    if port.service:
                        svc = port.service
                        csvc = svc.name.strip().lower()
                        svc_asset_id = f"ASSET:SERVICE:{csvc}"
                        svc_asset = assets_map.get(svc_asset_id)

                        if svc_asset:
                            ev_svc = [
                                e for e in evidence_registry.values()
                                if e.scan_id == scan_id and e.evidence_type == "nmap_service_probe" and e.normalized_value == csvc
                            ]
                            rel_svc = self.add_relationship(
                                source_asset=host_asset,
                                target_asset=svc_asset,
                                relationship_type="IP_EXPOSES_SERVICE",
                                supporting_evidence=ev_svc,
                                observed_at=ts
                            )
                            if rel_svc:
                                built.append(rel_svc)

                            # Service to CPE
                            for cpe_str in svc.cpe:
                                ccpe = cpe_str.strip().lower()
                                cpe_asset_id = f"ASSET:CPE:{ccpe}"
                                cpe_asset = assets_map.get(cpe_asset_id)
                                if cpe_asset:
                                    ev_cpe = [
                                        e for e in evidence_registry.values()
                                        if e.scan_id == scan_id and e.evidence_type == "nmap_cpe_identifier" and e.normalized_value == ccpe
                                    ]
                                    rel_cpe = self.add_relationship(
                                        source_asset=svc_asset,
                                        target_asset=cpe_asset,
                                        relationship_type="SERVICE_HAS_CPE",
                                        supporting_evidence=ev_cpe,
                                        observed_at=ts
                                    )
                                    if rel_cpe:
                                        built.append(rel_cpe)

        return built

    def get_all_relationships(self) -> List[AssetRelationship]:
        """Returns all registered relationships sorted by relationship_id."""
        return sorted(self.registry.values(), key=lambda r: r.relationship_id)

