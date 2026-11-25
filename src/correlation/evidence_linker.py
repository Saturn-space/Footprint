"""
OSINT-RECON Evidence Linker Module
Extracts, structures, and registers cryptographic and file-backed evidence references
from passive and active reconnaissance results.
"""

import os
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from src.schema import EvidenceReference, ReconRecord, NormalizedFinding, ActiveReconResult, NmapPort


def compute_file_sha256(filepath: str) -> Optional[str]:
    """Computes SHA256 hash of a file if it exists and is readable."""
    if not filepath or not os.path.isfile(filepath):
        return None
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None


def generate_evidence_id(source_module: str, evidence_type: str, raw_key: str) -> str:
    """Generates a stable, deterministic evidence identifier."""
    seed = f"{source_module}:{evidence_type}:{raw_key.strip().lower()}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
    clean_mod = source_module.replace("_", "-").lower()
    clean_type = evidence_type.replace("_", "-").lower()
    return f"EVID-{clean_mod}-{clean_type}-{digest}"


class EvidenceLinker:
    """
    Maintains a deduplicated registry of EvidenceReference objects
    linked to raw files, tool streams, and cryptographic checksums.
    """

    def __init__(self):
        self.registry: Dict[str, EvidenceReference] = {}

    def register_evidence(
        self,
        source_module: str,
        scan_id: str,
        evidence_type: str,
        original_value: str,
        normalized_value: str,
        source_file: Optional[str] = None,
        sha256: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        timestamp_utc: Optional[str] = None
    ) -> EvidenceReference:
        """
        Creates or retrieves a deterministic EvidenceReference in the registry.
        """
        raw_key = f"{scan_id}:{original_value}"
        evid_id = generate_evidence_id(source_module, evidence_type, raw_key)

        if evid_id in self.registry:
            existing = self.registry[evid_id]
            # Update source file / sha256 if previously missing
            if not existing.source_file and source_file:
                existing.source_file = source_file
            if not existing.sha256 and sha256:
                existing.sha256 = sha256
            if context:
                existing.context.update(context)
            return existing

        # Compute hash if source_file exists but sha256 was not passed
        computed_sha = sha256
        if source_file and not computed_sha and os.path.isfile(source_file):
            computed_sha = compute_file_sha256(source_file)

        ts = timestamp_utc or datetime.now(timezone.utc).isoformat()
        ev_ref = EvidenceReference(
            evidence_id=evid_id,
            source_module=source_module,
            scan_id=scan_id,
            evidence_type=evidence_type,
            original_value=original_value,
            normalized_value=normalized_value,
            source_file=source_file,
            observation_timestamp=ts,
            sha256=computed_sha,
            context=context or {}
        )
        self.registry[evid_id] = ev_ref
        return ev_ref

    def link_passive_records(
        self,
        scan_id: str,
        records: List[ReconRecord],
        raw_files: Optional[Dict[str, str]] = None
    ) -> List[EvidenceReference]:
        """Registers evidence from W2 passive ReconRecord instances."""
        linked: List[EvidenceReference] = []
        raw_map = raw_files or {}

        for rec in records:
            module = rec.tool_info.name
            src_file = rec.raw_output_reference or raw_map.get(module) or rec.evidence_source
            ts = rec.timestamp_utc

            # WHOIS evidence
            if rec.whois_data:
                wdata = rec.whois_data
                if wdata.registrar:
                    ev = self.register_evidence(
                        source_module=module,
                        scan_id=scan_id,
                        evidence_type="whois_registrar",
                        original_value=wdata.registrar,
                        normalized_value=wdata.registrar.strip(),
                        source_file=src_file,
                        context={"category": rec.recon_category, "domain": wdata.domain_name},
                        timestamp_utc=ts
                    )
                    linked.append(ev)

                for ns in wdata.name_servers:
                    ev = self.register_evidence(
                        source_module=module,
                        scan_id=scan_id,
                        evidence_type="whois_nameserver",
                        original_value=ns,
                        normalized_value=ns.strip().lower().rstrip("."),
                        source_file=src_file,
                        context={"category": rec.recon_category},
                        timestamp_utc=ts
                    )
                    linked.append(ev)

                for em in wdata.emails:
                    ev = self.register_evidence(
                        source_module=module,
                        scan_id=scan_id,
                        evidence_type="whois_email",
                        original_value=em,
                        normalized_value=em.strip().lower(),
                        source_file=src_file,
                        context={"category": rec.recon_category},
                        timestamp_utc=ts
                    )
                    linked.append(ev)

            # DNS records evidence
            for dns_rec in rec.dns_records:
                ev = self.register_evidence(
                    source_module=module,
                    scan_id=scan_id,
                    evidence_type=f"dns_{dns_rec.record_type.lower()}_record",
                    original_value=f"{dns_rec.record_type} {dns_rec.value}",
                    normalized_value=dns_rec.value.strip().lower().rstrip("."),
                    source_file=src_file,
                    context={"record_type": dns_rec.record_type, "ttl": dns_rec.ttl, "priority": dns_rec.priority},
                    timestamp_utc=ts
                )
                linked.append(ev)

            # Discovered subdomains / emails from theHarvester
            for sub in rec.discovered_domains:
                ev = self.register_evidence(
                    source_module=module,
                    scan_id=scan_id,
                    evidence_type="harvested_subdomain",
                    original_value=sub,
                    normalized_value=sub.strip().lower().rstrip("."),
                    source_file=src_file,
                    context={"tool": module},
                    timestamp_utc=ts
                )
                linked.append(ev)

            for em in rec.email_addresses:
                ev = self.register_evidence(
                    source_module=module,
                    scan_id=scan_id,
                    evidence_type="harvested_email",
                    original_value=em,
                    normalized_value=em.strip().lower(),
                    source_file=src_file,
                    context={"tool": module},
                    timestamp_utc=ts
                )
                linked.append(ev)

        return linked

    def link_active_result(self, active_result: ActiveReconResult) -> List[EvidenceReference]:
        """Registers evidence from W3 active ActiveReconResult."""
        linked: List[EvidenceReference] = []
        scan_id = active_result.scan_id
        xml_file = active_result.raw_files.get("xml")
        xml_hash = active_result.file_hashes.get("xml")
        ts = active_result.start_time_utc

        for host in active_result.hosts:
            # Host observation
            ev_host = self.register_evidence(
                source_module="nmap",
                scan_id=scan_id,
                evidence_type="nmap_host_status",
                original_value=f"{host.address} ({host.status})",
                normalized_value=host.address,
                source_file=xml_file,
                sha256=xml_hash,
                context={"status": host.status, "reason": host.status_reason, "addrtype": host.addrtype},
                timestamp_utc=ts
            )
            linked.append(ev_host)

            # Hostnames
            for hn in host.hostnames:
                ev_hn = self.register_evidence(
                    source_module="nmap",
                    scan_id=scan_id,
                    evidence_type="nmap_reverse_hostname",
                    original_value=hn,
                    normalized_value=hn.strip().lower().rstrip("."),
                    source_file=xml_file,
                    sha256=xml_hash,
                    context={"ip": host.address},
                    timestamp_utc=ts
                )
                linked.append(ev_hn)

            # Ports & Services
            for port in host.ports:
                if port.state == "open":
                    ev_port = self.register_evidence(
                        source_module="nmap",
                        scan_id=scan_id,
                        evidence_type="nmap_open_port",
                        original_value=f"{port.protocol}/{port.portid}",
                        normalized_value=f"{port.protocol}:{port.portid}",
                        source_file=xml_file,
                        sha256=xml_hash,
                        context={"port": port.portid, "protocol": port.protocol, "reason": port.reason},
                        timestamp_utc=ts
                    )
                    linked.append(ev_port)

                    if port.service:
                        svc = port.service
                        ev_svc = self.register_evidence(
                            source_module="nmap",
                            scan_id=scan_id,
                            evidence_type="nmap_service_probe",
                            original_value=f"{port.portid}/{svc.name}:{svc.product or ''} {svc.version or ''}",
                            normalized_value=svc.name.strip().lower(),
                            source_file=xml_file,
                            sha256=xml_hash,
                            context={
                                "port": port.portid,
                                "protocol": port.protocol,
                                "product": svc.product,
                                "version": svc.version,
                                "cpe": svc.cpe,
                                "confidence": svc.conf
                            },
                            timestamp_utc=ts
                        )
                        linked.append(ev_svc)

                        for cpe_str in svc.cpe:
                            ev_cpe = self.register_evidence(
                                source_module="nmap",
                                scan_id=scan_id,
                                evidence_type="nmap_cpe_identifier",
                                original_value=cpe_str,
                                normalized_value=cpe_str.strip().lower(),
                                source_file=xml_file,
                                sha256=xml_hash,
                                context={"port": port.portid, "service": svc.name},
                                timestamp_utc=ts
                            )
                            linked.append(ev_cpe)

        return linked

    def get_all_evidence(self) -> List[EvidenceReference]:
        """Returns all registered EvidenceReference items sorted by evidence_id."""
        return sorted(self.registry.values(), key=lambda e: e.evidence_id)

    def find_evidence_by_type(self, evidence_type: str) -> List[EvidenceReference]:
        """Filters registered evidence by type."""
        return [e for e in self.registry.values() if e.evidence_type == evidence_type]

