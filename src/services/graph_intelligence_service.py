"""
FootprintIQ - Investigation Entity Graph & Maltego Interchange Service
Unifies passive OSINT, active Nmap services, vulnerability findings, manual
investigation entities, and Maltego-compatible GraphML / CSV / JSON interchange
using the existing Correlation Engine IntelligenceGraph foundation.
"""

import csv
import hashlib
import io
import json
import logging
import os
import re
import shutil
import time
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from xml.sax.saxutils import escape as xml_escape

from src.correlation.intelligence_graph import IntelligenceGraph
from src.db.repository import FootprintIQRepository
from src.services.recon_results_helper import load_campaign_results_bundle
from src.storage.seaweedfs_client import SeaweedFSClient

logger = logging.getLogger("FootprintIQ.GraphIntelligence")

MALTEGO_TYPE_MAP: Dict[str, str] = {
    "domain": "maltego.Domain",
    "subdomain": "maltego.DNSName",
    "ip": "maltego.IPv4Address",
    "ipv4": "maltego.IPv4Address",
    "ipv6": "maltego.IPv6Address",
    "email": "maltego.EmailAddress",
    "organization": "maltego.Company",
    "person": "maltego.Person",
    "nameserver": "maltego.NSRecord",
    "mx": "maltego.MXRecord",
    "service": "maltego.Service",
    "port": "maltego.Port",
    "url": "maltego.URL",
    "vulnerability": "maltego.Vulnerability",
    "asn": "maltego.AS",
}

MALTEGO_REVERSE_MAP: Dict[str, str] = {
    v.lower(): k for k, v in MALTEGO_TYPE_MAP.items() if k not in ("ipv4", "port")
}

ALLOWED_ENTITY_TYPES = set(MALTEGO_TYPE_MAP.keys())
MAX_IMPORT_BYTES = 2 * 1024 * 1024
_XML_DANGEROUS_DECL_RE = re.compile(r"<!\s*(DOCTYPE|ENTITY)\b", re.IGNORECASE)


def normalize_entity_type(raw_type: Optional[str], value: str = "") -> str:
    """Maps Maltego or FootprintIQ entity type labels to canonical internal types."""
    val = (raw_type or "domain").strip().lower()
    if val in MALTEGO_REVERSE_MAP:
        val = MALTEGO_REVERSE_MAP[val]
    if val in ("ipv4", "ipaddress", "ip_address"):
        val = "ip"
    if val == "ip" and ":" in (value or ""):
        return "ipv6"
    if val not in ALLOWED_ENTITY_TYPES:
        return "domain" if "." in (value or "") else "organization"
    return val


def to_maltego_type(entity_type: str, value: str = "") -> str:
    """Maps canonical FootprintIQ entity type to standard Maltego entity name."""
    etype = normalize_entity_type(entity_type, value)
    if etype == "ip" and ":" in (value or ""):
        return "maltego.IPv6Address"
    return MALTEGO_TYPE_MAP.get(etype, "maltego.Unknown")


def _make_node_id(entity_type: str, value: str) -> str:
    clean_val = str(value or "").strip()
    etype = normalize_entity_type(entity_type, clean_val)
    if etype in ("domain", "subdomain", "email", "nameserver", "mx", "ip", "ipv6"):
        norm_val = clean_val.lower()
    else:
        norm_val = clean_val
    digest = hashlib.sha256(f"{etype}|{norm_val}".encode("utf-8")).hexdigest()[:12]
    return f"ENT:{etype.upper()}:{digest}"


class GraphIntelligenceService:
    """
    Builds, queries, mutates, imports, and exports investigation entity-relationship
    graphs grounded in real campaign evidence and compatible with Maltego workflows.
    """

    def __init__(
        self,
        repo: Optional[FootprintIQRepository] = None,
        storage: Optional[SeaweedFSClient] = None,
    ):
        self.repo = repo or FootprintIQRepository()
        self.storage = storage or SeaweedFSClient()

    @staticmethod
    def get_maltego_runtime_status() -> Dict[str, Any]:
        """Accurately inspects whether Maltego desktop CLI is installed on the host."""
        binary = shutil.which("maltego")
        return {
            "available": True,
            "maltego_desktop_installed": bool(binary),
            "maltego_binary_path": binary,
            "mode": (
                "Maltego Desktop + Native Graph Interchange"
                if binary
                else "Native Correlation Graph + Maltego GraphML / CSV Interchange"
            ),
            "supported_exports": ["graphml", "csv", "json"],
            "supported_imports": ["graphml", "csv", "json"],
            "honesty_note": (
                "Native FootprintIQ Entity Graph & Correlation engine active. "
                + (
                    f"Maltego binary detected at {binary}."
                    if binary
                    else "Maltego CE desktop binary is not installed on host; live GUI transform automation is unavailable, while Maltego GraphML/CSV import and export work natively."
                )
            ),
        }

    def _load_overlay(self, investigation_id: str) -> Dict[str, Any]:
        """Loads latest persisted manual + imported entities and relationships from SeaweedFS/Evidence."""
        records = [
            e for e in self.repo.list_evidence(investigation_id=investigation_id)
            if e.get("evidence_type") == "intelligence_graph_overlay"
        ]
        if not records:
            return {"entities": [], "relationships": []}

        # Sort newest first across MSSQL (`created_at`) and fallback (`uploaded_at`) plus list order
        ordered = list(reversed(records))
        ordered.sort(
            key=lambda r: (
                str(r.get("created_at") or r.get("uploaded_at") or ""),
                str(r.get("evidence_id") or ""),
            ),
            reverse=True,
        )

        best_payload: Optional[Dict[str, Any]] = None
        best_rev = -1
        for rec in ordered:
            payload = self._read_evidence_json(rec)
            if isinstance(payload, dict):
                rev = int(payload.get("revision_ns") or 0)
                if best_payload is None or rev > best_rev:
                    best_payload = payload
                    best_rev = rev
                if rev == 0 and best_payload is not None:
                    break

        if isinstance(best_payload, dict):
            return {
                "entities": list(best_payload.get("entities") or []),
                "relationships": list(best_payload.get("relationships") or []),
            }
        return {"entities": [], "relationships": []}

    def _read_evidence_json(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        local_path = ev.get("local_path")
        if local_path and os.path.isfile(local_path):
            try:
                with open(local_path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except Exception:
                pass
        fid = ev.get("seaweed_fid")
        if fid and self.storage:
            try:
                raw = self.storage.download_content(fid)
                if raw:
                    return json.loads(raw.decode("utf-8"))
            except Exception:
                pass
        return None

    def _save_overlay(
        self,
        investigation_id: str,
        overlay: Dict[str, Any],
        scan_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        rev_ns = time.time_ns()
        payload = {
            "entities": list(overlay.get("entities") or []),
            "relationships": list(overlay.get("relationships") or []),
            "revision_ns": rev_ns,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        raw_bytes = json.dumps(payload, indent=2).encode("utf-8")
        ev = self.storage.upload_content(
            content=raw_bytes,
            file_name=f"graph_overlay_{investigation_id}_{rev_ns}.json",
            investigation_id=investigation_id,
            evidence_type="intelligence_graph_overlay",
            content_type="application/json",
        )
        self.repo.add_evidence_record(
            investigation_id=investigation_id,
            evidence_type="intelligence_graph_overlay",
            file_name=ev["file_name"],
            file_size=ev["file_size"],
            sha256_hash=ev["sha256_hash"],
            seaweed_fid=ev.get("seaweed_fid"),
            seaweed_url=ev.get("seaweed_url"),
            local_path=ev.get("local_path"),
            scan_id=scan_id,
        )
        return ev

    def build_investigation_graph(self, investigation_id: str) -> Dict[str, Any]:
        """Constructs the unified entity-relationship graph for an investigation/campaign."""
        campaign = self.repo.get_recon_campaign(investigation_id) or self.repo.get_investigation(investigation_id)
        if not campaign:
            raise ValueError(f"Investigation '{investigation_id}' not found.")

        bundle = load_campaign_results_bundle(investigation_id, self.repo)
        findings = self.repo.list_findings(investigation_id=investigation_id)
        evidence_list = self.repo.list_evidence(investigation_id=investigation_id)
        overlay = self._load_overlay(investigation_id)

        graph = IntelligenceGraph()
        evidence_lookup = {
            str(ev.get("evidence_type") or ""): (ev.get("seaweed_fid") or ev.get("file_name") or ev.get("evidence_id"))
            for ev in evidence_list
        }

        target_val = str(campaign.get("target_value") or "").strip()
        target_type_raw = str(campaign.get("target_type") or "").strip().lower()
        root_id: Optional[str] = None
        if target_val:
            root_type = "ip" if target_type_raw in ("ip", "ipv4", "cidr") or re.match(r"^\d+\.\d+\.\d+\.\d+$", target_val) else "domain"
            root_id = self._add_entity_to_graph(
                graph,
                entity_type=root_type,
                value=target_val,
                label=target_val,
                source_tool="campaign_scope",
                risk_level="info",
                confidence=1.0,
                evidence_ref=f"campaign:{investigation_id}",
                attributes={"scope_role": "primary_target", "campaign_name": campaign.get("name")},
            )

        # 1. Passive Reconnaissance & OSINT entities
        for pr in bundle.get("passive_results") or []:
            p_target = str(pr.get("target") or target_val).strip()
            p_root_type = "ip" if re.match(r"^\d+\.\d+\.\d+\.\d+$", p_target) else "domain"
            p_root_id = self._add_entity_to_graph(
                graph,
                entity_type=p_root_type,
                value=p_target,
                label=p_target,
                source_tool="passive_recon",
                risk_level="info",
                confidence=0.95,
                evidence_ref=evidence_lookup.get("passive_summary") or evidence_lookup.get("recon_results_json") or f"passive:{p_target}",
            )

            dom = pr.get("domain_intel") or {}
            osint = pr.get("osint_intel") or {}
            infra = pr.get("infrastructure_intel") or {}
            whois = dom.get("whois") or {}

            # WHOIS Registrar / Organization
            org_name = str(whois.get("organization") or whois.get("org") or "").strip()
            registrar = str(whois.get("registrar") or "").strip()
            if org_name and org_name.lower() not in ("redacted for privacy", "n/a", "none"):
                oid = self._add_entity_to_graph(
                    graph, "organization", org_name, org_name,
                    source_tool="whois_rdap", confidence=0.85,
                    evidence_ref=f"whois:{p_target}",
                    attributes={"registrar": registrar} if registrar else {},
                )
                self._add_edge_to_graph(graph, p_root_id, oid, "OWNED_BY", weight=0.9, confidence=0.85, evidence_ids=[f"whois:{p_target}"])
            if registrar and registrar.lower() not in ("n/a", "none"):
                rid = self._add_entity_to_graph(
                    graph, "organization", f"Registrar: {registrar}", registrar,
                    source_tool="whois_rdap", confidence=0.90,
                    evidence_ref=f"whois:{p_target}",
                    attributes={"role": "registrar"},
                )
                self._add_edge_to_graph(graph, p_root_id, rid, "REGISTERED_WITH", weight=0.85, confidence=0.90, evidence_ids=[f"whois:{p_target}"])

            # Subdomains
            for sub in (dom.get("subdomains") or [])[:150]:
                sval = str(sub).strip().lower()
                if not sval:
                    continue
                sid = self._add_entity_to_graph(
                    graph, "subdomain", sval, sval,
                    source_tool="theharvester_dns", confidence=0.82,
                    evidence_ref=f"passive_subdomains:{p_target}",
                )
                self._add_edge_to_graph(graph, p_root_id, sid, "HAS_SUBDOMAIN", weight=0.8, confidence=0.82, evidence_ids=[f"passive:{p_target}"])

            # DNS records (NS, MX, A, AAAA)
            dns_recs = dom.get("dns_records") or dom.get("records") or {}
            if isinstance(dns_recs, dict):
                for ns in (dns_recs.get("NS") or dns_recs.get("ns") or [])[:20]:
                    nval = str(ns).rstrip(".").strip().lower()
                    if nval:
                        nid = self._add_entity_to_graph(graph, "nameserver", nval, nval, source_tool="dns_osint", confidence=0.95, evidence_ref=f"dns_ns:{p_target}")
                        self._add_edge_to_graph(graph, p_root_id, nid, "USES_NAMESERVER", weight=0.9, confidence=0.95, evidence_ids=[f"dns_ns:{p_target}"])
                for mx in (dns_recs.get("MX") or dns_recs.get("mx") or [])[:20]:
                    mval = str(mx).split()[-1].rstrip(".").strip().lower()
                    if mval:
                        mid = self._add_entity_to_graph(graph, "mx", mval, mval, source_tool="dns_osint", confidence=0.95, evidence_ref=f"dns_mx:{p_target}")
                        self._add_edge_to_graph(graph, p_root_id, mid, "ROUTES_MAIL_TO", weight=0.9, confidence=0.95, evidence_ids=[f"dns_mx:{p_target}"])
                for ip_key in ("A", "a", "AAAA", "aaaa"):
                    for ip_item in (dns_recs.get(ip_key) or [])[:30]:
                        ival = str(ip_item).strip()
                        if ival:
                            iid = self._add_entity_to_graph(graph, "ip", ival, ival, source_tool="dns_osint", confidence=0.95, evidence_ref=f"dns_{ip_key}:{p_target}")
                            self._add_edge_to_graph(graph, p_root_id, iid, "RESOLVES_TO", weight=0.95, confidence=0.95, evidence_ids=[f"dns:{p_target}"])

            for ip_item in (infra.get("resolved_ips") or [])[:40]:
                ival = str(ip_item).strip()
                if ival:
                    iid = self._add_entity_to_graph(graph, "ip", ival, ival, source_tool="dns_osint", confidence=0.92, evidence_ref=f"infra:{p_target}")
                    self._add_edge_to_graph(graph, p_root_id, iid, "RESOLVES_TO", weight=0.9, confidence=0.92, evidence_ids=[f"infra:{p_target}"])

            # OSINT Emails & Personnel
            for email_item in (osint.get("emails") or [])[:80]:
                eval_str = str(email_item).strip().lower()
                if "@" in eval_str:
                    eid = self._add_entity_to_graph(graph, "email", eval_str, eval_str, source_tool="theharvester", confidence=0.80, evidence_ref=f"theharvester:{p_target}")
                    self._add_edge_to_graph(graph, p_root_id, eid, "ASSOCIATED_EMAIL", weight=0.8, confidence=0.80, evidence_ids=[f"theharvester:{p_target}"])

            for emp in (osint.get("employees") or osint.get("people") or [])[:50]:
                emp_name = str(emp.get("name") if isinstance(emp, dict) else emp).strip()
                if emp_name:
                    pid = self._add_entity_to_graph(graph, "person", emp_name, emp_name, source_tool="theharvester", confidence=0.75, evidence_ref=f"theharvester:{p_target}")
                    self._add_edge_to_graph(graph, p_root_id, pid, "ASSOCIATED_PERSON", weight=0.75, confidence=0.75, evidence_ids=[f"theharvester:{p_target}"])

        # 2. Active Network Hosts & Discovered Services (Nmap)
        ip_node_map: Dict[str, str] = {}
        svc_node_map: Dict[Tuple[str, int], str] = {}

        for h in bundle.get("active_hosts") or []:
            hip = str(h.get("ip") or h.get("target") or "").strip()
            if not hip:
                continue
            hid = self._add_entity_to_graph(
                graph, "ip", hip, hip,
                source_tool="nmap", confidence=0.98,
                evidence_ref=evidence_lookup.get("nmap_xml") or f"nmap:{hip}",
                attributes={"hostname": h.get("hostname"), "os": h.get("os")},
            )
            ip_node_map[hip] = hid
            if root_id and root_id != hid:
                self._add_edge_to_graph(graph, root_id, hid, "RESOLVES_TO", weight=0.95, confidence=0.95, evidence_ids=[f"nmap:{hip}"])

        for p in bundle.get("discovered_ports") or []:
            pip = str(p.get("target_ip") or p.get("ip") or target_val).strip()
            try:
                pnum = int(p.get("port"))
            except (TypeError, ValueError):
                continue
            proto = str(p.get("protocol") or "tcp").lower()
            svc = str(p.get("service") or "unknown").strip()
            ver = str(p.get("service_version") or "").strip()

            hid = ip_node_map.get(pip) or self._add_entity_to_graph(
                graph, "ip", pip, pip, source_tool="nmap", confidence=0.98,
                evidence_ref=evidence_lookup.get("nmap_xml") or f"nmap:{pip}",
            )
            ip_node_map[pip] = hid
            if root_id and root_id != hid:
                self._add_edge_to_graph(graph, root_id, hid, "RESOLVES_TO", weight=0.95, confidence=0.95, evidence_ids=[f"nmap:{pip}"])

            svc_key_val = f"{pip}:{pnum}/{proto} ({svc})"
            svc_label = f"{pnum}/{proto} {svc}" + (f" [{ver[:24]}]" if ver else "")
            sid = self._add_entity_to_graph(
                graph, "service", svc_key_val, svc_label,
                source_tool="nmap", risk_level="low", confidence=0.95,
                evidence_ref=evidence_lookup.get("nmap_xml") or f"nmap:{pip}:{pnum}",
                attributes={"host": pip, "port": pnum, "protocol": proto, "service": svc, "version": ver},
            )
            svc_node_map[(pip, pnum)] = sid
            self._add_edge_to_graph(graph, hid, sid, "EXPOSES_SERVICE", weight=0.95, confidence=0.95, evidence_ids=[f"nmap:{pip}:{pnum}"])

        # 3. Findings (Nuclei, NSE, Nessus, historical Greenbone/OpenVAS)
        for f in findings:
            f_id = str(f.get("finding_id") or "")
            f_ip = str(f.get("target_ip") or target_val).strip()
            f_host = str(f.get("hostname") or "").strip()
            f_port = f.get("port")
            f_sev = str(f.get("severity") or "Informational").lower()
            f_src = str(f.get("detection_source") or "scanner").lower()
            f_title = str(f.get("title") or "Security Observation").strip()
            f_cve = str(f.get("cve_identifiers") or "").strip()
            f_ev = str(f.get("evidence_reference") or f"finding:{f_id}")

            risk_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
            risk_lvl = risk_map.get(f_sev, "info")

            if f_ip:
                hid = ip_node_map.get(f_ip) or self._add_entity_to_graph(
                    graph,
                    "ip" if re.match(r"^[\d.:]+$", f_ip) else "domain",
                    f_ip,
                    f_ip,
                    source_tool=f_src,
                    confidence=0.90,
                    evidence_ref=f_ev,
                )
                ip_node_map[f_ip] = hid
                if root_id and root_id != hid:
                    self._add_edge_to_graph(graph, root_id, hid, "RESOLVES_TO", weight=0.9, confidence=0.9, evidence_ids=[f_ev])
            else:
                hid = root_id

            if f_host and f_host != f_ip and "." in f_host:
                sub_id = self._add_entity_to_graph(graph, "subdomain", f_host, f_host, source_tool=f_src, confidence=0.85, evidence_ref=f_ev)
                if root_id and root_id != sub_id:
                    self._add_edge_to_graph(graph, root_id, sub_id, "HAS_HOST", weight=0.8, confidence=0.85, evidence_ids=[f_ev])

            parent_id = hid
            if f_port is not None and str(f_port).isdigit():
                pnum = int(f_port)
                if (f_ip, pnum) not in svc_node_map:
                    svc_name = str(f.get("service") or "service")
                    proto = str(f.get("protocol") or "tcp")
                    sid = self._add_entity_to_graph(
                        graph, "service", f"{f_ip}:{pnum}/{proto} ({svc_name})", f"{pnum}/{proto} {svc_name}",
                        source_tool=f_src, risk_level="low", confidence=0.90, evidence_ref=f_ev,
                        attributes={"host": f_ip, "port": pnum, "protocol": proto, "service": svc_name},
                    )
                    svc_node_map[(f_ip, pnum)] = sid
                    if hid:
                        self._add_edge_to_graph(graph, hid, sid, "EXPOSES_SERVICE", weight=0.9, confidence=0.9, evidence_ids=[f_ev])
                parent_id = svc_node_map[(f_ip, pnum)]

            v_val = f_cve or f_id or f_title
            v_id = self._add_entity_to_graph(
                graph, "vulnerability", f"{v_val}|{f_ip}|{f_port}|{f_title}",
                f"[{f_sev.upper()}] {f_title[:60]}",
                source_tool=f_src,
                risk_level=risk_lvl,
                confidence=float(f.get("confidence") or 0.85),
                evidence_ref=f_ev,
                attributes={"finding_id": f_id, "cve": f_cve or None, "cvss": f.get("cvss_score"), "severity": f.get("severity")},
            )
            if parent_id:
                self._add_edge_to_graph(graph, parent_id, v_id, "EXPOSES_VULNERABILITY", weight=1.0, confidence=float(f.get("confidence") or 0.85), evidence_ids=[f_ev])

        # 4. Merge Custom / Imported Overlay Entities & Relationships
        overlay_id_map: Dict[str, str] = {}
        for item in overlay.get("entities") or []:
            etype = normalize_entity_type(item.get("entity_type"), str(item.get("value") or ""))
            val = str(item.get("value") or "").strip()
            if not val:
                continue
            nid = self._add_entity_to_graph(
                graph,
                entity_type=etype,
                value=val,
                label=str(item.get("label") or val),
                source_tool=str(item.get("source_tool") or "analyst_manual"),
                risk_level=str(item.get("risk_level") or "info"),
                confidence=float(item.get("confidence") or 0.80),
                evidence_ref=str(item.get("evidence_ref") or "manual_analyst_entry"),
                attributes=item.get("attributes") if isinstance(item.get("attributes"), dict) else {},
                explicit_id=item.get("node_id"),
            )
            if item.get("node_id"):
                overlay_id_map[str(item["node_id"])] = nid

        for rel in overlay.get("relationships") or []:
            src = overlay_id_map.get(str(rel.get("source")), str(rel.get("source") or ""))
            tgt = overlay_id_map.get(str(rel.get("target")), str(rel.get("target") or ""))
            if src in graph.nodes and tgt in graph.nodes:
                self._add_edge_to_graph(
                    graph,
                    src,
                    tgt,
                    relationship=str(rel.get("relationship") or "RELATED_TO").upper().replace(" ", "_"),
                    weight=float(rel.get("weight") or 0.8),
                    confidence=float(rel.get("confidence") or 0.8),
                    evidence_ids=[str(rel.get("evidence_ref") or "manual_relationship")],
                )

        serialized = graph.to_dict()
        # Normalize node & edge attributes cleanly for frontend/Maltego exports
        nodes = serialized.get("nodes") or []
        edges = serialized.get("edges") or []
        metrics = dict(serialized.get("metrics") or {"node_count": len(nodes), "edge_count": len(edges)})
        metrics.setdefault("component_count", metrics.get("connected_component_count", len(serialized.get("components") or [])))

        type_counts = Counter()
        source_counts = Counter()
        for n in nodes:
            attrs = n.get("attributes") or {}
            etype = str(n.get("type") or "domain")
            src_tool = str(attrs.get("source_tool") or "correlation")
            n["entity_type"] = etype
            n["maltego_type"] = attrs.get("maltego_type") or to_maltego_type(etype, str(attrs.get("value") or n.get("label") or ""))
            n["source_tool"] = src_tool
            n["evidence_ref"] = attrs.get("evidence_ref") or ""
            n["value"] = attrs.get("value") or n.get("label")
            n["risk_level"] = n.get("risk_level") or attrs.get("risk_level") or "info"
            n["confidence"] = float(n.get("confidence") or attrs.get("confidence") or 0.85)
            type_counts[etype] += 1
            source_counts[src_tool] += 1

        for e in edges:
            e["relationship"] = str(e.get("relationship") or e.get("relationship_type") or "RELATED_TO")
            e["confidence"] = float(e.get("confidence_score") or (e.get("confidence") if isinstance(e.get("confidence"), (int, float)) else 0.85))

        return {
            "investigation_id": investigation_id,
            "campaign_name": campaign.get("name") or campaign.get("title"),
            "target": target_val,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "metrics": metrics,
            "entity_type_counts": dict(type_counts),
            "source_breakdown": dict(source_counts),
            "nodes": nodes,
            "edges": edges,
            "components": serialized.get("components") or [],
            "isolated_nodes": serialized.get("isolated_nodes") or [],
            "maltego_integration": self.get_maltego_runtime_status(),
        }

    @staticmethod
    def _add_entity_to_graph(
        graph: IntelligenceGraph,
        entity_type: str,
        value: str,
        label: str,
        source_tool: str,
        risk_level: str = "info",
        confidence: float = 0.85,
        evidence_ref: str = "",
        attributes: Optional[Dict[str, Any]] = None,
        explicit_id: Optional[str] = None,
    ) -> str:
        clean_val = str(value).strip()
        etype = normalize_entity_type(entity_type, clean_val)
        nid = explicit_id if (explicit_id and explicit_id in graph.nodes) else _make_node_id(etype, clean_val)
        merged_attrs = dict(attributes or {})
        merged_attrs.update({
            "value": clean_val,
            "source_tool": source_tool,
            "evidence_ref": evidence_ref,
            "risk_level": risk_level,
            "confidence": float(confidence),
            "maltego_type": to_maltego_type(etype, clean_val),
        })
        now_iso = datetime.now(timezone.utc).isoformat()
        existing = graph.nodes.get(nid)
        if existing:
            sources = list(dict.fromkeys(list(existing.get("sources") or []) + [source_tool]))
            existing_attrs = dict(existing.get("attributes") or {})
            existing_attrs.update(merged_attrs)
            merged_attrs = existing_attrs
        else:
            sources = [source_tool]

        graph.nodes[nid] = {
            "id": nid,
            "type": etype,
            "label": label[:120],
            "canonical_value": clean_val,
            "tags": [],
            "sources": sources,
            "risk_level": risk_level,
            "confidence": float(confidence),
            "attributes": merged_attrs,
            "first_seen": (existing or {}).get("first_seen", now_iso),
            "last_seen": now_iso,
        }
        graph.adjacency.setdefault(nid, set())
        return nid

    @staticmethod
    def _add_edge_to_graph(
        graph: IntelligenceGraph,
        source_id: str,
        target_id: str,
        relationship: str = "RELATED_TO",
        weight: float = 0.85,
        confidence: float = 0.85,
        evidence_ids: Optional[List[str]] = None,
    ) -> None:
        rel_name = str(relationship or "RELATED_TO").strip().upper().replace(" ", "_")
        edge_key = f"{source_id}->{rel_name}->{target_id}"
        now_iso = datetime.now(timezone.utc).isoformat()
        conf_val = max(0.0, min(float(confidence or 0.85), 1.0))
        rel_id = hashlib.sha256(edge_key.encode("utf-8")).hexdigest()[:12]
        graph.edges[edge_key] = {
            "id": f"REL:{rel_id}",
            "source": source_id,
            "target": target_id,
            "relationship_type": rel_name,
            "relationship": rel_name,
            "weight": float(weight),
            "confidence": conf_val,
            "confidence_score": conf_val,
            "evidence_ids": list(evidence_ids or []),
            "first_observed": now_iso,
            "last_observed": now_iso,
        }
        graph.adjacency[source_id].add(target_id)
        graph.reverse_adjacency[target_id].add(source_id)

    def add_manual_entity(
        self,
        investigation_id: str,
        entity_type: str,
        value: str,
        label: Optional[str] = None,
        source_tool: str = "analyst_manual",
        evidence_ref: Optional[str] = None,
        risk_level: str = "info",
        confidence: float = 0.85,
        attributes: Optional[Dict[str, Any]] = None,
        link_to_node_id: Optional[str] = None,
        relationship_type: str = "RELATED_TO",
        added_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Adds an entity (and optional edge) to the persistent investigation graph overlay."""
        clean_val = (value or "").strip()
        if not clean_val:
            raise ValueError("Entity value cannot be empty.")

        current_graph = self.build_investigation_graph(investigation_id)
        overlay = self._load_overlay(investigation_id)

        etype = normalize_entity_type(entity_type, clean_val)
        nid = _make_node_id(etype, clean_val)

        attrs = dict(attributes or {})
        if added_by:
            attrs["added_by"] = added_by

        entry = {
            "node_id": nid,
            "entity_type": etype,
            "maltego_type": to_maltego_type(etype, clean_val),
            "value": clean_val,
            "label": (label or clean_val).strip()[:120],
            "source_tool": (source_tool or "analyst_manual").strip(),
            "evidence_ref": (evidence_ref or f"manual:{investigation_id}").strip(),
            "risk_level": risk_level if risk_level in ("critical", "high", "medium", "low", "info") else "info",
            "confidence": max(0.1, min(float(confidence or 0.85), 1.0)),
            "attributes": attrs,
        }

        existing = [e for e in overlay["entities"] if e.get("node_id") == nid]
        if not existing:
            overlay["entities"].append(entry)

        if link_to_node_id:
            valid_nodes = {n["id"] for n in current_graph["nodes"]} | {nid}
            if link_to_node_id in valid_nodes:
                overlay["relationships"].append({
                    "source": link_to_node_id,
                    "target": nid,
                    "relationship": (relationship_type or "RELATED_TO").strip().upper().replace(" ", "_"),
                    "confidence": entry["confidence"],
                    "evidence_ref": entry["evidence_ref"],
                })

        self._save_overlay(investigation_id, overlay)
        return {"entity": entry, "graph": self.build_investigation_graph(investigation_id)}

    def add_manual_relationship(
        self,
        investigation_id: str,
        source_node_id: str,
        target_node_id: str,
        relationship_type: str = "RELATED_TO",
        evidence_ref: Optional[str] = None,
        confidence: float = 0.85,
        added_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Connects two existing investigation graph nodes with an attributed relationship."""
        graph = self.build_investigation_graph(investigation_id)
        node_ids = {n["id"] for n in graph["nodes"]}
        if source_node_id not in node_ids or target_node_id not in node_ids:
            raise ValueError("Both source and target nodes must exist in the investigation graph.")

        rel_name = (relationship_type or "RELATED_TO").strip().upper().replace(" ", "_")
        if not rel_name:
            raise ValueError("Relationship type is required.")

        overlay = self._load_overlay(investigation_id)
        rel_rec = {
            "source": source_node_id,
            "target": target_node_id,
            "relationship": rel_name,
            "confidence": max(0.1, min(float(confidence or 0.85), 1.0)),
            "evidence_ref": (evidence_ref or f"manual_link:{added_by or 'analyst'}").strip(),
        }
        overlay["relationships"].append(rel_rec)
        self._save_overlay(investigation_id, overlay)
        return {"relationship": rel_rec, "graph": self.build_investigation_graph(investigation_id)}

    def export_graph(self, investigation_id: str, fmt: str = "graphml") -> Tuple[bytes, str, str]:
        """Exports the investigation graph as GraphML, Maltego CSV, or JSON."""
        graph = self.build_investigation_graph(investigation_id)
        clean_fmt = (fmt or "graphml").strip().lower()
        safe_inv = re.sub(r"[^A-Za-z0-9_-]", "_", investigation_id)

        if clean_fmt == "json":
            payload = json.dumps(graph, indent=2).encode("utf-8")
            return payload, f"FootprintIQ_{safe_inv}_graph.json", "application/json"

        if clean_fmt == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow([
                "section",
                "id",
                "entity_type",
                "maltego_type",
                "value",
                "label",
                "source_tool",
                "risk_level",
                "confidence",
                "evidence_ref",
            ])

            for n in graph["nodes"]:
                writer.writerow([
                    "entity",
                    n["id"],
                    n["entity_type"],
                    n["maltego_type"],
                    n.get("value", n.get("label", "")),
                    n.get("label", ""),
                    n.get("source_tool", ""),
                    n.get("risk_level", "info"),
                    n.get("confidence", 0.5),
                    n.get("evidence_ref", ""),
                ])

            for e in graph["edges"]:
                writer.writerow([
                    "edge",
                    e["source"],
                    e.get("relationship", "RELATED_TO"),
                    e["target"],
                    ",".join(e.get("evidence_ids") or []) if isinstance(e.get("evidence_ids"), list) else str(e.get("evidence_ids") or ""),
                    "",
                    "correlation",
                    "info",
                    e.get("confidence", 0.85),
                    ",".join(e.get("evidence_ids") or []) if isinstance(e.get("evidence_ids"), list) else str(e.get("evidence_ids") or ""),
                ])
            return buf.getvalue().encode("utf-8"), f"FootprintIQ_{safe_inv}_maltego_entities.csv", "text/csv"

        if clean_fmt == "graphml":
            lines = [
                '<?xml version="1.0" encoding="UTF-8"?>',
                '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
                '  <key id="d0" for="node" attr.name="label" attr.type="string"/>',
                '  <key id="d1" for="node" attr.name="entity_type" attr.type="string"/>',
                '  <key id="d2" for="node" attr.name="maltego_type" attr.type="string"/>',
                '  <key id="d3" for="node" attr.name="value" attr.type="string"/>',
                '  <key id="d4" for="node" attr.name="source_tool" attr.type="string"/>',
                '  <key id="d5" for="node" attr.name="risk_level" attr.type="string"/>',
                '  <key id="d6" for="node" attr.name="confidence" attr.type="double"/>',
                '  <key id="d7" for="node" attr.name="evidence_ref" attr.type="string"/>',
                '  <key id="d8" for="edge" attr.name="relationship" attr.type="string"/>',
                '  <key id="d9" for="edge" attr.name="confidence" attr.type="double"/>',
                f'  <graph id="{xml_escape(safe_inv)}" edgedefault="directed">',
            ]
            for n in graph["nodes"]:
                nid = xml_escape(str(n["id"]))
                lines.append(f'    <node id="{nid}">')
                lines.append(f'      <data key="d0">{xml_escape(str(n.get("label", "")))}</data>')
                lines.append(f'      <data key="d1">{xml_escape(str(n.get("entity_type", "")))}</data>')
                lines.append(f'      <data key="d2">{xml_escape(str(n.get("maltego_type", "")))}</data>')
                lines.append(f'      <data key="d3">{xml_escape(str(n.get("value", "")))}</data>')
                lines.append(f'      <data key="d4">{xml_escape(str(n.get("source_tool", "")))}</data>')
                lines.append(f'      <data key="d5">{xml_escape(str(n.get("risk_level", "info")))}</data>')
                lines.append(f'      <data key="d6">{float(n.get("confidence") or 0.5)}</data>')
                lines.append(f'      <data key="d7">{xml_escape(str(n.get("evidence_ref", "")))}</data>')
                lines.append("    </node>")

            for idx, e in enumerate(graph["edges"]):
                lines.append(
                    f'    <edge id="e{idx}" source="{xml_escape(str(e["source"]))}" target="{xml_escape(str(e["target"]))}">'
                )
                lines.append(f'      <data key="d8">{xml_escape(str(e.get("relationship", "RELATED_TO")))}</data>')
                lines.append(f'      <data key="d9">{float(e.get("confidence") or 0.5)}</data>')
                lines.append("    </edge>")

            lines.append("  </graph>")
            lines.append("</graphml>")
            return "\n".join(lines).encode("utf-8"), f"FootprintIQ_{safe_inv}_graph.graphml", "application/xml"

        raise ValueError(f"Unsupported graph export format '{fmt}'. Use graphml, csv, or json.")

    def import_graph_file(
        self,
        investigation_id: str,
        filename: str,
        content_bytes: bytes,
        imported_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Safely parses an uploaded Maltego GraphML, CSV, or JSON graph export
        and merges its entities and relationships into the investigation overlay.
        """
        if not content_bytes:
            raise ValueError("Uploaded graph file is empty.")
        if len(content_bytes) > MAX_IMPORT_BYTES:
            raise ValueError(f"Graph file exceeds maximum allowed size of {MAX_IMPORT_BYTES // (1024 * 1024)} MB.")

        # Validate investigation exists
        self.build_investigation_graph(investigation_id)

        lower_name = (filename or "").strip().lower()
        text = content_bytes.decode("utf-8", errors="strict")

        imported_entities: List[Dict[str, Any]] = []
        imported_edges: List[Dict[str, Any]] = []

        if lower_name.endswith(".graphml") or lower_name.endswith(".xml") or text.lstrip().startswith("<?xml") or "<graphml" in text[:400]:
            imported_entities, imported_edges = self._parse_graphml_import(text, investigation_id, imported_by)
        elif lower_name.endswith(".json") or text.lstrip().startswith("{"):
            imported_entities, imported_edges = self._parse_json_import(text, investigation_id, imported_by)
        elif lower_name.endswith(".csv"):
            imported_entities, imported_edges = self._parse_csv_import(text, investigation_id, imported_by)
        else:
            raise ValueError("Unsupported file format. Please upload .graphml, .csv, or .json.")

        if not imported_entities and not imported_edges:
            raise ValueError("No valid entities or relationships were found in the uploaded file.")

        # Archive raw imported file as SeaweedFS EvidenceRecord
        ev = self.storage.upload_content(
            content=content_bytes,
            file_name=os.path.basename(filename or "maltego_import.graphml"),
            investigation_id=investigation_id,
            evidence_type="maltego_import",
            content_type="application/octet-stream",
        )
        self.repo.add_evidence_record(
            investigation_id=investigation_id,
            evidence_type="maltego_import",
            file_name=ev["file_name"],
            file_size=ev["file_size"],
            sha256_hash=ev["sha256_hash"],
            seaweed_fid=ev.get("seaweed_fid"),
            seaweed_url=ev.get("seaweed_url"),
            local_path=ev.get("local_path"),
        )

        overlay = self._load_overlay(investigation_id)
        existing_ids = {e.get("node_id") for e in overlay["entities"]}
        added_nodes = 0
        for ent in imported_entities:
            if ent["node_id"] not in existing_ids:
                overlay["entities"].append(ent)
                existing_ids.add(ent["node_id"])
                added_nodes += 1

        overlay["relationships"].extend(imported_edges)
        self._save_overlay(investigation_id, overlay)

        return {
            "imported_entities": added_nodes,
            "total_parsed_entities": len(imported_entities),
            "imported_relationships": len(imported_edges),
            "evidence_file": ev["file_name"],
            "graph": self.build_investigation_graph(investigation_id),
        }

    def _parse_graphml_import(
        self,
        xml_text: str,
        investigation_id: str,
        imported_by: Optional[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        if _XML_DANGEROUS_DECL_RE.search(xml_text):
            raise ValueError("XML security policy violation: DOCTYPE and ENTITY declarations are not permitted.")
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise ValueError(f"Malformed GraphML XML: {exc}")

        def _strip_ns(tag: str) -> str:
            return tag.split("}", 1)[-1] if "}" in tag else tag

        key_map: Dict[str, str] = {}
        for elem in root.iter():
            if _strip_ns(elem.tag) == "key":
                kid = elem.attrib.get("id")
                kname = elem.attrib.get("attr.name")
                if kid and kname:
                    key_map[kid] = kname.strip().lower()

        entities: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        id_remap: Dict[str, str] = {}

        for elem in root.iter():
            tag = _strip_ns(elem.tag)
            if tag == "node":
                raw_id = elem.attrib.get("id") or ""
                data_attrs: Dict[str, str] = {}
                for child in elem:
                    if _strip_ns(child.tag) == "data":
                        k = key_map.get(child.attrib.get("key", ""), child.attrib.get("key", "")).lower()
                        data_attrs[k] = (child.text or "").strip()

                val = data_attrs.get("value") or data_attrs.get("label") or raw_id
                if not val:
                    continue
                etype = normalize_entity_type(data_attrs.get("maltego_type") or data_attrs.get("entity_type"), val)
                nid = _make_node_id(etype, val)
                if raw_id:
                    id_remap[raw_id] = nid
                try:
                    conf = max(0.1, min(float(data_attrs.get("confidence") or 0.8), 1.0))
                except ValueError:
                    conf = 0.8
                entities.append({
                    "node_id": nid,
                    "entity_type": etype,
                    "maltego_type": to_maltego_type(etype, val),
                    "value": val,
                    "label": (data_attrs.get("label") or val)[:120],
                    "source_tool": data_attrs.get("source_tool") or "maltego_import",
                    "evidence_ref": data_attrs.get("evidence_ref") or f"maltego_import:{investigation_id}",
                    "risk_level": data_attrs.get("risk_level") or "info",
                    "confidence": conf,
                    "attributes": {"imported_by": imported_by or "analyst"},
                })

            elif tag == "edge":
                src = id_remap.get(elem.attrib.get("source", ""), elem.attrib.get("source", ""))
                tgt = id_remap.get(elem.attrib.get("target", ""), elem.attrib.get("target", ""))
                if not src or not tgt:
                    continue
                e_attrs: Dict[str, str] = {}
                for child in elem:
                    if _strip_ns(child.tag) == "data":
                        k = key_map.get(child.attrib.get("key", ""), child.attrib.get("key", "")).lower()
                        e_attrs[k] = (child.text or "").strip()
                edges.append({
                    "source": src,
                    "target": tgt,
                    "relationship": (e_attrs.get("relationship") or "RELATED_TO").upper().replace(" ", "_"),
                    "confidence": 0.8,
                    "evidence_ref": f"maltego_import:{investigation_id}",
                })

        return entities, edges

    def _parse_json_import(
        self,
        json_text: str,
        investigation_id: str,
        imported_by: Optional[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        try:
            data = json.loads(json_text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON graph file: {exc}")
        if not isinstance(data, dict):
            raise ValueError("JSON graph file must be an object with 'nodes' and optional 'edges'.")

        raw_nodes = data.get("nodes") or data.get("entities") or []
        raw_edges = data.get("edges") or data.get("relationships") or []
        entities: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        id_remap: Dict[str, str] = {}

        for n in raw_nodes[:500]:
            if not isinstance(n, dict):
                continue
            val = str(n.get("value") or n.get("label") or "").strip()
            if not val:
                continue
            etype = normalize_entity_type(n.get("maltego_type") or n.get("entity_type") or n.get("type"), val)
            nid = _make_node_id(etype, val)
            if n.get("id"):
                id_remap[str(n["id"])] = nid
            entities.append({
                "node_id": nid,
                "entity_type": etype,
                "maltego_type": to_maltego_type(etype, val),
                "value": val,
                "label": str(n.get("label") or val)[:120],
                "source_tool": str(n.get("source_tool") or "maltego_import"),
                "evidence_ref": str(n.get("evidence_ref") or f"maltego_import:{investigation_id}"),
                "risk_level": str(n.get("risk_level") or "info"),
                "confidence": max(0.1, min(float(n.get("confidence") or 0.8), 1.0)),
                "attributes": {"imported_by": imported_by or "analyst"},
            })

        for e in raw_edges[:1000]:
            if not isinstance(e, dict):
                continue
            src = id_remap.get(str(e.get("source", "")), str(e.get("source") or ""))
            tgt = id_remap.get(str(e.get("target", "")), str(e.get("target") or ""))
            if src and tgt:
                edges.append({
                    "source": src,
                    "target": tgt,
                    "relationship": str(e.get("relationship") or "RELATED_TO").upper().replace(" ", "_"),
                    "confidence": max(0.1, min(float(e.get("confidence") or 0.8), 1.0)),
                    "evidence_ref": str(e.get("evidence_ref") or f"maltego_import:{investigation_id}"),
                })

        return entities, edges

    def _parse_csv_import(
        self,
        csv_text: str,
        investigation_id: str,
        imported_by: Optional[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        reader = csv.DictReader(io.StringIO(csv_text))
        if not reader.fieldnames:
            raise ValueError("CSV file has no header row.")

        entities: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        id_remap: Dict[str, str] = {}
        for row in reader:
            norm_row = {str(k).strip().lower(): (v or "").strip() for k, v in row.items() if k}
            section = (norm_row.get("section") or "entity").strip().lower()
            if section == "edge":
                raw_src = norm_row.get("id") or norm_row.get("source") or ""
                rel_name = (norm_row.get("entity_type") or norm_row.get("relationship") or "RELATED_TO").upper().replace(" ", "_")
                raw_tgt = norm_row.get("maltego_type") or norm_row.get("target") or ""
                src = id_remap.get(raw_src, raw_src)
                tgt = id_remap.get(raw_tgt, raw_tgt)
                if src and tgt and len(edges) < 1000:
                    edges.append({
                        "source": src,
                        "target": tgt,
                        "relationship": rel_name,
                        "confidence": max(0.1, min(float(norm_row.get("confidence") or 0.8), 1.0)),
                        "evidence_ref": norm_row.get("evidence_ref") or norm_row.get("evidence ref") or f"maltego_import:{investigation_id}",
                    })
                continue

            val = (
                norm_row.get("value")
                or norm_row.get("entity value")
                or norm_row.get("entity")
                or norm_row.get("label")
                or ""
            )
            if not val:
                continue
            raw_type = (
                norm_row.get("maltego_type")
                or norm_row.get("maltego type")
                or norm_row.get("entity_type")
                or norm_row.get("entity type")
                or norm_row.get("type")
            )
            etype = normalize_entity_type(raw_type, val)
            nid = _make_node_id(etype, val)
            ext_id = norm_row.get("id") or norm_row.get("node id")
            if ext_id:
                id_remap[ext_id] = nid
            entities.append({
                "node_id": nid,
                "entity_type": etype,
                "maltego_type": to_maltego_type(etype, val),
                "value": val,
                "label": (norm_row.get("label") or val)[:120],
                "source_tool": norm_row.get("source_tool") or norm_row.get("source tool") or norm_row.get("source") or "maltego_import",
                "evidence_ref": norm_row.get("evidence_ref") or norm_row.get("evidence ref") or f"maltego_import:{investigation_id}",
                "risk_level": norm_row.get("risk_level") or norm_row.get("risk level") or "info",
                "confidence": max(0.1, min(float(norm_row.get("confidence") or 0.8), 1.0)),
                "attributes": {"imported_by": imported_by or "analyst"},
            })
            if len(entities) >= 500:
                break
        return entities, edges

    def sync_campaign_graph(
        self,
        investigation_id: str,
        scan_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Builds and archives an intelligence_graph_json snapshot to SeaweedFS + DB."""
        try:
            graph = self.build_investigation_graph(investigation_id)
            raw_bytes = json.dumps(graph, indent=2).encode("utf-8")
            ev = self.storage.upload_content(
                content=raw_bytes,
                file_name=f"intelligence_graph_{investigation_id}_{scan_id or 'latest'}.json",
                investigation_id=investigation_id,
                evidence_type="intelligence_graph_json",
                content_type="application/json",
            )
            self.repo.add_evidence_record(
                investigation_id=investigation_id,
                evidence_type="intelligence_graph_json",
                file_name=ev["file_name"],
                file_size=ev["file_size"],
                sha256_hash=ev["sha256_hash"],
                seaweed_fid=ev.get("seaweed_fid"),
                seaweed_url=ev.get("seaweed_url"),
                local_path=ev.get("local_path"),
                scan_id=scan_id,
            )
            return graph
        except Exception as exc:
            logger.warning(f"Campaign graph snapshot archival notice for {investigation_id}: {exc}")
            return None
