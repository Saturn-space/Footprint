"""
FootprintIQ - Integrated Report Analysis, Naming & Scan Comparison Engine
Synthesizes factual, non-fabricated Executive Analysis, Vulnerability Analysis,
Risk Interpretation, Remediation Analysis, Assessment Limitations, Interactive
Analytics Datasets, and Scan-to-Scan Comparisons directly from persisted MSSQL
campaign data, scan execution runs, vulnerability findings, exposure scores,
execution logs, and SeaweedFS/local evidence records.
"""

from __future__ import annotations

import os
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.db.repository import FootprintIQRepository
from src.services.exposure_scoring import ExposureScoringEngine
from src.services.finding_translator import (
    build_dynamic_remediation_roadmap,
    classify_confidence,
    explain_finding_plain_language,
)
from src.services.recon_results_helper import load_campaign_results_bundle
from src.utils.timezone import duration_human, format_ist

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")

SUPPORTED_REPORT_TYPES = {
    "executive",
    "technical",
    "active",
    "passive",
    "combined",
    "nmap",
    "nse",
    "nuclei",
    "nessus",
}

CANONICAL_TOOLS = (
    ("theharvester", "theHarvester"),
    ("whois_rdap_dns", "WHOIS / RDAP / DNS OSINT"),
    ("nmap", "Nmap"),
    ("nmap_nse", "Nmap NSE"),
    ("nuclei", "ProjectDiscovery Nuclei"),
    ("nessus", "Tenable Nessus"),
    ("maltego_graph", "Maltego Entity Graph"),
)


def sanitize_report_slug(name: Optional[str], fallback: str = "investigation") -> str:
    """Normalizes an investigation name into a filesystem-safe lowercase slug."""
    raw = str(name or "").strip().lower()
    slug = re.sub(r"[^a-z0-9_-]+", "_", raw)
    slug = re.sub(r"_+", "_", slug).strip("_-")
    if not slug:
        slug = fallback
    return slug[:60]


def normalize_report_type_tag(report_format: Optional[str]) -> str:
    """Maps requested report format / scope tag cleanly to canonical report type slug."""
    val = str(report_format or "executive").strip().lower()
    aliases = {
        "exec": "executive",
        "tech": "technical",
        "nmap_services": "nmap",
        "nmap_nse": "nse",
        "network_discovery": "active",
    }
    val = aliases.get(val, val)
    return val if val in SUPPORTED_REPORT_TYPES else "executive"


def build_investigation_report_filename(
    investigation_name: Optional[str],
    report_format: Optional[str],
    reports_dir: str = REPORTS_DIR,
    run_number: Optional[int] = None,
) -> str:
    """
    Produces collision-free, human-readable investigation-derived PDF filenames:
    - Primary format: `<investigation_slug>_<type>.pdf` (e.g. `test1_active.pdf`)
    - Disambiguates existing/multi-run deliverables cleanly with `-run-NNN`
      (e.g. `test1_active_run-001.pdf`, `test1_active_run-002.pdf`) so historical
      PDFs are never silently overwritten.
    """
    os.makedirs(reports_dir, exist_ok=True)
    slug = sanitize_report_slug(investigation_name)
    tag = normalize_report_type_tag(report_format)

    primary = f"{slug}_{tag}.pdf"
    if not os.path.exists(os.path.join(reports_dir, primary)):
        return primary

    if run_number is not None:
        run_name = f"{slug}_{tag}_run-{int(run_number):03d}.pdf"
        if not os.path.exists(os.path.join(reports_dir, run_name)):
            return run_name
        seq = 2
        while True:
            cand = f"{slug}_{tag}_run-{int(run_number):03d}_{seq}.pdf"
            if not os.path.exists(os.path.join(reports_dir, cand)):
                return cand
            seq += 1

    seq = 2
    while seq < 100:
        cand = f"{slug}_{tag}_{seq}.pdf"
        if not os.path.exists(os.path.join(reports_dir, cand)):
            return cand
        seq += 1
    return f"{slug}_{tag}_{uuid.uuid4().hex[:6]}.pdf"


def extract_report_file_metadata(filename: str) -> Dict[str, str]:
    """Extracts report format and investigation/campaign ID from legacy or slug PDF names."""
    base = os.path.basename(filename or "")
    m = re.search(r"FootprintIQ_(?:(Executive|Technical)_)?Report_([A-Za-z0-9_-]+)_\d+", base)
    if m:
        return {
            "report_format": (m.group(1) or "Executive").lower(),
            "investigation_id": m.group(2),
        }
    m2 = re.match(
        r"^[a-z0-9_-]+_(executive|technical|active|passive|combined|nmap|nse|nuclei|nessus)(?:_run-\d+)?(?:_\d+|[a-f0-9]+)?\.pdf$",
        base.lower(),
    )
    if m2:
        return {
            "report_format": m2.group(1),
            "investigation_id": "UNKNOWN",
        }
    return {"report_format": "executive", "investigation_id": "UNKNOWN"}


def resolve_report_record(
    report_identifier: str,
    repo: FootprintIQRepository,
    reports_dir: str = REPORTS_DIR,
) -> Optional[Dict[str, Any]]:
    """
    Resolves a report strictly by `REP-...` report_id or exact PDF filename,
    merging database metadata (`scan_id`, `run_number`, `investigation_name`,
    IST timestamps) with filesystem artifact details cleanly.
    """
    clean_id = os.path.basename((report_identifier or "").strip())
    if not clean_id:
        return None

    db_rec = repo.get_report_record(clean_id)
    if not db_rec and not clean_id.endswith(".pdf") and not clean_id.startswith("REP-"):
        db_rec = repo.get_report_record(clean_id + ".pdf")

    file_name = db_rec.get("file_name") if db_rec else (clean_id if clean_id.endswith(".pdf") else f"{clean_id}.pdf")
    full_path = os.path.join(reports_dir, file_name)
    file_exists = os.path.isfile(full_path)

    if not db_rec and not file_exists:
        return None

    meta = extract_report_file_metadata(file_name)
    inv_id = (
        (db_rec.get("recon_id") if db_rec else None)
        or (db_rec.get("investigation_id") if db_rec else None)
        or meta["investigation_id"]
    )
    stat_size = os.path.getsize(full_path) if file_exists else 0
    created_iso = (
        (db_rec.get("generated_at") if db_rec else None)
        or (datetime.fromtimestamp(os.path.getctime(full_path), tz=timezone.utc).isoformat() if file_exists else None)
    )
    report_id_val = (db_rec.get("report_id") if db_rec else None) or file_name
    run_number = db_rec.get("run_number") if db_rec else None

    return {
        "report_id": report_id_val,
        "db_report_id": db_rec.get("report_id") if db_rec else None,
        "file_name": file_name,
        "file_exists": file_exists,
        "file_path": full_path if file_exists else None,
        "investigation_id": inv_id,
        "recon_id": inv_id,
        "investigation_name": db_rec.get("investigation_name") if db_rec else None,
        "scan_id": db_rec.get("scan_id") if db_rec else None,
        "run_number": int(run_number) if run_number is not None else None,
        "run_label": f"Run {int(run_number):03d}" if run_number is not None else None,
        "scan_type": db_rec.get("scan_type") if db_rec else None,
        "report_status": (db_rec.get("report_status") if db_rec else None) or ("completed" if file_exists else "missing"),
        "report_format": ((db_rec.get("report_type") if db_rec else None) or meta["report_format"]).lower(),
        "file_size": db_rec.get("file_size") if (db_rec and db_rec.get("file_size")) else stat_size,
        "sha256_hash": db_rec.get("sha256_hash") if db_rec else None,
        "seaweed_fid": db_rec.get("seaweed_fid") if db_rec else None,
        "generated_by_user_id": db_rec.get("generated_by_user_id") if db_rec else None,
        "generated_by_username": db_rec.get("generated_by_username") if db_rec else None,
        "generated_at": created_iso,
        "generated_at_ist": format_ist(created_iso),
        "download_url": f"/api/v1/reports/{report_id_val}/download?investigation_id={inv_id}",
    }


def _normalize_severity(raw: Any) -> str:
    s = str(raw or "Informational").strip().title()
    if s in ("Info", "Information"):
        return "Informational"
    if s in ("Critical", "High", "Medium", "Low", "Informational"):
        return s
    return "Informational"


def _classify_vulnerability_category(f: Dict[str, Any]) -> str:
    cve = str(f.get("cve_identifiers") or "").strip()
    if cve and cve not in ("N/A", "None", "—"):
        return "Known CVEs"
    haystack = " ".join([
        str(f.get("title") or ""),
        str(f.get("description") or ""),
        str(f.get("service") or ""),
        str(f.get("scanner_vt_id") or ""),
    ]).lower()
    if any(k in haystack for k in ("tls", "ssl", "cipher", "certificate", "x509", "poodle", "heartbleed", "weak key")):
        return "TLS / SSL Weaknesses"
    if any(k in haystack for k in ("http", "header", "hsts", "csp", "cors", "cookie", "xss", "csrf", "web", "robots.txt", "waf")):
        return "Web / HTTP Security"
    if any(k in haystack for k in ("dns", "whois", "rdap", "spf", "dmarc", "dkim", "zone transfer", "nameserver", "subdomain")):
        return "DNS / Infrastructure OSINT"
    if any(k in haystack for k in ("default credential", "anonymous", "misconfig", "config", "open relay", "smb-security", "permission")):
        return "Misconfigurations"
    if any(k in haystack for k in ("disclosure", "banner", "version", "info", "leak", "exposed directory", "phpinfo")):
        return "Information Disclosure"
    if f.get("port") or any(k in haystack for k in ("open port", "service", "ssh", "ftp", "telnet", "smb", "rdp", "database")):
        return "Exposed Services"
    return "Other"


def _map_source_to_tool_key(source: Any) -> str:
    s = str(source or "").lower()
    if "harvester" in s:
        return "theharvester"
    if any(k in s for k in ("whois", "rdap", "dns", "passive")):
        return "whois_rdap_dns"
    if "nse" in s:
        return "nmap_nse"
    if "nmap" in s or "active port" in s or "port & service" in s or "service discovery" in s:
        return "nmap"
    if "nuclei" in s:
        return "nuclei"
    if "nessus" in s:
        return "nessus"
    if "maltego" in s or "graph" in s:
        return "maltego_graph"
    return s or "unknown"


def _finding_fingerprint(f: Dict[str, Any]) -> Tuple[str, int, str, str]:
    host = str(f.get("target_ip") or f.get("hostname") or "unknown").strip().lower()
    port = int(f.get("port") or 0)
    proto = str(f.get("protocol") or "tcp").strip().lower()
    cve = str(f.get("cve_identifiers") or "").strip().upper()
    vt = str(f.get("scanner_vt_id") or "").strip().lower()
    title = re.sub(r"\s+", " ", str(f.get("title") or "").strip().lower())
    ident = cve if cve and cve not in ("N/A", "NONE", "—") else (vt or title)
    return (host, port, proto, ident)


def _filter_findings_by_report_scope(
    findings: List[Dict[str, Any]],
    report_format: str,
) -> List[Dict[str, Any]]:
    fmt = normalize_report_type_tag(report_format)
    if fmt in ("executive", "technical", "combined"):
        return findings
    if fmt == "passive":
        return [f for f in findings if _map_source_to_tool_key(f.get("detection_source")) in ("theharvester", "whois_rdap_dns")]
    if fmt == "active":
        return [f for f in findings if _map_source_to_tool_key(f.get("detection_source")) in ("nmap", "nmap_nse")]
    if fmt == "nmap":
        return [f for f in findings if _map_source_to_tool_key(f.get("detection_source")) == "nmap"]
    if fmt == "nse":
        return [f for f in findings if _map_source_to_tool_key(f.get("detection_source")) == "nmap_nse"]
    if fmt == "nuclei":
        return [f for f in findings if _map_source_to_tool_key(f.get("detection_source")) == "nuclei"]
    if fmt == "nessus":
        return [f for f in findings if _map_source_to_tool_key(f.get("detection_source")) == "nessus"]
    return findings


def _build_scanner_contribution_matrix(
    *,
    findings: List[Dict[str, Any]],
    scanner_statuses: List[Dict[str, Any]],
    scanners_executed: List[str],
    passive_results: List[Dict[str, Any]],
    discovered_ports: List[Dict[str, Any]],
    selected_scan: Optional[Dict[str, Any]],
    graph_stats: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    raw_by_tool: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for f in findings:
        raw_by_tool[_map_source_to_tool_key(f.get("detection_source"))].append(f)

    selected_scanners_raw = " ".join([
        str(s) for s in ((selected_scan or {}).get("selected_scanners") or [])
    ] + [str(s) for s in scanners_executed]).lower()

    status_by_tool: Dict[str, List[str]] = defaultdict(list)
    detail_by_tool: Dict[str, List[str]] = defaultdict(list)
    for ss in scanner_statuses:
        if not isinstance(ss, dict):
            continue
        tkey = _map_source_to_tool_key(ss.get("scanner"))
        if tkey == "nmap" and "nse" in str(ss.get("scanner") or "").lower():
            tkey = "nmap_nse"
        st_val = str(ss.get("status") or "").upper()
        if st_val:
            status_by_tool[tkey].append(st_val)
        det_msg = ss.get("detail") or ss.get("details")
        if det_msg:
            detail_by_tool[tkey].append(str(det_msg))

    has_passive_ip_only = bool(passive_results) and all(
        str(pr.get("target_kind") or "").lower() == "ip"
        for pr in passive_results
    )
    harvester_explicit_skip = any(
        uc.get("id") == "theharvester"
        and str(uc.get("status") or "").upper() in ("SKIPPED", "NOT_APPLICABLE")
        for pr in passive_results
        for uc in (pr.get("unavailable_checks") or [])
    )

    rows: List[Dict[str, Any]] = []
    for tkey, label in CANONICAL_TOOLS:
        tool_findings = raw_by_tool.get(tkey, [])
        unique_fp = {_finding_fingerprint(item) for item in tool_findings}
        statuses = list(status_by_tool.get(tkey, []))
        raw_count = len(tool_findings)
        uniq_count = len(unique_fp)

        extra_obs = 0
        if tkey == "theharvester":
            for pr in passive_results:
                osint = pr.get("osint_intel") or {}
                dom = pr.get("domain_intel") or {}
                extra_obs += len(osint.get("emails") or []) + len(dom.get("subdomains") or [])
            if raw_count == 0 and extra_obs == 0 and (harvester_explicit_skip or has_passive_ip_only):
                if "SKIPPED" not in statuses:
                    statuses.append("SKIPPED")
                if not detail_by_tool[tkey]:
                    detail_by_tool[tkey].append("Domain-only OSINT check skipped for IP target.")
        elif tkey == "whois_rdap_dns":
            for pr in passive_results:
                dom = pr.get("domain_intel") or {}
                dns = dom.get("dns_records") or {}
                extra_obs += sum(len(v) for v in dns.values() if isinstance(v, list))
                if dom.get("whois") or dom.get("rdap"):
                    extra_obs += 1
                rdns = dom.get("reverse_dns")
                if isinstance(rdns, list):
                    extra_obs += len(rdns)
                elif rdns:
                    extra_obs += 1
                if pr.get("ip_scope") and not (dom.get("whois") or dom.get("rdap")):
                    extra_obs += 1
        elif tkey == "nmap":
            extra_obs = len(discovered_ports)
        elif tkey == "maltego_graph" and graph_stats:
            extra_obs = int(graph_stats.get("nodes_count") or 0)

        # Honest execution state determination (strictly unified with Section 3 tables & charts)
        has_failed = any(s in ("FAILED", "ERROR") for s in statuses)
        has_partial = any(s in ("PARTIAL", "TIMEOUT", "INCOMPLETE") for s in statuses)
        has_completed = any(
            s in ("COMPLETED", "COMPLETED_WITH_FINDINGS", "COMPLETED_ZERO_FINDINGS")
            for s in statuses
        )
        has_skipped = any(
            s in ("READ_ONLY", "READ_ONLY_LICENSE", "SKIPPED", "UNAVAILABLE", "BLOCKED", "NOT_APPLICABLE")
            for s in statuses
        )

        if has_partial or (has_failed and (has_completed or raw_count > 0)):
            exec_state = "partial"
            exec_label = (
                f"Partial ({raw_count} finding(s))"
                if raw_count > 0
                else "Partial / Timed out (0 findings)"
            )
            status_badge = "PARTIAL"
        elif has_failed:
            exec_state = "failed"
            exec_label = "Failed"
            status_badge = "FAILED"
        elif has_skipped and not has_completed and raw_count == 0:
            exec_state = "skipped"
            exec_label = "Skipped / Unavailable"
            status_badge = "SKIPPED"
        elif raw_count > 0:
            exec_state = "executed_with_findings"
            exec_label = f"Completed ({raw_count} finding(s))"
            status_badge = "COMPLETED WITH FINDINGS"
        elif has_completed or (
            tkey != "theharvester" and tkey in selected_scanners_raw
        ) or (
            tkey == "theharvester" and (
                "passive" in selected_scanners_raw or "theharvester" in selected_scanners_raw
            ) and not has_passive_ip_only
        ) or (
            tkey == "whois_rdap_dns" and (
                "passive" in selected_scanners_raw or "whois" in selected_scanners_raw
                or "rdap" in selected_scanners_raw or "dns" in selected_scanners_raw
            )
        ) or (
            tkey == "nmap_nse" and "nse" in selected_scanners_raw
        ) or (
            tkey == "nmap" and ("nmap" in selected_scanners_raw or discovered_ports)
        ):
            exec_state = "executed_zero_findings"
            exec_label = (
                "Completed cleanly (0 findings)"
                if extra_obs == 0
                else f"Completed ({extra_obs} artifact/port item(s); 0 vuln findings)"
            )
            status_badge = "COMPLETED WITH ZERO FINDINGS"
        elif tkey == "maltego_graph" and extra_obs > 0:
            exec_state = "executed_with_findings"
            exec_label = f"Built ({extra_obs} graph node(s))"
            status_badge = "BUILT"
        else:
            exec_state = "not_selected"
            exec_label = "Not selected in run"
            status_badge = "NOT SELECTED"

        rows.append({
            "tool_key": tkey,
            "tool_label": label,
            "tool_name": label,
            "execution_state": exec_state,
            "execution_label": exec_label,
            "status_badge": status_badge,
            "raw_count": raw_count,
            "raw_findings": raw_count,
            "unique_count": uniq_count,
            "unique_findings": uniq_count,
            "observations_count": extra_obs,
            "details": "; ".join(detail_by_tool.get(tkey, [])) or None,
        })
    return rows


def build_report_analysis(
    investigation_id: str,
    repo: FootprintIQRepository,
    *,
    report_meta: Optional[Dict[str, Any]] = None,
    findings_override: Optional[List[Dict[str, Any]]] = None,
    targets_override: Optional[List[Dict[str, Any]]] = None,
    evidence_override: Optional[List[Dict[str, Any]]] = None,
    results_bundle_override: Optional[Dict[str, Any]] = None,
    scan_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Produces complete factual Report Analysis across executive summary, vulnerability analysis,
    risk interpretation, interactive visualization datasets, historical scan-run trends,
    remediation priorities, and honest scope limitations.
    """
    camp = repo.get_recon_campaign(investigation_id) or {}
    inv = repo.get_investigation(investigation_id) or {}
    campaign_name = (
        (report_meta or {}).get("investigation_name")
        or camp.get("name")
        or inv.get("title")
        or investigation_id
    )
    target_value = camp.get("target_value") or "Scoped targets"

    eff_scan_id = scan_id or (report_meta.get("scan_id") if report_meta else None)
    all_scans = repo.list_scans(investigation_id)
    selected_scan = repo.get_scan(eff_scan_id) if eff_scan_id else (all_scans[0] if all_scans else None)
    campaign_status = (
        (selected_scan.get("status") if eff_scan_id and selected_scan else None)
        or camp.get("status")
        or inv.get("status")
        or "Unknown"
    )

    targets = targets_override if targets_override is not None else repo.list_authorized_targets(investigation_id)
    base_findings = (
        findings_override
        if findings_override is not None
        else repo.list_findings(investigation_id, scan_id=eff_scan_id)
    )
    report_format = normalize_report_type_tag((report_meta or {}).get("report_format"))
    findings = _filter_findings_by_report_scope(base_findings, report_format) if report_meta else base_findings
    evidence = (
        evidence_override
        if evidence_override is not None
        else repo.list_evidence(investigation_id, scan_id=eff_scan_id)
    )
    bundle = (
        results_bundle_override
        if results_bundle_override is not None
        else load_campaign_results_bundle(investigation_id, repo, scan_id=eff_scan_id)
    )

    discovered_ports = bundle.get("discovered_ports") or []
    scanner_statuses = bundle.get("scanner_statuses") or []
    passive_results = bundle.get("passive_results") or []
    scanners_executed = bundle.get("scanners_executed") or []
    failed_stages = list(bundle.get("failed_stages") or [])
    partial_stages = list(bundle.get("partial_stages") or [])

    exposure = ExposureScoringEngine.calculate_investigation_exposure(
        findings,
        discovered_ports=discovered_ports,
    )
    raw_sev = exposure["severity_counts"]
    sev_counts = {
        "Critical": int(raw_sev.get("Critical", 0)),
        "High": int(raw_sev.get("High", 0)),
        "Medium": int(raw_sev.get("Medium", 0)),
        "Low": int(raw_sev.get("Low", 0)),
        "Informational": int(raw_sev.get("Informational", 0)) + int(raw_sev.get("Info", 0)),
    }
    score = exposure["exposure_score"]
    level = exposure["exposure_level"]

    # 1. Confidence, Classification, Host & Category Breakdown
    confidence_counts: Dict[str, int] = defaultdict(int)
    remediation_counts: Dict[str, int] = defaultdict(int)
    category_counts: Dict[str, int] = defaultdict(int)
    cve_set = set()
    host_map: Dict[str, Dict[str, Any]] = {}
    service_map: Dict[Tuple[int, str, str], Dict[str, Any]] = {}

    enriched_findings: List[Dict[str, Any]] = []
    for f in findings:
        norm_sev = _normalize_severity(f.get("severity"))
        conf_label = classify_confidence(f)
        confidence_counts[conf_label] += 1
        rem_status = str(f.get("remediation_status") or f.get("finding_status") or "open").lower()
        remediation_counts[rem_status] += 1
        cat_label = _classify_vulnerability_category(f)
        category_counts[cat_label] += 1

        raw_cve = str(f.get("cve_identifiers") or "").strip()
        f_cves = [c.strip() for c in raw_cve.split(",") if c.strip() and c.strip() not in ("N/A", "None", "—")]
        cve_set.update(f_cves)

        ip_key = str(f.get("target_ip") or f.get("hostname") or target_value or "Target")
        if ip_key not in host_map:
            host_map[ip_key] = {
                "host": ip_key,
                "finding_count": 0,
                "critical_high_count": 0,
                "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0},
                "ports": set(),
                "services": set(),
                "cves": set(),
            }
        host_map[ip_key]["finding_count"] += 1
        host_map[ip_key]["severity_counts"][norm_sev] += 1
        if norm_sev in ("Critical", "High"):
            host_map[ip_key]["critical_high_count"] += 1
        if f.get("port"):
            p_num = int(f["port"])
            host_map[ip_key]["ports"].add(p_num)
            svc_name = str(f.get("service") or "unknown").lower()
            proto = str(f.get("protocol") or "tcp").lower()
            s_key = (p_num, proto, svc_name)
            if s_key not in service_map:
                service_map[s_key] = {
                    "port": p_num,
                    "protocol": proto,
                    "service": svc_name,
                    "hosts": set(),
                    "findings_count": 0,
                    "max_sev": norm_sev,
                }
            service_map[s_key]["hosts"].add(ip_key)
            service_map[s_key]["findings_count"] += 1
        if f.get("service"):
            host_map[ip_key]["services"].add(str(f["service"]))
        host_map[ip_key]["cves"].update(f_cves)

        plain = explain_finding_plain_language(f)
        enriched_findings.append({
            **f,
            "severity": norm_sev,
            "category": cat_label,
            "confidence_label": conf_label,
            "remediation_status": rem_status,
            "first_detected_ist": f.get("first_detected_ist") or format_ist(f.get("first_detected")),
            "plain_language": plain,
        })

    # Include active discovered ports in host & service summaries cleanly
    for dp in discovered_ports:
        ip_key = str(dp.get("target_ip") or target_value or "Target")
        if ip_key not in host_map:
            host_map[ip_key] = {
                "host": ip_key,
                "finding_count": 0,
                "critical_high_count": 0,
                "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0},
                "ports": set(),
                "services": set(),
                "cves": set(),
            }
        if dp.get("port"):
            p_num = int(dp["port"])
            host_map[ip_key]["ports"].add(p_num)
            svc_name = str(dp.get("service") or "unknown").lower()
            proto = str(dp.get("protocol") or "tcp").lower()
            s_key = (p_num, proto, svc_name)
            if s_key not in service_map:
                service_map[s_key] = {
                    "port": p_num,
                    "protocol": proto,
                    "service": svc_name,
                    "hosts": set(),
                    "findings_count": 0,
                    "max_sev": "Informational",
                }
            service_map[s_key]["hosts"].add(ip_key)
        if dp.get("service"):
            host_map[ip_key]["services"].add(str(dp["service"]))

    sev_rank = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1, "Info": 1}
    sorted_findings = sorted(
        enriched_findings,
        key=lambda item: (
            sev_rank.get(str(item.get("severity") or "Informational"), 0),
            float(item.get("cvss_score") or 0.0),
            item.get("title") or "",
        ),
        reverse=True,
    )

    affected_hosts = [
        {
            "host": h["host"],
            "finding_count": h["finding_count"],
            "findings_count": h["finding_count"],
            "critical_high_count": h["critical_high_count"],
            "severity_counts": h["severity_counts"],
            "open_ports_count": len(h["ports"]),
            "ports": sorted(h["ports"]),
            "services": sorted(h["services"]),
            "cves": sorted(h["cves"]),
        }
        for h in sorted(host_map.values(), key=lambda x: (x["critical_high_count"], x["finding_count"], len(x["ports"])), reverse=True)
    ]

    exposed_services_list = sorted(
        [
            {
                "label": f"{v['port']}/{v['protocol']} ({v['service']})",
                "port": v["port"],
                "protocol": v["protocol"],
                "service": v["service"],
                "count": len(v["hosts"]),
                "hosts_count": len(v["hosts"]),
                "findings_count": v["findings_count"],
                "is_high_risk_service": v["service"] in {
                    "telnet", "ftp", "smb", "microsoft-ds", "netbios-ssn", "rdp",
                    "ms-wbt-server", "vnc", "mysql", "postgresql", "bindshell",
                    "exec", "login", "shell", "rsh", "rlogin", "rexec", "x11",
                    "nfs", "rpcbind", "ajp13", "ldap", "java-rmi", "rmiregistry", "drb",
                },
            }
            for v in service_map.values()
        ],
        key=lambda x: (x["findings_count"], x["hosts_count"], 1 if x["is_high_risk_service"] else 0),
        reverse=True,
    )

    # 2. Honest Coverage & Limitations Evaluation
    coverage_gaps: List[str] = []
    for st in failed_stages:
        coverage_gaps.append(f"Stage '{st}' failed or exited incomplete; findings from this stage may be missing.")
    for st in partial_stages:
        if st not in failed_stages:
            coverage_gaps.append(
                f"Stage '{st}' ended partially (timeout, skipped checks, or incomplete execution); findings from unfinished checks are missing."
            )
    for ss in scanner_statuses:
        s_status = str(ss.get("status") or "").upper()
        if s_status in ("FAILED", "ERROR", "PARTIAL", "TIMEOUT", "INCOMPLETE", "UNAVAILABLE", "READ_ONLY", "READ_ONLY_LICENSE", "BLOCKED", "CANCELLED"):
            det = ss.get("detail") or ss.get("details") or "Engine unavailable or did not finish cleanly."
            coverage_gaps.append(f"{ss.get('scanner') or 'Scanner'} ({s_status}): {det}")
    scans_to_check = [selected_scan] if (eff_scan_id and selected_scan) else all_scans
    for sc in scans_to_check:
        if not sc:
            continue
        sc_status = str(sc.get("status") or "").lower()
        if sc_status in ("failed", "cancelled", "interrupted", "partially_completed"):
            coverage_gaps.append(
                f"Scan {sc.get('scan_id')} ({sc.get('scan_type')}) ended with status '{sc_status}'."
            )
    for pr in passive_results:
        for uc in (pr.get("unavailable_checks") or []):
            uc_status = str(uc.get("status") or "UNAVAILABLE").upper()
            verb = "skipped" if uc_status in ("SKIPPED", "NOT_APPLICABLE") else "unavailable"
            coverage_gaps.append(f"Passive check '{uc.get('id')}' {verb}: {uc.get('reason')}")

    dedup_gaps = list(dict.fromkeys(coverage_gaps))
    norm_camp_status = str(campaign_status or "").replace("_", " ").lower()
    is_incomplete_campaign = norm_camp_status in (
        "draft", "pending authorization", "authorized", "queued", "running",
        "failed", "partially completed", "cancelled", "interrupted"
    )
    has_incomplete_coverage = bool(dedup_gaps or is_incomplete_campaign or partial_stages or failed_stages)

    # 3. Scanner Contribution & Coverage Matrix
    scanner_contribution = _build_scanner_contribution_matrix(
        findings=findings,
        scanner_statuses=scanner_statuses,
        scanners_executed=scanners_executed,
        passive_results=passive_results,
        discovered_ports=discovered_ports,
        selected_scan=selected_scan,
    )

    # 4. Overall Risk Score Availability & Transparency
    any_completed_stage = any(
        row["execution_state"] in ("executed_with_findings", "executed_zero_findings", "partial")
        for row in scanner_contribution
    ) or bool(findings or discovered_ports or scans_to_check)
    risk_score_available = bool(any_completed_stage and not (norm_camp_status == "failed" and not findings))

    # 5. Historical Scan-Run Trend across this Investigation
    all_inv_findings = repo.list_findings(investigation_id)
    trend_rows: List[Dict[str, Any]] = []
    ordered_runs = sorted(
        all_scans,
        key=lambda s: (int(s.get("run_number") or 1), s.get("started_at") or s.get("created_at") or "")
    )
    for run in ordered_runs:
        sid = run.get("scan_id")
        r_findings = [f for f in all_inv_findings if f.get("scan_id") == sid]
        r_exp = ExposureScoringEngine.calculate_investigation_exposure(r_findings)
        r_sev = r_exp["severity_counts"]
        status_clean = str(run.get("status") or "").lower()
        is_failed = status_clean in ("failed", "cancelled", "interrupted", "error")
        is_completed = status_clean in ("completed", "partially_completed", "partial")
        is_partial = status_clean in ("partially_completed", "partial")

        # Do not treat missing results from failed scans as zero findings
        run_findings_count = len(r_findings) if not is_failed else None
        run_risk_score = r_exp["exposure_score"] if not is_failed else None

        trend_rows.append({
            "scan_id": sid,
            "run_number": int(run.get("run_number") or 1),
            "run_label": run.get("run_label") or f"Run {int(run.get('run_number') or 1):03d}",
            "scan_type": run.get("scan_type"),
            "status": run.get("status"),
            "is_completed": is_completed,
            "is_partial": is_partial,
            "started_at": run.get("started_at") or run.get("created_at"),
            "started_at_ist": run.get("started_at_ist") or run.get("created_at_ist") or format_ist(run.get("started_at") or run.get("created_at")),
            "Critical": int(r_sev.get("Critical", 0)) if not is_failed else None,
            "High": int(r_sev.get("High", 0)) if not is_failed else None,
            "Medium": int(r_sev.get("Medium", 0)) if not is_failed else None,
            "Low": int(r_sev.get("Low", 0)) if not is_failed else None,
            "Informational": (int(r_sev.get("Informational", 0)) + int(r_sev.get("Info", 0))) if not is_failed else None,
            "total_findings": run_findings_count,
            "risk_score": run_risk_score,
        })
    trend_completed_count = sum(1 for r in trend_rows if r.get("is_completed"))

    # 6. Executive Analysis
    key_takeaways: List[str] = []
    if sev_counts["Critical"] or sev_counts["High"]:
        key_takeaways.append(
            f"Identified {sev_counts['Critical']} Critical and {sev_counts['High']} High severity findings contributing to a {score}/100 ({level}) exposure score."
        )
    elif findings:
        key_takeaways.append(
            f"Recorded {len(findings)} lower-severity or informational finding(s) with no Critical or High vulnerabilities in completed modules (Exposure Score: {score}/100)."
        )
    elif has_incomplete_coverage:
        key_takeaways.append(
            f"No findings were persisted, but coverage is INCOMPLETE ({campaign_status}). Zero recorded findings cannot be interpreted as a clean bill of health."
        )
    else:
        key_takeaways.append(
            "Zero vulnerabilities were detected across all completed assessment modules for the configured scope."
        )

    if discovered_ports:
        port_sample = ", ".join([f"{p.get('port')}/{p.get('service') or p.get('protocol', 'tcp')}" for p in discovered_ports[:6]])
        key_takeaways.append(f"Observed {len(discovered_ports)} exposed service port(s), including {port_sample}.")
    if cve_set:
        key_takeaways.append(f"Correlated {len(cve_set)} distinct CVE identifier(s): {', '.join(sorted(cve_set)[:6])}.")
    if confidence_counts.get("Confirmed Vulnerability"):
        key_takeaways.append(f"{confidence_counts['Confirmed Vulnerability']} finding(s) carry Confirmed confidence from verified evidence.")
    if confidence_counts.get("Observed Scanner Match"):
        key_takeaways.append(
            f"{confidence_counts['Observed Scanner Match']} finding(s) are automated scanner signature matches (Observed) pending independent exploitability verification."
        )
    if confidence_counts.get("Potential Vulnerability"):
        key_takeaways.append(f"{confidence_counts['Potential Vulnerability']} finding(s) are classified as Potential vulnerabilities pending manual validation.")

    run_context_phrase = f" on {selected_scan['run_label']} ({selected_scan['scan_id']})" if eff_scan_id and selected_scan else ""
    overall_posture = (
        f"Investigation '{campaign_name}' ({investigation_id}){run_context_phrase} assessed target '{target_value}' "
        f"with current outcome '{campaign_status}'. Calculated risk posture is "
        f"{f'{level} ({score}/100)' if risk_score_available else 'Risk score unavailable'} across "
        f"{len(findings)} recorded finding(s) and {len(discovered_ports)} discovered port(s)."
    )
    if has_incomplete_coverage:
        overall_posture += " Incomplete or failed scan modules limit completeness; affected modules must be re-run before concluding target security."

    # 7. Risk Interpretation (non-fabricated, driven by observed evidence)
    risk_drivers: List[str] = []
    confirmed_count = confidence_counts.get("Confirmed Vulnerability", 0)
    observed_count = confidence_counts.get("Observed Scanner Match", 0)
    potential_count = confidence_counts.get("Potential Vulnerability", 0)
    high_cvss = [f for f in sorted_findings if (f.get("cvss_score") or 0) >= 7.0]
    if high_cvss:
        risk_drivers.append(
            f"{len(high_cvss)} finding(s) carry CVSS scores >= 7.0 (highest: {high_cvss[0].get('cvss_score')} on '{high_cvss[0].get('title')}'), indicating elevated severity subject to verification/remediation."
        )
    exposed_services = {str(p.get("service") or "").lower() for p in discovered_ports if p.get("service")}
    legacy_or_admin = sorted(
        exposed_services
        & {
            "ftp", "telnet", "smb", "microsoft-ds", "netbios-ssn", "ssh", "rdp",
            "ms-wbt-server", "vnc", "http", "bindshell", "exec", "login", "shell",
            "rsh", "rlogin", "rexec", "mysql", "postgresql", "nfs", "rpcbind",
            "ajp13", "ldap", "java-rmi", "rmiregistry", "drb",
        }
    )
    if legacy_or_admin:
        risk_drivers.append(
            f"{len(discovered_ports)} open port(s) discovered including remote/cleartext/high-risk services ({', '.join(legacy_or_admin[:12])}); raw open ports provide asset context in the table above and do not add direct score points."
        )
    if observed_count and not confirmed_count:
        risk_drivers.append(
            f"{observed_count} finding(s) are Observed Scanner Matches (weighted at 0.85x vs 1.00x Confirmed in the bounded exposure curve); analyst verification is recommended before classifying exploitability as proven."
        )
    if potential_count and not confirmed_count and not observed_count:
        risk_drivers.append(
            "Findings rely primarily on automated version/signature indicators (Potential); analyst validation is recommended to confirm exploitability."
        )
    if partial_stages or failed_stages:
        risk_drivers.append(
            f"Incomplete scanner execution ({', '.join(partial_stages + failed_stages)}): unfinished or failed checks did not contribute findings, which may understate total risk."
        )
    if not risk_drivers and findings:
        risk_drivers.append(
            "Observed items are primarily moderate/informational configuration exposures without confirmed critical remote exploitation paths in scanned scope."
        )
    if not risk_drivers and not findings:
        risk_drivers.append(
            "No exploit paths recorded in completed stages."
            if not has_incomplete_coverage
            else "Risk remains indeterminate for incomplete or failed scanner stages until those checks complete cleanly."
        )

    risk_interpretation = {
        "exposure_score": score if risk_score_available else None,
        "exposure_level": level if risk_score_available else "Risk score unavailable",
        "risk_score_available": risk_score_available,
        "formula_note": exposure.get("scoring_formula") or (
            "Weighted diminishing-returns curve: 100 * (1 - exp(-sum(CVSS * 10 * status_weight * confidence) / 150.0))."
        ),
        "scoring_breakdown": exposure.get("scoring_breakdown") or {},
        "confirmed_findings": confirmed_count,
        "observed_findings": observed_count,
        "potential_findings": potential_count,
        "informational_findings": confidence_counts.get("Informational Observation", 0) + confidence_counts.get("Unverified / Informational", 0),
        "drivers": risk_drivers,
        "confidence_summary": (
            f"{confirmed_count} confirmed, {observed_count} observed matcher, {potential_count} potential, "
            f"{confidence_counts.get('Marked False Positive', 0)} false positive"
        ),
    }

    # 8. Remediation Analysis
    roadmap = build_dynamic_remediation_roadmap(findings, failed_scanners=failed_stages)
    action_items: List[Dict[str, Any]] = []
    for f in sorted_findings[:20]:
        rem_text = str(f.get("remediation") or f.get("plain_language", {}).get("recommended_action") or "").strip()
        if not rem_text:
            continue
        action_items.append({
            "finding_id": f.get("finding_id"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "target": f"{f.get('target_ip')}:{f.get('port')}" if f.get("port") else f.get("target_ip"),
            "status": f.get("remediation_status"),
            "action": rem_text,
        })

    # 9. Scope Limitations
    scope_constraints = {
        "authorized_targets_count": len(targets),
        "primary_target": target_value,
        "excluded_targets": camp.get("excluded_targets") or "None recorded",
        "excluded_ports": camp.get("excluded_ports") or "None recorded",
        "selected_scan_types": (selected_scan.get("scan_type") if selected_scan else None) or camp.get("selected_scan_types") or "Not specified",
        "report_scope": report_format,
        "scan_id": eff_scan_id,
        "run_label": selected_scan.get("run_label") if selected_scan else None,
        "scanner_versions": (selected_scan.get("scanner_versions") if selected_scan else {}) or {},
    }

    meta_out = dict(report_meta or {
        "investigation_id": investigation_id,
        "recon_id": investigation_id,
        "campaign_name": campaign_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })
    meta_out.setdefault("investigation_name", campaign_name)
    meta_out.setdefault("generated_at_ist", format_ist(meta_out.get("generated_at")))
    if selected_scan and not meta_out.get("scan_id"):
        meta_out["scan_id"] = selected_scan.get("scan_id")
        meta_out["run_number"] = selected_scan.get("run_number")
        meta_out["run_label"] = selected_scan.get("run_label")

    classification_counts = {
        "Confirmed Vulnerability": confidence_counts.get("Confirmed Vulnerability", 0),
        "Observed Scanner Match": confidence_counts.get("Observed Scanner Match", 0),
        "Potential Vulnerability": confidence_counts.get("Potential Vulnerability", 0),
        "Informational Observation": confidence_counts.get("Informational Observation", 0),
        "Marked False Positive": confidence_counts.get("Marked False Positive", 0),
        "Unverified / Informational": confidence_counts.get("Unverified / Informational", 0),
        "Service / Port Exposure": len(discovered_ports),
    }

    return {
        "report_metadata": meta_out,
        "campaign": {
            "investigation_id": investigation_id,
            "name": campaign_name,
            "status": campaign_status,
            "target_value": target_value,
            "purpose": camp.get("purpose") or inv.get("description") or "Security Assessment",
            "creator_id": camp.get("creator_id") or inv.get("creator_id"),
            "authorized_by": camp.get("authorized_by"),
            "created_at": camp.get("created_at") or inv.get("created_at"),
            "created_at_ist": format_ist(camp.get("created_at") or inv.get("created_at")),
        },
        "scan_run": selected_scan,
        "available_runs": all_scans,
        "executive_analysis": {
            "overall_posture": overall_posture,
            "exposure_score": score if risk_score_available else None,
            "exposure_level": level if risk_score_available else "Risk score unavailable",
            "risk_score_available": risk_score_available,
            "affected_target_count": len(affected_hosts) or len(targets) or 1,
            "findings_count": len(findings),
            "non_info_findings_count": len(findings) - sev_counts["Informational"],
            "confirmed_count": confirmed_count,
            "potential_count": potential_count,
            "open_ports_count": len(discovered_ports),
            "exposed_services_count": len(exposed_services_list),
            "evidence_count": len(evidence),
            "key_takeaways": key_takeaways,
        },
        "vulnerability_analysis": {
            "severity_distribution": sev_counts,
            "confidence_breakdown": dict(confidence_counts),
            "classification_breakdown": classification_counts,
            "affected_hosts": affected_hosts,
            "discovered_ports": discovered_ports,
            "exposed_services": exposed_services_list,
            "vulnerability_categories": dict(category_counts),
            "cve_inventory": sorted(cve_set),
            "scanner_coverage": scanner_statuses,
            "scanner_contribution": scanner_contribution,
            "top_findings": sorted_findings[:25],
            "all_findings": sorted_findings,
        },
        "analytics": {
            "severity_distribution": sev_counts,
            "classification_breakdown": classification_counts,
            "scanner_contribution": scanner_contribution,
            "affected_hosts": affected_hosts[:15],
            "exposed_services": exposed_services_list,
            "vulnerability_categories": dict(category_counts),
            "overall_risk_score": risk_interpretation,
            "historical_trend": trend_rows,
            "trend_completed_count": trend_completed_count,
            "run_duration": duration_human(
                selected_scan.get("started_at") if selected_scan else None,
                selected_scan.get("completed_at") if selected_scan else None,
                selected_scan.get("duration_seconds") if selected_scan else None,
            ),
        },
        "risk_interpretation": risk_interpretation,
        "remediation_analysis": {
            "roadmap": roadmap,
            "remediation_status_counts": dict(remediation_counts),
            "prioritized_actions": action_items,
            "verification_guidance": (
                "Re-execute targeted validation scans after applying patches/hardening and update each finding's remediation status with verification notes."
            ),
        },
        "assessment_limitations": {
            "campaign_status": campaign_status,
            "is_complete": not has_incomplete_coverage,
            "incomplete_warning": (
                "Assessment has incomplete, cancelled, failed, or unavailable scanner stages. Absence of findings in incomplete stages is NOT clean."
                if has_incomplete_coverage
                else None
            ),
            "coverage_gaps": dedup_gaps,
            "failed_stages": failed_stages,
            "partial_stages": partial_stages,
            "scope_constraints": scope_constraints,
        },
        "evidence_references": evidence[:50],
    }


def compare_investigation_runs(
    investigation_id: str,
    base_scan_id: str,
    target_scan_id: str,
    repo: FootprintIQRepository,
) -> Dict[str, Any]:
    """
    Compares two independent ScanExecution runs (`base_scan_id` baseline -> `target_scan_id` newer run)
    under the same Investigation. Honestly guards resolved status when the newer run did not execute
    or failed the originating scanner.
    """
    base_scan = repo.get_scan(base_scan_id)
    target_scan = repo.get_scan(target_scan_id)
    if not base_scan or (base_scan.get("recon_id") != investigation_id and base_scan.get("investigation_id") != investigation_id):
        raise ValueError(f"Baseline scan run '{base_scan_id}' not found under investigation '{investigation_id}'.")
    if not target_scan or (target_scan.get("recon_id") != investigation_id and target_scan.get("investigation_id") != investigation_id):
        raise ValueError(f"Comparison target scan run '{target_scan_id}' not found under investigation '{investigation_id}'.")

    base_findings = repo.list_findings(investigation_id, scan_id=base_scan_id)
    target_findings = repo.list_findings(investigation_id, scan_id=target_scan_id)
    base_bundle = load_campaign_results_bundle(investigation_id, repo, scan_id=base_scan_id)
    target_bundle = load_campaign_results_bundle(investigation_id, repo, scan_id=target_scan_id)

    base_map = {_finding_fingerprint(f): f for f in base_findings}
    target_map = {_finding_fingerprint(f): f for f in target_findings}

    # Determine which tools cleanly completed in target_scan so missing findings aren't falsely marked resolved
    target_contrib = _build_scanner_contribution_matrix(
        findings=target_findings,
        scanner_statuses=target_bundle.get("scanner_statuses") or [],
        scanners_executed=target_bundle.get("scanners_executed") or [],
        passive_results=target_bundle.get("passive_results") or [],
        discovered_ports=target_bundle.get("discovered_ports") or [],
        selected_scan=target_scan,
    )
    target_tool_states = {row["tool_key"]: row["execution_state"] for row in target_contrib}

    new_findings = [f for fp, f in target_map.items() if fp not in base_map]
    persistent_findings = []
    severity_changes = []
    for fp, tf in target_map.items():
        if fp in base_map:
            bf = base_map[fp]
            persistent_findings.append(tf)
            b_sev = _normalize_severity(bf.get("severity"))
            t_sev = _normalize_severity(tf.get("severity"))
            if b_sev != t_sev:
                severity_changes.append({
                    "title": tf.get("title"),
                    "target_ip": tf.get("target_ip"),
                    "port": tf.get("port"),
                    "previous_severity": b_sev,
                    "current_severity": t_sev,
                })

    resolved_findings = []
    not_reassessed_findings = []
    for fp, bf in base_map.items():
        if fp in target_map:
            continue
        tkey = _map_source_to_tool_key(bf.get("detection_source"))
        if target_tool_states.get(tkey) in ("executed_with_findings", "executed_zero_findings"):
            resolved_findings.append(bf)
        else:
            not_reassessed_findings.append({
                **bf,
                "reason": f"Scanner '{bf.get('detection_source')}' did not execute cleanly in {target_scan.get('run_label')}.",
            })

    base_hosts = {str(h.get("ip")) for h in (base_bundle.get("active_hosts") or []) if h.get("ip")} | {
        str(f.get("target_ip")) for f in base_findings if f.get("target_ip")
    }
    target_hosts = {str(h.get("ip")) for h in (target_bundle.get("active_hosts") or []) if h.get("ip")} | {
        str(f.get("target_ip")) for f in target_findings if f.get("target_ip")
    }

    base_ports = {f"{p.get('port')}/{p.get('protocol', 'tcp')} ({p.get('service') or 'unknown'})" for p in (base_bundle.get("discovered_ports") or []) if p.get("port")}
    target_ports = {f"{p.get('port')}/{p.get('protocol', 'tcp')} ({p.get('service') or 'unknown'})" for p in (target_bundle.get("discovered_ports") or []) if p.get("port")}

    base_exp = ExposureScoringEngine.calculate_investigation_exposure(base_findings)
    target_exp = ExposureScoringEngine.calculate_investigation_exposure(target_findings)
    score_delta = round(target_exp["exposure_score"] - base_exp["exposure_score"], 1)

    warnings: List[str] = []
    if set(base_scan.get("selected_scanners") or []) != set(target_scan.get("selected_scanners") or []):
        warnings.append("Selected scanners differ between the two scan runs; findings from unexecuted scanners cannot be compared directly.")
    if str(base_scan.get("status") or "").lower() in ("failed", "cancelled", "interrupted", "partially_completed") or str(target_scan.get("status") or "").lower() in ("failed", "cancelled", "interrupted", "partially_completed"):
        warnings.append("One or both compared runs ended incomplete/failed; differences may reflect partial coverage rather than actual remediation.")
    if base_scan.get("target") != target_scan.get("target"):
        warnings.append(f"Target scope changed between runs ('{base_scan.get('target')}' -> '{target_scan.get('target')}').")
    if base_scan.get("scanner_versions") != target_scan.get("scanner_versions"):
        warnings.append("Scanner versions/configurations differed between runs.")
    if not_reassessed_findings:
        warnings.append(f"{len(not_reassessed_findings)} earlier finding(s) were NOT marked resolved because their detecting scanner did not complete in the newer run.")

    return {
        "investigation_id": investigation_id,
        "base_run": base_scan,
        "target_run": target_scan,
        "summary": {
            "base_findings_count": len(base_findings),
            "target_findings_count": len(target_findings),
            "new_findings_count": len(new_findings),
            "resolved_findings_count": len(resolved_findings),
            "persistent_findings_count": len(persistent_findings),
            "not_reassessed_count": len(not_reassessed_findings),
            "severity_changes_count": len(severity_changes),
            "base_risk_score": base_exp["exposure_score"],
            "target_risk_score": target_exp["exposure_score"],
            "risk_score_delta": score_delta,
        },
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "persistent_findings": persistent_findings,
        "not_reassessed_findings": not_reassessed_findings,
        "severity_changes": severity_changes,
        "hosts_added": sorted(target_hosts - base_hosts),
        "hosts_removed": sorted(base_hosts - target_hosts),
        "services_added": sorted(target_ports - base_ports),
        "services_removed": sorted(base_ports - target_ports),
        "limitation_warnings": warnings,
    }
