"""
FootprintIQ - Unified Investigation Report Generator
Produces professional executive PDF investigation reports covering:
- Executive summary & overall exposure score (0 - 100)
- Investigation scope & authorized targets
- OSINT passive reconnaissance findings (theHarvester, WHOIS/RDAP/DNS)
- Discovered network services & ports (Nmap)
- Nmap NSE findings
- ProjectDiscovery Nuclei findings
- Nessus scanner findings (and preserved historical Greenbone/OpenVAS records)
- Investigation entity & relationship graph summary (Maltego-compatible)
- Correlated vulnerabilities & severity distribution
- Cryptographic evidence hashes (SHA-256) & SeaweedFS references
- Prioritized remediation roadmap
"""

import os
import json
import ipaddress
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import hashlib
from xml.sax.saxutils import escape as _xml_escape

logger = logging.getLogger("FootprintIQ.Report")

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing, String, Rect, Line
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import HorizontalBarChart, VerticalBarChart

from src.services.exposure_scoring import ExposureScoringEngine
from src.services.finding_translator import (
    explain_finding_plain_language,
    classify_confidence,
    build_dynamic_remediation_roadmap,
)
from src.services.report_analysis_service import (
    _build_scanner_contribution_matrix,
    _map_source_to_tool_key,
    build_investigation_report_filename,
    normalize_report_type_tag,
)
from src.storage.seaweedfs_client import SeaweedFSClient
from src.utils.timezone import duration_human, format_ist


SEVERITY_HEX = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#d97706",
    "Low": "#2563eb",
    "Informational": "#64748b",
}

CLASSIFICATION_HEX = {
    "Confirmed Vulnerability": "#dc2626",
    "Observed Scanner Match": "#ea580c",
    "Potential Vulnerability": "#d97706",
    "Informational Observation": "#2563eb",
    "Marked False Positive": "#64748b",
    "Unverified / Informational": "#94a3b8",
    "Service / Port Exposure": "#0d9488",
}


def _build_severity_visual_drawing(sev_counts: Dict[str, int]) -> Drawing:
    """Renders crisp side-by-side vector Donut & Severity Bar chart in ReportLab."""
    d = Drawing(540, 175)
    d.add(Rect(0, 0, 540, 175, fillColor=colors.HexColor("#f8fafc"), strokeColor=colors.HexColor("#cbd5e1"), strokeWidth=0.6))
    d.add(String(12, 158, "Severity Distribution Breakdown", fontName="Helvetica-Bold", fontSize=9.5, fillColor=colors.HexColor("#0f172a")))
    d.add(String(275, 158, "Severity Counts (Non-Empty Buckets & Scale)", fontName="Helvetica-Bold", fontSize=9.5, fillColor=colors.HexColor("#0f172a")))

    order = ["Critical", "High", "Medium", "Low", "Informational"]
    vals = [int(sev_counts.get(k, 0) or 0) for k in order]
    total = sum(vals)

    if total > 0:
        non_zero = [(k, v) for k, v in zip(order, vals) if v > 0]
        pie = Pie()
        pie.x = 24
        pie.y = 22
        pie.width = 108
        pie.height = 108
        pie.innerRadiusFraction = 0.52
        pie.data = [v for _, v in non_zero]
        pie.labels = None
        pie.slices.strokeColor = colors.white
        pie.slices.strokeWidth = 1.0
        for idx, (k, _v) in enumerate(non_zero):
            pie.slices[idx].fillColor = colors.HexColor(SEVERITY_HEX[k])
        d.add(pie)
        d.add(String(78, 72, str(total), textAnchor="middle", fontName="Helvetica-Bold", fontSize=13, fillColor=colors.HexColor("#0f172a")))
        d.add(String(78, 60, "Findings", textAnchor="middle", fontName="Helvetica", fontSize=7, fillColor=colors.HexColor("#64748b")))

        ly = 122
        for k, v in zip(order, vals):
            d.add(Rect(148, ly, 8, 8, fillColor=colors.HexColor(SEVERITY_HEX[k]), strokeWidth=0))
            d.add(String(160, ly + 1, f"{k}: {v}", fontName="Helvetica", fontSize=8, fillColor=colors.HexColor("#334155")))
            ly -= 19
    else:
        d.add(Rect(24, 30, 108, 100, fillColor=colors.HexColor("#f1f5f9"), strokeColor=colors.HexColor("#cbd5e1"), strokeWidth=0.5))
        d.add(String(78, 78, "0 Findings", textAnchor="middle", fontName="Helvetica-Bold", fontSize=10, fillColor=colors.HexColor("#64748b")))

    bar = VerticalBarChart()
    bar.x = 290
    bar.y = 28
    bar.width = 232
    bar.height = 112
    bar.data = [vals]
    bar.categoryAxis.categoryNames = ["Crit", "High", "Med", "Low", "Info"]
    bar.categoryAxis.labels.fontSize = 7.5
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = max(max(vals) + 1, 2)
    bar.valueAxis.labels.fontSize = 7.5
    bar.valueAxis.visibleGrid = True
    bar.valueAxis.gridStrokeColor = colors.HexColor("#e2e8f0")
    bar.bars[0].fillColor = colors.HexColor("#2563eb")
    for idx, k in enumerate(order):
        bar.bars[(0, idx)].fillColor = colors.HexColor(SEVERITY_HEX[k])
    bar.barLabelFormat = "%d"
    bar.barLabels.nudge = 6
    bar.barLabels.fontSize = 7.5
    d.add(bar)
    return d


def _build_scanner_contribution_drawing(scanner_contrib: List[Dict[str, Any]]) -> Optional[Drawing]:
    """Renders horizontal vector bar chart of findings contributed across configured scanners."""
    if not scanner_contrib:
        return None
    rows = scanner_contrib[:7]
    d = Drawing(540, 200)
    d.add(Rect(0, 0, 540, 200, fillColor=colors.HexColor("#f8fafc"), strokeColor=colors.HexColor("#cbd5e1"), strokeWidth=0.6))
    d.add(String(12, 184, "Scanner Coverage & Deduplicated Findings by Tool", fontName="Helvetica-Bold", fontSize=9.5, fillColor=colors.HexColor("#0f172a")))
    d.add(String(12, 172, "Tags: [FOUND]=Completed w/ findings | [0-HITS]=Completed w/ 0 findings | [PARTIAL]=Incomplete | [FAILED] | [SKIP] | [OFF]=Not selected", fontName="Helvetica", fontSize=6.4, fillColor=colors.HexColor("#475569")))

    labels = []
    counts = []
    for item in reversed(rows):
        name = str(item.get("tool_label") or item.get("tool_name") or item.get("tool_key") or "Tool")[:24]
        state = str(item.get("execution_state") or "not_selected")
        tag = {
            "executed_with_findings": "FOUND",
            "partial": "PARTIAL",
            "executed_zero_findings": "0-HITS",
            "failed": "FAILED",
            "failed_or_error": "FAILED",
            "skipped": "SKIP",
            "skipped_or_unavailable": "SKIP",
            "not_selected": "OFF",
        }.get(state, "N/A")
        labels.append(f"{name} [{tag}]")
        uniq_val = item.get("unique_count")
        if uniq_val is None:
            uniq_val = item.get("unique_findings", 0)
        counts.append(int(uniq_val or 0))

    bar = HorizontalBarChart()
    bar.x = 200
    bar.y = 22
    bar.width = 305
    bar.height = 136
    bar.data = [counts]
    bar.categoryAxis.categoryNames = labels
    bar.categoryAxis.labels.fontSize = 7.2
    max_c = max(counts) if counts else 0
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = max(max_c + 1, 2)
    bar.valueAxis.forceZero = True
    if bar.valueAxis.valueMax <= 6:
        bar.valueAxis.valueStep = 1
    bar.valueAxis.labels.fontSize = 7.5
    bar.valueAxis.visibleGrid = True
    bar.valueAxis.gridStrokeColor = colors.HexColor("#e2e8f0")
    bar.bars[0].fillColor = colors.HexColor("#0d9488")
    bar.barLabelFormat = "%d"
    bar.barLabels.nudge = 8
    bar.barLabels.fontSize = 7.5
    d.add(bar)
    return d


def _build_hosts_and_categories_drawing(
    affected_hosts: List[Dict[str, Any]],
    vuln_categories: Dict[str, int],
) -> Optional[Drawing]:
    """Renders side-by-side vector charts for Affected Hosts & Vulnerability Categories."""
    if not affected_hosts and not vuln_categories:
        return None
    d = Drawing(540, 175)
    d.add(Rect(0, 0, 540, 175, fillColor=colors.HexColor("#f8fafc"), strokeColor=colors.HexColor("#cbd5e1"), strokeWidth=0.6))
    d.add(String(12, 158, "Top Affected Hosts / Targets", fontName="Helvetica-Bold", fontSize=9, fillColor=colors.HexColor("#0f172a")))
    d.add(String(278, 158, "Vulnerability Categories", fontName="Helvetica-Bold", fontSize=9, fillColor=colors.HexColor("#0f172a")))

    if affected_hosts:
        h_rows = list(reversed(affected_hosts[:6]))
        bar_h = HorizontalBarChart()
        bar_h.x = 92
        bar_h.y = 22
        bar_h.width = 158
        bar_h.height = 122
        h_vals = []
        for h in h_rows:
            fc = h.get("finding_count")
            if fc is None:
                fc = h.get("findings_count")
            if fc is None:
                fc = h.get("total", 0)
            h_vals.append(int(fc or 0))
        bar_h.data = [h_vals]
        bar_h.categoryAxis.categoryNames = [str(h.get("host") or h.get("target_ip") or "host")[:16] for h in h_rows]
        bar_h.categoryAxis.labels.fontSize = 7
        max_h = max(h_vals) if h_vals else 0
        bar_h.valueAxis.valueMin = 0
        bar_h.valueAxis.valueMax = max(max_h + 1, 2)
        bar_h.valueAxis.forceZero = True
        if bar_h.valueAxis.valueMax <= 6:
            bar_h.valueAxis.valueStep = 1
        bar_h.valueAxis.labels.fontSize = 7
        bar_h.bars[0].fillColor = colors.HexColor("#dc2626")
        bar_h.barLabelFormat = "%d"
        bar_h.barLabels.nudge = 6
        bar_h.barLabels.fontSize = 7
        d.add(bar_h)
    else:
        d.add(String(18, 85, "No affected hosts recorded.", fontName="Helvetica", fontSize=8, fillColor=colors.HexColor("#64748b")))

    if vuln_categories:
        c_rows = sorted(vuln_categories.items(), key=lambda kv: kv[1], reverse=True)[:6]
        c_rows.reverse()
        bar_c = HorizontalBarChart()
        bar_c.x = 372
        bar_c.y = 22
        bar_c.width = 148
        bar_c.height = 122
        c_vals = [int(v or 0) for _, v in c_rows]
        bar_c.data = [c_vals]
        bar_c.categoryAxis.categoryNames = [str(k)[:18] for k, _ in c_rows]
        bar_c.categoryAxis.labels.fontSize = 7
        max_cat = max(c_vals) if c_vals else 0
        bar_c.valueAxis.valueMin = 0
        bar_c.valueAxis.valueMax = max(max_cat + 1, 2)
        bar_c.valueAxis.forceZero = True
        if bar_c.valueAxis.valueMax <= 6:
            bar_c.valueAxis.valueStep = 1
        bar_c.valueAxis.labels.fontSize = 7
        bar_c.bars[0].fillColor = colors.HexColor("#7c3aed")
        bar_c.barLabelFormat = "%d"
        bar_c.barLabels.nudge = 6
        bar_c.barLabels.fontSize = 7
        d.add(bar_c)
    else:
        d.add(String(282, 85, "No vulnerability categories mapped.", fontName="Helvetica", fontSize=8, fillColor=colors.HexColor("#64748b")))

    return d


class UnifiedReportGenerator:
    def __init__(self, storage_client: Optional[SeaweedFSClient] = None):
        self.storage = storage_client or SeaweedFSClient()

    def generate_pdf_report(
        self,
        investigation: Dict[str, Any],
        targets: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]],
        output_path: Optional[str] = None,
        report_format: str = "executive",
        results_bundle: Optional[Dict[str, Any]] = None,
        analysis: Optional[Dict[str, Any]] = None,
        generated_by: Optional[str] = None,
        scan_run: Optional[Dict[str, Any]] = None,
        comparison_data: Optional[Dict[str, Any]] = None,
    ) -> str:
        inv_id = investigation.get("recon_id") or investigation.get("investigation_id", "REC-UNKNOWN")
        inv_title = investigation.get("name") or investigation.get("title", "Reconnaissance Audit")
        camp_status = (scan_run.get("status") if scan_run else None) or investigation.get("status", "Completed")
        norm_type = normalize_report_type_tag(report_format)
        is_technical = norm_type in ("technical", "nmap", "nse", "nuclei", "nessus")

        format_tag = {
            "executive": "Executive",
            "technical": "Technical",
            "active": "Active Recon",
            "passive": "Passive OSINT",
            "combined": "Combined Recon & Vuln",
            "nmap": "Nmap Service",
            "nse": "Nmap NSE",
            "nuclei": "Nuclei Vuln",
            "nessus": "Nessus Vuln",
        }.get(norm_type, norm_type.title())

        if not output_path:
            reports_dir = os.path.abspath("reports")
            os.makedirs(reports_dir, exist_ok=True)
            run_num = (scan_run or {}).get("run_number")
            fname = build_investigation_report_filename(
                inv_title,
                norm_type,
                reports_dir=reports_dir,
                run_number=run_num,
            )
            output_path = os.path.join(reports_dir, fname)
        else:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "TitleStyle",
            parent=styles["Heading1"],
            fontSize=21,
            leading=25,
            textColor=colors.HexColor("#1e293b"),
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            "SubtitleStyle",
            parent=styles["Normal"],
            fontSize=10.5,
            leading=14,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=14
        )
        h2_style = ParagraphStyle(
            "Heading2Style",
            parent=styles["Heading2"],
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=12,
            spaceAfter=8
        )
        body_style = ParagraphStyle(
            "BodyStyle",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155")
        )
        callout_style = ParagraphStyle(
            "CalloutStyle",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#065f46")
        )
        warn_style = ParagraphStyle(
            "WarnStyle",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#991b1b")
        )
        cell_style = ParagraphStyle(
            "CellWrapStyle",
            parent=body_style,
            fontSize=7.2,
            leading=9.6,
            wordWrap="CJK",
        )
        mono_wrap_style = ParagraphStyle(
            "MonoWrapStyle",
            parent=cell_style,
            fontName="Courier",
            fontSize=6.5,
            leading=8.6,
            wordWrap="CJK",
        )

        elements = []
        bundle = results_bundle or {}
        passive_results = bundle.get("passive_results") or []
        active_hosts = bundle.get("active_hosts") or []
        discovered_ports = bundle.get("discovered_ports") or []
        scanner_statuses = bundle.get("scanner_statuses") or []
        failed_stages = list(bundle.get("failed_stages") or [])
        partial_stages = list(bundle.get("partial_stages") or [])

        # 1. Header & Title Block (IST presentation)
        inv_purpose = _xml_escape(str(investigation.get("purpose") or "Security Assessment"))
        assess_date = format_ist(
            (scan_run.get("started_at") if scan_run else None)
            or investigation.get("created_at")
            or datetime.now(timezone.utc)
        )
        generated_ist = format_ist(datetime.now(timezone.utc))
        try:
            raw_cfg = (scan_run.get("scan_config_json") if scan_run and scan_run.get("scan_config_json") else None) or investigation.get("scan_config_json") or "{}"
            scan_cfg = json.loads(raw_cfg) if isinstance(raw_cfg, str) else (raw_cfg or {})
        except Exception:
            scan_cfg = {}

        header_text = f"FootprintIQ — {format_tag} Security Assessment Report"
        elements.append(Paragraph(header_text, title_style))
        actor_line = f" &bull; Generated By: <b>{_xml_escape(str(generated_by))}</b>" if generated_by else ""
        run_line = ""
        if scan_run:
            r_lbl = scan_run.get("run_label") or (f"Run {int(scan_run['run_number']):03d}" if scan_run.get("run_number") else scan_run.get("scan_id"))
            r_dur = duration_human(scan_run.get("started_at"), scan_run.get("completed_at"), scan_run.get("duration_seconds"))
            run_line = f" &bull; Scan Run: <b>{_xml_escape(str(r_lbl))}</b> ({_xml_escape(str(scan_run.get('scan_id', '')))}, Duration: {_xml_escape(r_dur)})"
        elements.append(Paragraph(
            f"Investigation: <b>{_xml_escape(str(inv_title))}</b> &bull; ID: <b>{_xml_escape(str(inv_id))}</b>{run_line} &bull; "
            f"Purpose: <b>{inv_purpose}</b> &bull; Assessed: {_xml_escape(assess_date)} &bull; "
            f"Generated: {_xml_escape(generated_ist)}{actor_line} &bull; Outcome: <b>{_xml_escape(str(camp_status))}</b>",
            subtitle_style
        ))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=12))

        incomplete_notice_stages = list(dict.fromkeys(list(failed_stages) + list(partial_stages)))
        norm_camp_status = str(camp_status or "").replace("_", " ").lower()
        if norm_camp_status in ("failed", "partially completed", "cancelled", "interrupted") or incomplete_notice_stages:
            elements.append(Paragraph(
                f"<b>Assessment Coverage Notice:</b> Campaign status is <b>{_xml_escape(str(camp_status))}</b>. "
                + (f"Incomplete or failed modules: {_xml_escape(', '.join(incomplete_notice_stages))}. " if incomplete_notice_stages else "")
                + "Absence of findings in incomplete or aborted modules must not be interpreted as clean security status.",
                warn_style
            ))
            elements.append(Spacer(1, 10))

        # 2. Executive Summary & Exposure Scoring
        exposure = ExposureScoringEngine.calculate_investigation_exposure(
            findings,
            discovered_ports=discovered_ports,
        )
        ri_from_analysis = (analysis or {}).get("risk_interpretation") or {}
        risk_available = ri_from_analysis.get("risk_score_available", True)
        score = ri_from_analysis.get("exposure_score") if risk_available else None
        if score is None and risk_available:
            score = exposure["exposure_score"]
        level = str(ri_from_analysis.get("exposure_level") or (exposure["exposure_level"] if risk_available else "Risk score unavailable"))
        score_text = f"{score} / 100 ({level})" if (risk_available and score is not None) else "Risk score unavailable"

        if is_technical:
            elements.append(Paragraph("1. Technical Methodology & Exposure Summary", h2_style))
            summary_p = (
                f"This technical deliverable documents the verified reconnaissance and vulnerability assessment executed under "
                f"Investigation <b>{_xml_escape(str(inv_title))}</b> ({_xml_escape(str(inv_id))}). Results combine executed modules across passive intelligence, active port/service discovery, "
                f"and enabled vulnerability assessment engines. "
                f"Aggregate risk index: <b>{_xml_escape(score_text)}</b> across <b>{len(findings)} security finding(s)</b> and <b>{len(discovered_ports)} open port(s)</b>."
            )
        else:
            elements.append(Paragraph("1. Executive Overview & Security Posture", h2_style))
            summary_p = (
                f"This report summarizes security exposures identified during Investigation <b>{_xml_escape(str(inv_title))}</b> ({_xml_escape(str(inv_id))}). "
                f"The overall calculated risk rating is <b>{_xml_escape(score_text)}</b> across <b>{len(targets) or 1} scoped asset(s)</b>, "
                f"<b>{len(discovered_ports)} exposed service port(s)</b>, and <b>{len(findings)} security finding(s)</b>, "
                f"including <b>{exposure['severity_counts']['Critical']} Critical</b> and <b>{exposure['severity_counts']['High']} High</b> severity items."
            )
        elements.append(Paragraph(summary_p, body_style))
        elements.append(Spacer(1, 10))

        sev_counts = exposure["severity_counts"]
        kpi_data = [
            ["Critical", "High", "Medium", "Low", "Informational", "Open Ports", "Risk Score"],
            [
                str(sev_counts["Critical"]),
                str(sev_counts["High"]),
                str(sev_counts["Medium"]),
                str(sev_counts["Low"]),
                str(sev_counts["Informational"]),
                str(len(discovered_ports)),
                f"{score}/100 ({level})" if (risk_available and score is not None) else "Unavailable",
            ]
        ]
        t_kpi = Table(kpi_data, colWidths=[68, 65, 68, 62, 85, 78, 114])
        t_kpi.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#475569")),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('FONTSIZE', (0, 1), (-1, 1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t_kpi)
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(
            f"<b>Severity Distribution:</b> Critical: {sev_counts['Critical']} | High: {sev_counts['High']} | "
            f"Medium: {sev_counts['Medium']} | Low: {sev_counts['Low']} | Informational: {sev_counts['Informational']}",
            body_style
        ))
        elements.append(Spacer(1, 10))

        # 1B. ReportLab Native Vector Risk & Scanner Analytics Charts
        analytics = (analysis or {}).get("analytics") or {}
        elements.append(Paragraph("1B. Visual Risk & Coverage Analytics", h2_style))
        sev_drawing = _build_severity_visual_drawing(analytics.get("severity_distribution") or sev_counts)
        elements.append(KeepTogether([sev_drawing, Spacer(1, 8)]))

        scanner_contrib = analytics.get("scanner_contribution") or []
        if not scanner_contrib:
            scanner_contrib = _build_scanner_contribution_matrix(
                findings=findings,
                scanner_statuses=scanner_statuses,
                scanners_executed=bundle.get("scanners_executed") or [],
                passive_results=passive_results,
                discovered_ports=discovered_ports,
                selected_scan=scan_run,
            )
        sc_drawing = _build_scanner_contribution_drawing(scanner_contrib)
        if sc_drawing:
            elements.append(KeepTogether([sc_drawing, Spacer(1, 8)]))

        aff_hosts = analytics.get("affected_hosts") or []
        v_cats = analytics.get("vulnerability_categories") or {}
        hc_drawing = _build_hosts_and_categories_drawing(aff_hosts, v_cats)
        if hc_drawing:
            elements.append(KeepTogether([hc_drawing, Spacer(1, 8)]))
        elements.append(Spacer(1, 6))

        # 2B. Selected Scan Methods Summary
        sel_cats = [str(c).title() for c in (scan_cfg.get("selected_categories") or [])]
        if not sel_cats and investigation.get("selected_scan_types"):
            sel_cats = [str(investigation.get("selected_scan_types")).title()]
        p_checks = (scan_cfg.get("passive") or {}).get("selected_checks") or []
        a_cfg = scan_cfg.get("active") or {}
        v_cfg = scan_cfg.get("vulnerability") or {}
        v_engines = v_cfg.get("engines") or ([v_cfg.get("engine")] if v_cfg.get("engine") else [])
        methods_text = (
            f"<b>Selected Categories:</b> {_xml_escape(', '.join(sel_cats) or 'Standard')} &bull; "
            f"<b>Passive Modules:</b> {_xml_escape(', '.join(p_checks[:12]) if p_checks else 'None')} &bull; "
            f"<b>Active Options:</b> {_xml_escape(str(a_cfg.get('port_mode', 'N/A')) if a_cfg else 'None')} &bull; "
            f"<b>Vulnerability Engines:</b> {_xml_escape(', '.join(str(e).upper() for e in v_engines if e) or 'None')}"
        )
        elements.append(Paragraph("2. Selected Scan Methods & Assessment Scope", h2_style))
        elements.append(Paragraph(methods_text, body_style))
        elements.append(Spacer(1, 8))
        target_rows = [["Target", "Type", "Description", "Scope Basis", "Exclusions"]]
        for t in (targets or [{"target": investigation.get("target_value", "N/A"), "target_type": investigation.get("target_type", "ipv4"), "name": inv_title, "scope": investigation.get("scope_description") or "Authorized Campaign Scope"}]):
            target_rows.append([
                Paragraph(_xml_escape(str(t.get("target", "N/A"))), cell_style),
                Paragraph(_xml_escape(str(t.get("target_type", "ipv4"))), cell_style),
                Paragraph(_xml_escape(str(t.get("name", inv_title))), cell_style),
                Paragraph(_xml_escape(str(t.get("scope", "Authorized Scope"))), cell_style),
                Paragraph(_xml_escape(str(investigation.get("excluded_targets") or "None")), cell_style),
            ])
        t_targets = Table(target_rows, colWidths=[110, 55, 145, 140, 90], repeatRows=1)
        t_targets.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_targets)
        elements.append(Spacer(1, 10))

        # Scanner Execution Coverage (unified with Section 1B chart and scan_run data)
        if scanner_statuses:
            elements.append(Paragraph("3. Executed Assessment Modules & Coverage", h2_style))
            sc_rows = [["Module / Scanner", "Target", "Status", "Details"]]
            for ss in scanner_statuses:
                sc_name = str(ss.get("scanner", "Module"))
                raw_st = str(ss.get("status") or "").upper()
                tool_key = _map_source_to_tool_key(sc_name)
                if tool_key == "nmap" and "nse" in sc_name.lower():
                    tool_key = "nmap_nse"
                matched_findings = [
                    f for f in findings
                    if _map_source_to_tool_key(f.get("detection_source")) == tool_key
                ]
                f_count = ss.get("findings")
                if f_count is None:
                    f_count = len(matched_findings)
                if raw_st in ("PARTIAL", "TIMEOUT", "INCOMPLETE"):
                    disp_status = "PARTIAL"
                elif raw_st in ("FAILED", "ERROR"):
                    disp_status = "FAILED"
                elif raw_st in ("SKIPPED", "NOT_APPLICABLE"):
                    disp_status = "SKIPPED"
                elif raw_st in ("READ_ONLY", "READ_ONLY_LICENSE", "UNAVAILABLE", "BLOCKED", "CANCELLED"):
                    disp_status = raw_st.replace("_", " ")
                elif raw_st in ("COMPLETED", "COMPLETED_WITH_FINDINGS", "COMPLETED_ZERO_FINDINGS"):
                    disp_status = (
                        "COMPLETED WITH FINDINGS"
                        if (raw_st == "COMPLETED_WITH_FINDINGS" or int(f_count or 0) > 0)
                        else "COMPLETED WITH ZERO FINDINGS"
                    )
                else:
                    disp_status = raw_st or "UNKNOWN"
                det_text = str(ss.get("detail") or ss.get("details") or "")
                sc_rows.append([
                    Paragraph(_xml_escape(sc_name), cell_style),
                    Paragraph(_xml_escape(str(ss.get("target", ""))), cell_style),
                    Paragraph(_xml_escape(disp_status), cell_style),
                    Paragraph(_xml_escape(det_text), cell_style),
                ])
            t_sc = Table(sc_rows, colWidths=[115, 85, 115, 225], repeatRows=1)
            t_sc.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(t_sc)
            elements.append(Spacer(1, 10))

        # 4. Passive & Active Recon Results Summary
        if passive_results or discovered_ports:
            elements.append(Paragraph("4. Reconnaissance Observations (Passive & Active)", h2_style))
            if passive_results:
                for pr in passive_results:
                    p_tgt = str(pr.get("target", "") or "")
                    dom = pr.get("domain_intel") or {}
                    osint = pr.get("osint_intel") or {}
                    infra = pr.get("infrastructure_intel") or {}
                    ip_scope_raw = pr.get("ip_scope")
                    ip_scope = ip_scope_raw if isinstance(ip_scope_raw, dict) else (
                        {
                            "scope_label": str(ip_scope_raw),
                            "is_non_public": any(
                                k in str(ip_scope_raw).lower()
                                for k in ("private", "rfc", "loopback", "link-local", "cgnat", "reserved")
                            ),
                        }
                        if ip_scope_raw
                        else {}
                    )
                    is_ip_target = str(pr.get("target_kind") or "").lower() == "ip" or bool(ip_scope_raw)
                    if not is_ip_target and p_tgt:
                        try:
                            ipaddress.ip_address(p_tgt.split("/")[0].strip())
                            is_ip_target = True
                        except ValueError:
                            is_ip_target = False

                    if is_ip_target:
                        whois_data = dom.get("whois") or {}
                        rdap_data = dom.get("rdap") or {}
                        scope_lbl = str(
                            ip_scope.get("scope_label")
                            or ip_scope.get("label")
                            or rdap_data.get("scope")
                            or whois_data.get("scope")
                            or ("Private / Internal Network (RFC 1918)" if whois_data.get("ownership_status") == "private_ip_rfc1918" else "IP Target")
                        )
                        is_non_pub = bool(
                            ip_scope.get("is_non_public")
                            or ip_scope.get("is_public") is False
                            or str(rdap_data.get("status") or "") == "LOCAL_PRIVATE_IP"
                            or bool(whois_data.get("ownership_status"))
                        )
                        own_lbl = str(
                            whois_data.get("isp")
                            or whois_data.get("organization")
                            or rdap_data.get("org")
                            or "Local / Unregistered Private Range"
                        )
                        if "internet assigned numbers authority" in own_lbl.lower() and is_non_pub:
                            own_lbl = str(rdap_data.get("org") or scope_lbl)
                        rdns = dom.get("reverse_dns") or infra.get("reverse_dns") or []
                        if isinstance(rdns, str):
                            rdns_list = [rdns]
                        elif isinstance(rdns, dict):
                            ptrs = rdns.get("ptr_records") or []
                            if isinstance(ptrs, list) and ptrs:
                                rdns_list = [str(p) for p in ptrs if p]
                            elif rdns.get("status") == "NO_PTR":
                                rdns_list = []
                            else:
                                rdns_list = [f"{k}: {v}" for k, v in rdns.items() if v]
                        elif isinstance(rdns, list):
                            rdns_list = []
                            for x in rdns:
                                if isinstance(x, dict):
                                    ptrs = x.get("ptr_records") or []
                                    if isinstance(ptrs, list) and ptrs:
                                        rdns_list.extend(str(p) for p in ptrs if p)
                                    elif x.get("ptr") or x.get("hostname"):
                                        rdns_list.append(str(x.get("ptr") or x.get("hostname")))
                                elif x:
                                    rdns_list.append(str(x))
                        else:
                            rdns_list = [str(rdns)] if rdns else []
                        rdns_str = ", ".join(rdns_list[:6]) if rdns_list else "None recorded"
                        elements.append(Paragraph(
                            f"<b>Passive Intelligence (IP Target — {_xml_escape(p_tgt)}):</b> "
                            f"Address Scope: {_xml_escape(scope_lbl)} &bull; "
                            f"Network Ownership / ISP: {_xml_escape(own_lbl)} &bull; "
                            f"Reverse DNS (PTR): {_xml_escape(rdns_str)} &bull; "
                            f"Domain-only checks (WHOIS domain, DNS zone, CT subdomains, email OSINT, SPF/DMARC): Skipped (not applicable to IP target)",
                            body_style
                        ))
                    else:
                        whois_org = ((dom.get("whois") or {}).get("organization") or (dom.get("whois") or {}).get("registrar") or "Not disclosed")
                        subs = dom.get("subdomains") or []
                        ips = infra.get("resolved_ips") or []
                        emails = osint.get("emails") or []
                        sec_post = dom.get("dns_security") or {}
                        spf_ok = "Configured" if sec_post.get("spf_configured") else "Not detected"
                        dmarc_ok = "Configured" if sec_post.get("dmarc_configured") else "Not detected"
                        elements.append(Paragraph(
                            f"<b>Passive Intelligence ({_xml_escape(p_tgt)}):</b> Registrar/Org: {_xml_escape(str(whois_org))} &bull; "
                            f"Resolved IPs: {_xml_escape(', '.join(str(i) for i in ips[:5]) or 'None')} &bull; "
                            f"Subdomains Discovered: {len(subs)} &bull; Public Contacts: {len(emails)} &bull; SPF: {spf_ok} &bull; DMARC: {dmarc_ok}",
                            body_style
                        ))
                    elements.append(Spacer(1, 4))

            if discovered_ports:
                port_rows = [["Host IP", "Port / Proto", "State", "Service", "Detected Version"]]
                for p in discovered_ports[:60]:
                    port_rows.append([
                        Paragraph(_xml_escape(str(p.get("target_ip", ""))), cell_style),
                        Paragraph(_xml_escape(f"{p.get('port')}/{p.get('protocol', 'tcp')}"), cell_style),
                        Paragraph(_xml_escape(str(p.get("state", "open"))), cell_style),
                        Paragraph(_xml_escape(str(p.get("service", "unknown"))), cell_style),
                        Paragraph(_xml_escape(str(p.get("service_version") or "—")), cell_style),
                    ])
                t_ports = Table(port_rows, colWidths=[105, 75, 55, 100, 205], repeatRows=1)
                t_ports.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 7.5),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                ]))
                elements.append(t_ports)
                elements.append(Spacer(1, 10))

        # 5. Findings Section (Full Non-Truncated Breakdown)
        if is_technical:
            elements.append(Paragraph("5. Detailed Vulnerability Findings (Technical Breakdown)", h2_style))
            vuln_rows = [["Host:Port", "Svc", "Severity", "Classification", "CVE / CVSS", "Title", "Source"]]
            for f in findings:
                cve_text = str(f.get("cve_identifiers") or "—")
                if f.get("cvss_score"):
                    cve_text += f" ({f.get('cvss_score')})"
                conf_cls = classify_confidence(f)
                if conf_cls != "Observed Scanner Match":
                    conf_cls = conf_cls.replace(" Vulnerability", "")
                vuln_rows.append([
                    Paragraph(_xml_escape(f"{f.get('target_ip')}:{f.get('port') or 'all'}"), cell_style),
                    Paragraph(_xml_escape(str(f.get("service") or "—")), cell_style),
                    Paragraph(_xml_escape(str(f.get("severity", "Info"))), cell_style),
                    Paragraph(_xml_escape(conf_cls), cell_style),
                    Paragraph(_xml_escape(cve_text), cell_style),
                    Paragraph(_xml_escape(str(f.get("title", "Untitled"))), cell_style),
                    Paragraph(_xml_escape(str(f.get("detection_source", "scanner"))), cell_style),
                ])
            if len(vuln_rows) > 1:
                t_vulns = Table(vuln_rows, colWidths=[72, 48, 48, 82, 82, 150, 58], repeatRows=1)
                t_vulns.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 7),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                ]))
                elements.append(t_vulns)
            else:
                elements.append(Paragraph("No vulnerability findings recorded in this campaign.", body_style))
        else:
            elements.append(Paragraph("5. Key Findings & Plain-Language Risk Explanations", h2_style))
            if findings:
                for idx, f in enumerate(findings[:25], start=1):
                    exp = explain_finding_plain_language(f)
                    meta_line = (
                        f"Host: {_xml_escape(str(f.get('target_ip') or 'N/A'))}"
                        + (f":{_xml_escape(str(f.get('port')))}" if f.get("port") else "")
                        + f" &bull; Source: {_xml_escape(str(f.get('detection_source') or 'scanner'))}"
                        + (f" &bull; CVE: {_xml_escape(str(f.get('cve_identifiers')))}" if f.get("cve_identifiers") else "")
                        + (f" &bull; CVSS: {f.get('cvss_score')}" if f.get("cvss_score") is not None else "")
                    )
                    card_data = [
                        [Paragraph(f"<b>#{idx}: {_xml_escape(str(f.get('title') or 'Untitled'))}</b> — <b>{_xml_escape(exp['seriousness'])}</b> ({_xml_escape(exp['confidence_label'])})", body_style)],
                        [Paragraph(f"<b>Attribution:</b> {meta_line}", cell_style)],
                        [Paragraph(f"<b>What was discovered:</b> {_xml_escape(exp['what_discovered'])}", body_style)],
                        [Paragraph(f"<b>Why it matters:</b> {_xml_escape(exp['why_important'])}", body_style)],
                        [Paragraph(f"<b>Potential impact:</b> {_xml_escape(exp['potential_impact'])}", body_style)],
                        [Paragraph(f"<b>Recommended action:</b> {_xml_escape(exp['recommended_action'])}", callout_style)]
                    ]
                    t_card = Table(card_data, colWidths=[540])
                    t_card.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#eff6ff")),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#fafafa")),
                        ('BOX', (0, 0), (-1, -1), 0.8, colors.HexColor("#cbd5e1")),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                        ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ]))
                    elements.append(KeepTogether([t_card, Spacer(1, 6)]))
            else:
                elements.append(Paragraph("No security vulnerabilities were recorded in the completed scan modules.", body_style))

        elements.append(Spacer(1, 10))

        # 6. Evidence & Entity Graph Summary
        elements.append(Paragraph("6. Collected Evidence References &amp; Entity Graph Attribution", h2_style))
        graph_ev = [ev for ev in (evidence or []) if ev.get("evidence_type") in ("intelligence_graph_json", "maltego_import", "intelligence_graph_overlay")]
        if graph_ev:
            elements.append(Paragraph(
                f"<b>Investigation Entity Graph / Maltego Interchange:</b> {len(graph_ev)} integrity-verified graph artifact(s) archived (GraphML/Maltego CSV export available in platform).",
                body_style,
            ))
            elements.append(Spacer(1, 4))
        if evidence:
            ev_rows = [["Type", "File Name", "Size (B)", "SHA-256 Digest", "Storage Ref"]]
            for ev in evidence[:50]:
                fid = str(ev.get("seaweed_fid") or "").strip()
                storage_ref = f"SeaweedFS ({fid})" if fid else "Local Cache Only"
                sha_full = str(ev.get("sha256_hash") or "").strip() or "—"
                ev_rows.append([
                    Paragraph(_xml_escape(str(ev.get("evidence_type", "artifact"))), cell_style),
                    Paragraph(_xml_escape(str(ev.get("file_name", "evidence.bin"))), cell_style),
                    Paragraph(_xml_escape(str(ev.get("file_size", 0))), cell_style),
                    Paragraph(_xml_escape(sha_full), mono_wrap_style),
                    Paragraph(_xml_escape(storage_ref), cell_style),
                ])
            t_ev = Table(ev_rows, colWidths=[75, 165, 48, 147, 105], repeatRows=1)
            t_ev.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 7.5),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(t_ev)
        else:
            elements.append(Paragraph("No external binary or raw XML evidence artifacts were attached for this campaign run.", body_style))
        elements.append(Spacer(1, 10))

        # 7. Dynamic Prioritized Recommendations & Integrated Report Analysis
        elements.append(Paragraph("7. Integrated Report Analysis, Risk Interpretation & Remediation", h2_style))
        roadmap = build_dynamic_remediation_roadmap(findings, failed_scanners=list(dict.fromkeys(list(failed_stages) + list(partial_stages))))
        roadmap_html = "<br/>".join([f"{i}. {_xml_escape(str(item))}" for i, item in enumerate(roadmap, start=1)])

        if analysis:
            ri = analysis.get("risk_interpretation") or {}
            va = analysis.get("vulnerability_analysis") or {}
            al = analysis.get("assessment_limitations") or {}
            drivers = ri.get("drivers") or []
            driver_lines = "<br/>".join([f"&bull; {_xml_escape(str(d))}" for d in drivers])
            conf_summary = _xml_escape(str(ri.get("confidence_summary") or ""))
            formula_note = _xml_escape(str(ri.get("formula_note") or exposure.get("scoring_formula") or ""))
            cves = va.get("cve_inventory") or []
            cve_line = _xml_escape(", ".join(cves[:12])) if cves else "None recorded"
            roadmap_html = (
                f"<b>Risk Interpretation ({_xml_escape(score_text)}):</b><br/>"
                f"Confidence Profile: {conf_summary} &bull; CVEs Referenced: {cve_line}<br/>"
                + (f"<i>Scoring Formula: {formula_note}</i><br/>" if formula_note else "")
                + f"{driver_lines}<br/><br/>"
                f"<b>Prioritized Remediation Roadmap:</b><br/>{roadmap_html}"
            )
            extra_gaps = list(al.get("coverage_gaps") or [])
        else:
            extra_gaps = []

        unavail_notes = list(extra_gaps)
        seen_signatures = {str(g).strip().lower() for g in unavail_notes}

        def _append_unique_gap(check_key: str, text_line: str) -> None:
            norm_line = str(text_line).strip().lower()
            norm_key = str(check_key or "").strip().lower()
            if norm_line in seen_signatures:
                return
            if norm_key and any(norm_key in existing for existing in seen_signatures):
                return
            seen_signatures.add(norm_line)
            unavail_notes.append(text_line)

        for ss in scanner_statuses:
            s_st = str(ss.get("status") or "").upper()
            if s_st in ("FAILED", "ERROR", "PARTIAL", "TIMEOUT", "INCOMPLETE", "UNAVAILABLE", "READ_ONLY", "READ_ONLY_LICENSE", "BLOCKED", "CANCELLED"):
                sc_n = str(ss.get("scanner") or "Scanner")
                _append_unique_gap(sc_n, f"{sc_n} ({s_st}): {ss.get('detail') or ss.get('details') or 'Engine incomplete.'}")

        for pr in passive_results:
            for uc in (pr.get("unavailable_checks") or []):
                uc_id = str(uc.get("id") or "passive_check")
                uc_reason = str(uc.get("reason") or "Not applicable or unavailable.")
                _append_unique_gap(f"passive check '{uc_id}'", f"Passive check '{uc_id}': {uc_reason}")

        if unavail_notes:
            limitations_html = "<br/>&bull; ".join(_xml_escape(str(item)) for item in unavail_notes[:25])
            limitations_block = f"<b>Assessment Limitations &amp; Coverage Verification:</b><br/>&bull; {limitations_html}<br/>"
        else:
            limitations_block = (
                "<b>Assessment Limitations &amp; Coverage Verification:</b> All enabled modules executed cleanly within authorized scope.<br/>"
            )

        roadmap_html += (
            f"<br/><br/>{limitations_block}"
            "<i>Scope Notice: Findings strictly reflect the authorized targets, selected modules, and host permissions active at execution time.</i>"
        )
        elements.append(Paragraph(roadmap_html, body_style))

        # 8. Optional Historical Scan-Run Trend & Run-to-Run Delta Comparison
        trend_rows = (analytics.get("historical_trend") or [])
        if len(trend_rows) >= 2 or comparison_data:
            elements.append(Spacer(1, 10))
            elements.append(Paragraph("8. Historical Scan-Run Trend &amp; Baseline Comparison", h2_style))
            if len(trend_rows) >= 2:
                tr_data = [["Run", "Scan Type", "Executed (IST)", "Status", "Crit/High", "Total", "Risk Score"]]
                for tr in trend_rows[-10:]:
                    tr_data.append([
                        Paragraph(_xml_escape(str(tr.get("run_label") or tr.get("scan_id") or "Run")), cell_style),
                        Paragraph(_xml_escape(str(tr.get("scan_type") or "—")), cell_style),
                        Paragraph(_xml_escape(str(tr.get("started_at_ist") or "—")), cell_style),
                        Paragraph(_xml_escape(str(tr.get("status") or "—")), cell_style),
                        f"{tr.get('Critical', 0)} / {tr.get('High', 0)}",
                        str(tr.get("total_findings", 0)),
                        f"{tr['risk_score']}/100" if tr.get("risk_score") is not None else "Unavailable",
                    ])
                t_tr = Table(tr_data, colWidths=[60, 105, 115, 70, 58, 42, 90], repeatRows=1)
                t_tr.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 7.5),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                ]))
                elements.append(t_tr)
                elements.append(Spacer(1, 8))

            if comparison_data:
                csum = comparison_data.get("summary") or {}
                b_lbl = (comparison_data.get("base_run") or {}).get("run_label") or "Baseline"
                t_lbl = (comparison_data.get("target_run") or {}).get("run_label") or "Current"
                comp_text = (
                    f"<b>Baseline Comparison ({_xml_escape(str(b_lbl))} &rarr; {_xml_escape(str(t_lbl))}):</b> "
                    f"New Findings: <b>{csum.get('new_findings_count', 0)}</b> &bull; "
                    f"Verified Resolved: <b>{csum.get('resolved_findings_count', 0)}</b> &bull; "
                    f"Persistent: <b>{csum.get('persistent_findings_count', 0)}</b> &bull; "
                    f"Not Reassessed: <b>{csum.get('not_reassessed_count', 0)}</b> &bull; "
                    f"Risk Score Delta: <b>{csum.get('risk_score_delta', 0):+g}</b>"
                )
                elements.append(Paragraph(comp_text, body_style))
                for w in (comparison_data.get("limitation_warnings") or [])[:4]:
                    elements.append(Paragraph(f"&bull; <i>Note: {_xml_escape(str(w))}</i>", warn_style))

        # Build document
        doc.build(elements)
        logger.info(f"Generated {format_tag} PDF report at: {output_path}")

        # Preserve generated PDF in SeaweedFS
        try:
            with open(output_path, "rb") as f:
                pdf_bytes = f.read()
            self.storage.upload_content(
                content=pdf_bytes,
                file_name=os.path.basename(output_path),
                investigation_id=inv_id,
                evidence_type="pdf_report",
                content_type="application/pdf"
            )
        except Exception as e:
            logger.warning(f"SeaweedFS upload notice for PDF: {e}")

        return output_path

