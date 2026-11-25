"""
OSINT-RECON Preliminary Digital Footprint Intelligence Report Generator
Generates professional PDF intelligence reports using ReportLab with 14 structured sections.
Distinguishes passive findings from defensive recommendations without arbitrary risk scores.
"""

import os
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)
from reportlab.pdfgen import canvas

from src.schema import PassivePipelineResult, ActiveReconResult


class NumberedCanvas(canvas.Canvas):
    """Adds 'Page X of Y' footers and document classification to every page."""

    doc_title = "OSINT-RECON: Digital Footprint Intelligence Report"
    sub_title = "Passive Reconnaissance Evidence"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#718096"))

        # Header
        self.drawString(36, 762, self.doc_title)
        self.drawRightString(576, 762, self.sub_title)
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(36, 756, 576, 756)

        # Footer
        self.line(36, 40, 576, 40)
        footer_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 28, footer_text)
        self.drawString(36, 28, "CONFIDENTIAL — STRICTLY FOR AUTHORIZED DEFENSIVE AUDITING")
        self.restoreState()


class ActiveNumberedCanvas(NumberedCanvas):
    """Canvas subclass specifically configured with Active Reconnaissance headers."""
    doc_title = "OSINT-RECON: Active Reconnaissance Intelligence Report"
    sub_title = "Controlled Nmap Evidence"



class PDFReportGenerator:
    """
    Generates a structured, multi-section PDF Digital Footprint Intelligence Report
    from a PassivePipelineResult.
    """

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "reports"
        os.makedirs(self.output_dir, exist_ok=True)
        self.styles = self._setup_styles()

    def _setup_styles(self) -> Dict[str, ParagraphStyle]:
        """Configures typography and paragraph styles."""
        base = getSampleStyleSheet()
        custom = {}

        custom["Title"] = ParagraphStyle(
            "DocTitle",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#1A365D"),
            spaceAfter=4
        )

        custom["Subtitle"] = ParagraphStyle(
            "DocSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#4A5568"),
            spaceAfter=10
        )

        custom["H1"] = ParagraphStyle(
            "Heading1",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#2B6CB0"),
            spaceBefore=12,
            spaceAfter=6
        )

        custom["H2"] = ParagraphStyle(
            "Heading2",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#2D3748"),
            spaceBefore=8,
            spaceAfter=4
        )

        custom["Body"] = ParagraphStyle(
            "BodyText",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#2D3748"),
            spaceAfter=4
        )

        custom["BodyBold"] = ParagraphStyle(
            "BodyBold",
            parent=custom["Body"],
            fontName="Helvetica-Bold"
        )

        custom["TableText"] = ParagraphStyle(
            "TableText",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#2D3748")
        )

        custom["TableHeader"] = ParagraphStyle(
            "TableHeader",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white
        )

        custom["Observation"] = ParagraphStyle(
            "Observation",
            parent=custom["Body"],
            textColor=colors.HexColor("#2C5282"),
            leftIndent=10
        )

        custom["Recommendation"] = ParagraphStyle(
            "Recommendation",
            parent=custom["Body"],
            textColor=colors.HexColor("#9B2C2C"),
            leftIndent=10
        )

        return custom

    def generate(self, result: PassivePipelineResult, output_path: Optional[str] = None) -> str:
        """
        Builds the PDF document from the PassivePipelineResult.
        Returns the absolute path to the generated PDF.
        """
        if not output_path:
            filename = f"{result.scan_id}_report.pdf"
            output_path = os.path.join(self.output_dir, filename)

        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=46,
            bottomMargin=46
        )

        story = []

        # 1. Title Banner & Header
        story.append(Paragraph("DIGITAL FOOTPRINT INTELLIGENCE REPORT", self.styles["Title"]))
        story.append(Paragraph("OSINT-RECON Automated Passive Reconnaissance Framework — W2 Baseline", self.styles["Subtitle"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2B6CB0"), spaceAfter=10))

        # 2 & 3 & 4 & 5. Metadata Block (Scan ID, Target Domain, Date/Time, Overall Status)
        status_color = "#276749" if result.overall_status == "SUCCESS" else ("#C05621" if result.overall_status == "PARTIAL" else "#9B2C2C")
        status_badge = f"<font color='{status_color}'><b>{result.overall_status}</b></font>"

        meta_data = [
            [
                Paragraph("<b>Target Domain:</b>", self.styles["TableText"]),
                Paragraph(f"<b>{result.target_domain}</b>", self.styles["TableText"]),
                Paragraph("<b>Scan Session ID:</b>", self.styles["TableText"]),
                Paragraph(f"<code>{result.scan_id}</code>", self.styles["TableText"]),
            ],
            [
                Paragraph("<b>Collection Start (UTC):</b>", self.styles["TableText"]),
                Paragraph(result.start_time_utc[:19] + "Z", self.styles["TableText"]),
                Paragraph("<b>Collection End (UTC):</b>", self.styles["TableText"]),
                Paragraph(result.end_time_utc[:19] + "Z", self.styles["TableText"]),
            ],
            [
                Paragraph("<b>Assessment Type:</b>", self.styles["TableText"]),
                Paragraph("Passive Reconnaissance (Non-Intrusive)", self.styles["TableText"]),
                Paragraph("<b>Overall Status:</b>", self.styles["TableText"]),
                Paragraph(status_badge, self.styles["TableText"]),
            ]
        ]

        meta_table = Table(meta_data, colWidths=[110, 160, 110, 160])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # 6. Executive Summary
        story.append(Paragraph("1. Executive Summary", self.styles["H1"]))
        summary = result.summary or {}
        exec_text = (
            f"This intelligence report compiles passive digital footprint indicators for <b>{result.target_domain}</b>. "
            f"A total of <b>{summary.get('total_normalized_findings', 0)}</b> distinct finding(s) were gathered across authoritative "
            f"WHOIS registries, DNS zone lookups, and public search engine indices without sending active probes to the target network. "
            f"Identified perimeter assets include <b>{summary.get('subdomains_count', 0)}</b> subdomain(s), "
            f"<b>{summary.get('ip_addresses_count', 0)}</b> IP address(es), and <b>{summary.get('email_addresses_count', 0)}</b> public email address(es)."
        )
        story.append(Paragraph(exec_text, self.styles["Body"]))

        # Metric summary row
        metric_data = [
            [
                Paragraph("<b>Subdomains</b>", self.styles["TableHeader"]),
                Paragraph("<b>IP Addresses</b>", self.styles["TableHeader"]),
                Paragraph("<b>Mail Servers (MX)</b>", self.styles["TableHeader"]),
                Paragraph("<b>Name Servers</b>", self.styles["TableHeader"]),
                Paragraph("<b>Exposed Emails</b>", self.styles["TableHeader"])
            ],
            [
                Paragraph(str(summary.get("subdomains_count", 0)), self.styles["TableText"]),
                Paragraph(str(summary.get("ip_addresses_count", 0)), self.styles["TableText"]),
                Paragraph(str(summary.get("mail_servers_count", 0)), self.styles["TableText"]),
                Paragraph(str(summary.get("nameservers_count", 0)), self.styles["TableText"]),
                Paragraph(str(summary.get("email_addresses_count", 0)), self.styles["TableText"])
            ]
        ]
        metric_table = Table(metric_data, colWidths=[108, 108, 108, 108, 108])
        metric_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2B6CB0")),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#EDF2F7")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(metric_table)
        story.append(Spacer(1, 10))

        # 7. WHOIS Findings
        story.append(Paragraph("2. WHOIS Registration Findings", self.styles["H1"]))
        whois_rec = next((r for r in result.collector_records if r.recon_category == "whois"), None)
        whois_data = whois_rec.whois_data if whois_rec else None

        if whois_data:
            ns_str = ", ".join(whois_data.name_servers) if whois_data.name_servers else "None listed"
            status_str = ", ".join(whois_data.status) if whois_data.status else "Active / Unspecified"
            whois_table_data = [
                [Paragraph("<b>Registrar:</b>", self.styles["TableText"]), Paragraph(whois_data.registrar or "Unavailable", self.styles["TableText"])],
                [Paragraph("<b>Creation Date:</b>", self.styles["TableText"]), Paragraph(whois_data.creation_date or "Unavailable", self.styles["TableText"])],
                [Paragraph("<b>Expiration Date:</b>", self.styles["TableText"]), Paragraph(whois_data.expiration_date or "Unavailable", self.styles["TableText"])],
                [Paragraph("<b>Last Updated:</b>", self.styles["TableText"]), Paragraph(whois_data.updated_date or "Unavailable", self.styles["TableText"])],
                [Paragraph("<b>Authoritative NS:</b>", self.styles["TableText"]), Paragraph(ns_str, self.styles["TableText"])],
                [Paragraph("<b>Domain Status:</b>", self.styles["TableText"]), Paragraph(status_str, self.styles["TableText"])],
                [Paragraph("<b>Registrant Org:</b>", self.styles["TableText"]), Paragraph(whois_data.registrant_organization or "[Redacted/Private]", self.styles["TableText"])],
                [Paragraph("<b>Registrant Country:</b>", self.styles["TableText"]), Paragraph(whois_data.registrant_country or "Unavailable", self.styles["TableText"])],
                [Paragraph("<b>DNSSEC Status:</b>", self.styles["TableText"]), Paragraph(whois_data.dnssec or "Unsigned / Unspecified", self.styles["TableText"])],
            ]
            w_table = Table(whois_table_data, colWidths=[120, 420])
            w_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F7FAFC")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]))
            story.append(w_table)
        else:
            story.append(Paragraph("<i>No WHOIS records available or query did not return registration data.</i>", self.styles["Body"]))

        story.append(Spacer(1, 10))

        # 8. DNS Findings
        story.append(Paragraph("3. DNS Zone Findings", self.styles["H1"]))
        dns_rec = next((r for r in result.collector_records if r.recon_category == "dns"), None)
        dns_records = dns_rec.dns_records if dns_rec else []

        if dns_records:
            dns_table_data = [
                [
                    Paragraph("<b>Type</b>", self.styles["TableHeader"]),
                    Paragraph("<b>Record Value</b>", self.styles["TableHeader"]),
                    Paragraph("<b>TTL</b>", self.styles["TableHeader"]),
                    Paragraph("<b>Priority</b>", self.styles["TableHeader"])
                ]
            ]
            for r in dns_records:
                dns_table_data.append([
                    Paragraph(f"<b>{r.record_type}</b>", self.styles["TableText"]),
                    Paragraph(r.value, self.styles["TableText"]),
                    Paragraph(str(r.ttl) if r.ttl else "-", self.styles["TableText"]),
                    Paragraph(str(r.priority) if r.priority is not None else "-", self.styles["TableText"])
                ])
            dns_tbl = Table(dns_table_data, colWidths=[55, 385, 50, 50])
            dns_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2B6CB0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]))
            story.append(dns_tbl)
        else:
            story.append(Paragraph("<i>No DNS records resolved.</i>", self.styles["Body"]))

        story.append(Spacer(1, 10))

        # 9. Subdomain Discoveries
        story.append(Paragraph("4. Subdomain & Host Discoveries", self.styles["H1"]))
        subdomains = [f for f in result.deduplicated_findings if f.finding_type == "subdomain"]
        if subdomains:
            sub_table_data = [
                [
                    Paragraph("<b>Discovered Hostname</b>", self.styles["TableHeader"]),
                    Paragraph("<b>Source Tools</b>", self.styles["TableHeader"]),
                    Paragraph("<b>Status</b>", self.styles["TableHeader"])
                ]
            ]
            for s in subdomains:
                sub_table_data.append([
                    Paragraph(s.finding_value, self.styles["TableText"]),
                    Paragraph(", ".join(s.source_tools), self.styles["TableText"]),
                    Paragraph(s.status, self.styles["TableText"])
                ])
            sub_tbl = Table(sub_table_data, colWidths=[300, 160, 80])
            sub_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2B6CB0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]))
            story.append(sub_tbl)
        else:
            story.append(Paragraph("<i>No subdomains discovered via passive enumeration.</i>", self.styles["Body"]))

        story.append(Spacer(1, 10))

        # 10. Public Email Findings
        story.append(Paragraph("5. Public Email Exposures", self.styles["H1"]))
        emails = [f for f in result.deduplicated_findings if f.finding_type == "email"]
        if emails:
            email_data = [
                [
                    Paragraph("<b>Email Address</b>", self.styles["TableHeader"]),
                    Paragraph("<b>Discovered Via</b>", self.styles["TableHeader"])
                ]
            ]
            for e in emails:
                email_data.append([
                    Paragraph(e.finding_value, self.styles["TableText"]),
                    Paragraph(", ".join(e.source_tools), self.styles["TableText"])
                ])
            em_tbl = Table(email_data, colWidths=[340, 200])
            em_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2B6CB0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]))
            story.append(em_tbl)
        else:
            story.append(Paragraph("<i>No public email addresses were identified.</i>", self.styles["Body"]))

        story.append(Spacer(1, 10))

        # 11. Evidence Sources
        story.append(Paragraph("6. Evidence Preservation & Source Attribution", self.styles["H1"]))
        ev_data = [
            [
                Paragraph("<b>Collector Module</b>", self.styles["TableHeader"]),
                Paragraph("<b>Tool Name & Version</b>", self.styles["TableHeader"]),
                Paragraph("<b>Status</b>", self.styles["TableHeader"]),
                Paragraph("<b>Preserved Evidence Reference</b>", self.styles["TableHeader"])
            ]
        ]
        for rec in result.collector_records:
            ev_data.append([
                Paragraph(rec.recon_category.upper(), self.styles["TableText"]),
                Paragraph(f"{rec.tool_info.name} ({rec.tool_info.version})", self.styles["TableText"]),
                Paragraph(rec.scan_status, self.styles["TableText"]),
                Paragraph(rec.raw_output_reference or rec.evidence_source, self.styles["TableText"])
            ])
        ev_tbl = Table(ev_data, colWidths=[90, 110, 60, 280])
        ev_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2B6CB0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ]))
        story.append(ev_tbl)
        story.append(Spacer(1, 10))

        # 12. Collection Errors & Limitations
        story.append(Paragraph("7. Collection Errors & Technical Limitations", self.styles["H1"]))
        if result.errors:
            for err in result.errors:
                story.append(Paragraph(f"&bull; <font color='#9B2C2C'>{err}</font>", self.styles["Body"]))
        else:
            story.append(Paragraph("<i>All passive collectors executed cleanly without recorded errors.</i>", self.styles["Body"]))

        story.append(Spacer(1, 10))

        # 13. Defensive Observations
        story.append(Paragraph("8. Defensive Security Observations", self.styles["H1"]))
        story.append(Paragraph("<i>Observations derived strictly from passive configuration analysis:</i>", self.styles["Body"]))
        if result.defensive_observations:
            for obs in result.defensive_observations:
                story.append(Paragraph(f"&bull; {obs}", self.styles["Observation"]))
        else:
            story.append(Paragraph("<i>No significant configuration anomalies detected.</i>", self.styles["Body"]))

        story.append(Spacer(1, 10))

        # 14. Recommended Defensive Actions
        story.append(Paragraph("9. Recommended Defensive Hardening Actions", self.styles["H1"]))
        story.append(Paragraph("<i>Actionable defensive recommendations to harden digital perimeter posture:</i>", self.styles["Body"]))
        if result.recommended_actions:
            for act in result.recommended_actions:
                story.append(Paragraph(f"&bull; <b>[ACTION]</b> {act}", self.styles["Recommendation"]))
        else:
            story.append(Paragraph("<i>Maintain existing perimeter DNS and registry security practices.</i>", self.styles["Body"]))

        doc.build(story, canvasmaker=NumberedCanvas)
        return os.path.abspath(output_path)

    def generate_active_report(self, result: ActiveReconResult, output_path: Optional[str] = None) -> str:
        """
        Builds an executive-level Active Reconnaissance PDF report from ActiveReconResult.
        """
        if not output_path:
            filename = f"{result.scan_id}_report.pdf"
            output_path = os.path.join(self.output_dir, filename)

        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=46,
            bottomMargin=46
        )

        story = []

        # 1. Title Banner & Framework Identification
        story.append(Paragraph("ACTIVE RECONNAISSANCE INTELLIGENCE REPORT", self.styles["Title"]))
        story.append(Paragraph("OSINT-RECON Controlled Nmap Active Reconnaissance Framework — W3 Baseline", self.styles["Subtitle"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#C53030"), spaceAfter=10))

        # 2. Metadata Block (Scan ID, Target, Date/Time, Scanner, Profile, Status)
        status_color = "#276749" if result.overall_status == "SUCCESS" else ("#C05621" if result.overall_status in ("PARTIAL", "BLOCKED") else "#9B2C2C")
        status_badge = f"<font color='{status_color}'><b>{result.overall_status}</b></font>"

        scanner_str = f"{result.scan_metadata.scanner.upper()} {result.scan_metadata.version}" if result.scan_metadata else "NMAP 7.99"

        meta_data = [
            [
                Paragraph("<b>Target Host:</b>", self.styles["TableText"]),
                Paragraph(f"<b>{result.target}</b>", self.styles["TableText"]),
                Paragraph("<b>Scan Session ID:</b>", self.styles["TableText"]),
                Paragraph(f"<code>{result.scan_id}</code>", self.styles["TableText"]),
            ],
            [
                Paragraph("<b>Collection Start (UTC):</b>", self.styles["TableText"]),
                Paragraph(result.start_time_utc[:19] + "Z", self.styles["TableText"]),
                Paragraph("<b>Collection End (UTC):</b>", self.styles["TableText"]),
                Paragraph(result.end_time_utc[:19] + "Z", self.styles["TableText"]),
            ],
            [
                Paragraph("<b>Active Scanner:</b>", self.styles["TableText"]),
                Paragraph(scanner_str, self.styles["TableText"]),
                Paragraph("<b>Overall Status:</b>", self.styles["TableText"]),
                Paragraph(status_badge, self.styles["TableText"]),
            ],
            [
                Paragraph("<b>Scan Profile:</b>", self.styles["TableText"]),
                Paragraph(f"<code>{result.scan_profile}</code>", self.styles["TableText"]),
                Paragraph("<b>Operator:</b>", self.styles["TableText"]),
                Paragraph(result.authorization_record.operator if result.authorization_record else "asip_ali", self.styles["TableText"]),
            ]
        ]

        meta_table = Table(meta_data, colWidths=[110, 160, 110, 160])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF5F5")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#FEB2B2")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#FED7D7")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # 3. Executive Summary
        story.append(Paragraph("1. Executive Summary", self.styles["H1"]))
        summary = result.summary or {}
        host_count = len(result.hosts)
        host_status = result.hosts[0].status.upper() if result.hosts else "UNKNOWN"
        open_count = summary.get("open_ports_count", 0)
        filtered_count = summary.get("filtered_ports_count", 0)
        closed_count = summary.get("closed_ports_count", 0)
        services_count = summary.get("services_detected_count", 0)

        exec_text = (
            f"This active reconnaissance intelligence report summarizes controlled Nmap port and service enumeration "
            f"for target <b>{result.target}</b> under authorized profile <code>{result.scan_profile}</code>. "
            f"The target host state was determined to be <b>{host_status}</b>. A total of <b>{open_count}</b> open TCP port(s) "
            f"were observed, with <b>{services_count}</b> distinct service banner(s) and software version(s) identified. "
            f"All probes were strictly non-intrusive without vulnerability exploitation or denial-of-service scripts."
        )
        story.append(Paragraph(exec_text, self.styles["Body"]))

        # Metrics row
        metric_data = [
            [
                Paragraph("<b>Host Status</b>", self.styles["TableHeader"]),
                Paragraph("<b>Open Ports</b>", self.styles["TableHeader"]),
                Paragraph("<b>Filtered Ports</b>", self.styles["TableHeader"]),
                Paragraph("<b>Closed Ports</b>", self.styles["TableHeader"]),
                Paragraph("<b>Detected Services</b>", self.styles["TableHeader"])
            ],
            [
                Paragraph(host_status, self.styles["TableText"]),
                Paragraph(str(open_count), self.styles["TableText"]),
                Paragraph(str(filtered_count), self.styles["TableText"]),
                Paragraph(str(closed_count), self.styles["TableText"]),
                Paragraph(str(services_count), self.styles["TableText"])
            ]
        ]
        metric_table = Table(metric_data, colWidths=[108, 108, 108, 108, 108])
        metric_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#C53030")),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#FFF5F5")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#FEB2B2")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#FED7D7")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(metric_table)
        story.append(Spacer(1, 10))

        # 4. Target Authorization & Scope Control Record
        story.append(Paragraph("2. Target Authorization & Scope Record", self.styles["H1"]))
        auth = result.authorization_record
        auth_data = [
            [Paragraph("<b>Authorized Scope:</b>", self.styles["TableText"]), Paragraph(auth.scope if auth else "Lab Scope", self.styles["TableText"])],
            [Paragraph("<b>Target Category:</b>", self.styles["TableText"]), Paragraph(auth.category if auth else "intentionally_vulnerable_lab", self.styles["TableText"])],
            [Paragraph("<b>Authorization Status:</b>", self.styles["TableText"]), Paragraph(auth.authorization_status if auth else "AUTHORIZED_LOCAL_LAB", self.styles["TableText"])],
            [Paragraph("<b>Authorized Operator:</b>", self.styles["TableText"]), Paragraph(auth.operator if auth else "asip_ali", self.styles["TableText"])],
            [Paragraph("<b>Permitted Profiles:</b>", self.styles["TableText"]), Paragraph(", ".join(auth.permitted_profiles) if auth else "lab-basic", self.styles["TableText"])],
            [Paragraph("<b>Authorization Notes:</b>", self.styles["TableText"]), Paragraph(auth.notes or "Local lab VM authorized for active reconnaissance.", self.styles["TableText"])]
        ]
        auth_tbl = Table(auth_data, colWidths=[130, 410])
        auth_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F7FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ]))
        story.append(auth_tbl)
        story.append(Spacer(1, 10))

        # 5. Port & Service Discovery Table
        story.append(Paragraph("3. Observed Port & Service Discoveries", self.styles["H1"]))
        all_ports = []
        for h in result.hosts:
            all_ports.extend(h.ports)

        open_ports = [p for p in all_ports if p.state == "open"]

        if open_ports:
            port_table_data = [
                [
                    Paragraph("<b>Port</b>", self.styles["TableHeader"]),
                    Paragraph("<b>Proto</b>", self.styles["TableHeader"]),
                    Paragraph("<b>State</b>", self.styles["TableHeader"]),
                    Paragraph("<b>Service</b>", self.styles["TableHeader"]),
                    Paragraph("<b>Product & Version</b>", self.styles["TableHeader"]),
                    Paragraph("<b>Detection Reason</b>", self.styles["TableHeader"])
                ]
            ]
            for p in open_ports:
                s_name = p.service.name if p.service else "unknown"
                prod_ver = []
                if p.service and p.service.product:
                    prod_ver.append(p.service.product)
                if p.service and p.service.version:
                    prod_ver.append(p.service.version)
                prod_str = " ".join(prod_ver) if prod_ver else "Unknown / Banner Unparsed"

                port_table_data.append([
                    Paragraph(f"<b>{p.portid}</b>", self.styles["TableText"]),
                    Paragraph(p.protocol.upper(), self.styles["TableText"]),
                    Paragraph(f"<font color='#276749'><b>{p.state}</b></font>", self.styles["TableText"]),
                    Paragraph(s_name, self.styles["TableText"]),
                    Paragraph(prod_str, self.styles["TableText"]),
                    Paragraph(p.reason or "-", self.styles["TableText"])
                ])

            port_tbl = Table(port_table_data, colWidths=[45, 45, 50, 75, 235, 90])
            port_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#C53030")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]))
            story.append(port_tbl)
        else:
            story.append(Paragraph("<i>No open TCP ports were observed on target host.</i>", self.styles["Body"]))

        story.append(Spacer(1, 10))

        # 6. Service Details & CPE Inventory
        story.append(Paragraph("4. Service Fingerprints & CPE Inventory", self.styles["H1"]))
        services_with_cpe = [p for p in open_ports if p.service and (p.service.cpe or p.service.extrainfo)]
        if services_with_cpe:
            cpe_table_data = [
                [
                    Paragraph("<b>Port</b>", self.styles["TableHeader"]),
                    Paragraph("<b>Service</b>", self.styles["TableHeader"]),
                    Paragraph("<b>Extra Information</b>", self.styles["TableHeader"]),
                    Paragraph("<b>Common Platform Enumeration (CPE)</b>", self.styles["TableHeader"])
                ]
            ]
            for p in services_with_cpe:
                s = p.service
                cpe_str = "<br/>".join(s.cpe) if s.cpe else "None assigned"
                cpe_table_data.append([
                    Paragraph(f"<b>{p.portid}/tcp</b>", self.styles["TableText"]),
                    Paragraph(s.name, self.styles["TableText"]),
                    Paragraph(s.extrainfo or "-", self.styles["TableText"]),
                    Paragraph(cpe_str, self.styles["TableText"])
                ])
            cpe_tbl = Table(cpe_table_data, colWidths=[60, 70, 160, 250])
            cpe_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#C53030")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]))
            story.append(cpe_tbl)
        else:
            story.append(Paragraph("<i>No extended CPE identifiers or extra service metadata recorded.</i>", self.styles["Body"]))

        story.append(Spacer(1, 10))

        # 7. Evidence Preservation & Integrity Hashes
        story.append(Paragraph("5. Evidence Preservation & Integrity Hashes", self.styles["H1"]))
        ev_data = [
            [
                Paragraph("<b>Artifact Description</b>", self.styles["TableHeader"]),
                Paragraph("<b>File Location</b>", self.styles["TableHeader"]),
                Paragraph("<b>SHA256 Integrity Checksum</b>", self.styles["TableHeader"])
            ]
        ]
        for key, path in result.raw_files.items():
            h = result.file_hashes.get(key, "-")
            ev_data.append([
                Paragraph(f"Nmap {key.upper()} Output", self.styles["TableText"]),
                Paragraph(path, self.styles["TableText"]),
                Paragraph(f"<code>{h[:32]}...</code>" if len(h) > 32 else h, self.styles["TableText"])
            ])
        ev_tbl = Table(ev_data, colWidths=[120, 240, 180])
        ev_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#C53030")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ]))
        story.append(ev_tbl)
        story.append(Spacer(1, 10))

        # 8. Collection Errors & Limitations
        story.append(Paragraph("6. Scanner Notices & Execution Limitations", self.styles["H1"]))
        if result.errors:
            for err in result.errors:
                story.append(Paragraph(f"&bull; <font color='#9B2C2C'>{err}</font>", self.styles["Body"]))
        else:
            story.append(Paragraph("<i>Nmap execution completed with code 0 without recorded errors.</i>", self.styles["Body"]))

        story.append(Spacer(1, 10))

        # 9. Defensive Security Observations
        story.append(Paragraph("7. Defensive Security Observations", self.styles["H1"]))
        story.append(Paragraph("<i>Technical observations derived strictly from observed port and service states:</i>", self.styles["Body"]))
        if result.defensive_observations:
            for obs in result.defensive_observations:
                story.append(Paragraph(f"&bull; {obs}", self.styles["Observation"]))
        else:
            story.append(Paragraph("<i>No perimeter exposure anomalies observed.</i>", self.styles["Body"]))

        story.append(Spacer(1, 10))

        # 10. Recommended Defensive Actions
        story.append(Paragraph("8. Recommended Defensive Hardening Actions", self.styles["H1"]))
        story.append(Paragraph("<i>Actionable perimeter hardening recommendations based on observed exposure:</i>", self.styles["Body"]))
        if result.recommended_actions:
            for act in result.recommended_actions:
                story.append(Paragraph(f"&bull; <b>[ACTION]</b> {act}", self.styles["Recommendation"]))
        else:
            story.append(Paragraph("<i>Maintain existing host firewall and access control policies.</i>", self.styles["Body"]))

        doc.build(story, canvasmaker=ActiveNumberedCanvas)
        return os.path.abspath(output_path)

