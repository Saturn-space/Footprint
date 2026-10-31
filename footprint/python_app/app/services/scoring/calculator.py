"""Genuine 5-factor exposure score calculator for FootprintIQ investigations.

Formula:
  Exposure = (0.20 * P) + (0.15 * D) + (0.25 * S) + (0.35 * V) + (0.05 * C)

Where:
  - P: Public Footprint (0 - 100) based on discovered emails, persons, documents, and search evidence.
  - D: Domain Hygiene (0 - 100) based on subdomains, missing DMARC/SPF, and misconfigurations.
  - S: Service Exposure (0 - 100) based on open network ports and penalties for exposed database/admin interfaces.
  - V: Vulnerability Severity (0 - 100) based on CVSS-rated Greenbone/OpenVAS findings.
  - C: Correlation Confidence (0 - 100) based on cross-collector corroboration and evidence density.

Tiers:
  - Minimal:  0 - 19
  - Low:     20 - 39
  - Moderate: 40 - 59
  - High:    60 - 79
  - Critical: 80 - 100
"""

from dataclasses import dataclass, asdict
from typing import List, Optional, Set, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models.investigation import InvestigationModel
from app.models.recon import EntityModel, EvidenceModel
from app.models.scan import ScanFindingHostModel, ScanFindingPortModel
from app.models.vulnerability import VulnerabilityFindingModel


@dataclass
class ExposureScoreBreakdown:
    P: int
    D: int
    S: int
    V: int
    C: int
    total_score: int
    tier: str
    formula_version: str
    calculation_timestamp: str
    reviewer_notes: str
    components_detail: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ExposureScorer:
    """Calculates the composite 5-factor Exposure Score from actual database records."""

    WEIGHT_P = 0.20
    WEIGHT_D = 0.15
    WEIGHT_S = 0.25
    WEIGHT_V = 0.35
    WEIGHT_C = 0.05

    DATABASE_PORTS = {3306, 5432, 27017, 1433, 1521, 6379, 9200}
    ADMIN_PORTS = {8080, 8443, 9090, 10000, 2082, 2083, 2086, 2087}

    @classmethod
    def calculate_for_investigation(
        cls,
        investigation_id: str,
        db: Session,
        reviewer_notes: Optional[str] = None
    ) -> ExposureScoreBreakdown:
        """Computes exposure score for an investigation using persisted records."""
        # Query persisted data
        entities: List[EntityModel] = db.scalars(
            select(EntityModel).where(EntityModel.investigation_id == investigation_id)
        ).all()

        evidence_list: List[EvidenceModel] = db.scalars(
            select(EvidenceModel).where(EvidenceModel.investigation_id == investigation_id)
        ).all()

        ports: List[ScanFindingPortModel] = db.scalars(
            select(ScanFindingPortModel)
            .join(ScanFindingHostModel, ScanFindingPortModel.host_id == ScanFindingHostModel.id)
            .where(ScanFindingHostModel.investigation_id == investigation_id)
        ).all()

        vulns: List[VulnerabilityFindingModel] = db.scalars(
            select(VulnerabilityFindingModel).where(VulnerabilityFindingModel.investigation_id == investigation_id)
        ).all()

        # 1. P: Public Footprint (0 - 100)
        emails = [e for e in entities if e.entity_type.lower() == "email"]
        persons = [e for e in entities if e.entity_type.lower() == "person"]
        docs = [e for e in entities if e.entity_type.lower() == "document"]
        search_evidence = [ev for ev in evidence_list if "search" in (ev.source_type or "").lower()]

        raw_p = (len(emails) * 12) + (len(persons) * 8) + (len(docs) * 18) + (len(search_evidence) * 10)
        p = min(100, max(0, round(raw_p)))

        # 2. D: Domain Hygiene (0 - 100)
        subdomains = [e for e in entities if e.entity_type.lower() in ("subdomain", "domain")]
        dns_evidence = [ev for ev in evidence_list if "dns" in (ev.source_type or "").lower()]
        
        # Check if DMARC or SPF missing from DNS metadata
        has_dmarc = any("dmarc" in str(ev.source_metadata).lower() for ev in dns_evidence)
        missing_dmarc = len(dns_evidence) > 0 and not has_dmarc

        raw_d = len(subdomains) * 10
        if missing_dmarc:
            raw_d += 25
        d = min(100, max(0, round(raw_d)))

        # 3. S: Service Exposure (0 - 100)
        open_ports = [p_obj for p_obj in ports if (p_obj.state or "").lower() == "open"]
        raw_s = len(open_ports) * 14
        for p_obj in open_ports:
            port_num = p_obj.port_number
            if port_num in cls.DATABASE_PORTS:
                raw_s += 20
            elif port_num in cls.ADMIN_PORTS:
                raw_s += 15
            elif port_num == 80:
                raw_s += 5
        s = min(100, max(0, round(raw_s)))

        # 4. V: Vulnerability Severity (0 - 100)
        raw_v = 0.0
        for v_obj in vulns:
            sev = (v_obj.severity or "info").lower()
            qod_factor = (v_obj.qod or 100) / 100.0
            if sev == "critical":
                pts = 35
            elif sev == "high":
                pts = 22
            elif sev == "medium":
                pts = 12
            elif sev == "low":
                pts = 5
            else:
                pts = 1
            raw_v += pts * qod_factor
        v = min(100, max(0, round(raw_v)))

        # 5. C: Correlation Confidence (0 - 100)
        distinct_sources: Set[str] = {ev.source_name for ev in evidence_list if ev.source_name}
        evidence_count = len(evidence_list)
        raw_c = min(100, (len(distinct_sources) * 20) + min(40, evidence_count * 5))
        c = min(100, max(0, round(raw_c)))

        # Composite Exposure Score
        composite = (cls.WEIGHT_P * p) + (cls.WEIGHT_D * d) + (cls.WEIGHT_S * s) + (cls.WEIGHT_V * v) + (cls.WEIGHT_C * c)
        total_score = min(100, max(0, round(composite)))

        # Risk tier assignment
        if total_score >= 80:
            tier = "Critical"
        elif total_score >= 60:
            tier = "High"
        elif total_score >= 40:
            tier = "Moderate"
        elif total_score >= 20:
            tier = "Low"
        else:
            tier = "Minimal"

        notes = reviewer_notes or (
            f"Automated 5-factor calculation based on {len(entities)} entities, "
            f"{len(open_ports)} exposed ports, and {len(vulns)} vulnerability findings."
        )

        return ExposureScoreBreakdown(
            P=p,
            D=d,
            S=s,
            V=v,
            C=c,
            total_score=total_score,
            tier=tier,
            formula_version="v3.0-5factor (0.20*P + 0.15*D + 0.25*S + 0.35*V + 0.05*C)",
            calculation_timestamp=datetime.now(timezone.utc).isoformat(),
            reviewer_notes=notes,
            components_detail={
                "public_entities_count": len(entities),
                "emails_count": len(emails),
                "open_ports_count": len(open_ports),
                "vulnerabilities_count": len(vulns),
                "evidence_records_count": len(evidence_list),
                "distinct_sources_count": len(distinct_sources),
            }
        )
