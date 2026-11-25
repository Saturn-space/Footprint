"""
FootprintIQ - Exposure Scoring and Risk Prioritization Engine
Implements a transparent, deterministic risk-scoring methodology combining:
- CVSS v3.x base scores
- Scanner confidence and verification status
- Multi-scanner corroboration
- Network service exposure
- Severity category distribution
"""

import math
from typing import List, Dict, Any, Optional

from src.services.finding_translator import parse_confidence_score

SEVERITY_WEIGHTS = {
    "Critical": 10.0,
    "High": 7.5,
    "Medium": 5.0,
    "Low": 2.5,
    "Informational": 0.5
}

EXPOSURE_SCALE_DIVISOR = 150.0


class ExposureScoringEngine:
    @staticmethod
    def calculate_finding_risk(finding: Dict[str, Any], corroborated: bool = False) -> Dict[str, Any]:
        """
        Calculates individual finding risk score (0 - 100).
        Uses CVSS * 10 when available, otherwise severity-tier mapping * 10,
        scaled by verification status (1.0 verified/confirmed vs 0.85 observed/unverified),
        confidence factor (0.5 - 1.0), and multi-scanner corroboration boost (1.15).
        """
        cvss = finding.get("cvss_score")
        severity = str(finding.get("severity", "Informational") or "Informational")
        confidence = parse_confidence_score(finding.get("confidence"), default=0.8)
        ver_status = str(finding.get("verification_status") or "").strip().lower()
        is_verified = ver_status in ("verified", "confirmed")

        # Determine base score
        if cvss is not None and isinstance(cvss, (int, float)) and cvss > 0:
            base_score = float(cvss) * 10.0
            score_source = f"CVSS {cvss}"
        else:
            base_score = SEVERITY_WEIGHTS.get(severity.title(), SEVERITY_WEIGHTS.get(severity, 2.5)) * 10.0
            score_source = f"Severity mapping ({severity})"

        # Multipliers
        verif_factor = 1.0 if is_verified else 0.85
        conf_factor = max(0.5, min(1.0, confidence))
        corroboration_factor = 1.15 if corroborated else 1.0

        raw_score = base_score * verif_factor * conf_factor * corroboration_factor
        final_score = round(min(100.0, max(0.0, raw_score)), 1)

        return {
            "finding_id": finding.get("finding_id"),
            "risk_score": final_score,
            "base_score": base_score,
            "score_source": score_source,
            "corroborated": corroborated,
            "verification_factor": verif_factor,
            "confidence_factor": conf_factor,
            "verified": is_verified,
        }

    @classmethod
    def calculate_investigation_exposure(
        cls,
        findings: List[Dict[str, Any]],
        discovered_ports: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Calculates aggregate target and investigation exposure score (0 - 100)
        and severity distribution.
        NOTE: Open network ports are tracked under asset attack-surface context and do NOT
        directly inflate the vulnerability risk index unless linked to a recorded finding.
        """
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0
        }
        ports_count = len(discovered_ports or [])

        if not findings:
            return {
                "exposure_score": 0.0,
                "exposure_level": "Minimal",
                "total_findings": 0,
                "severity_counts": severity_counts,
                "prioritized_findings": [],
                "scoring_formula": (
                    "Exposure = 100 * (1 - exp(-Sum(Risk_i) / 150)) where Risk_i = "
                    "(CVSS*10 or SeverityWeight*10) * VerificationFactor * ConfidenceFactor * CorroborationBoost"
                ),
                "scoring_breakdown": {
                    "total_risk_sum": 0.0,
                    "scale_divisor": EXPOSURE_SCALE_DIVISOR,
                    "verified_count": 0,
                    "observed_or_unverified_count": 0,
                    "open_ports_count": ports_count,
                    "open_ports_scored_directly": False,
                    "per_finding_contributions": [],
                },
                "scoring_methodology": "No vulnerability findings recorded. Attack-surface ports are inventoried separately.",
            }

        # Check for multi-scanner corroboration by CVE
        cve_map: Dict[str, set] = {}
        for f in findings:
            cves = f.get("cve_identifiers")
            src = f.get("detection_source", "unknown")
            if cves:
                for cve in str(cves).split(","):
                    cve_clean = cve.strip().upper()
                    if cve_clean:
                        cve_map.setdefault(cve_clean, set()).add(src)

        finding_risks = []
        contributions = []
        total_risk_sum = 0.0
        verified_count = 0
        unverified_count = 0

        for f in findings:
            sev = f.get("severity", "Informational")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            cves = str(f.get("cve_identifiers", "")).split(",")
            corroborated = False
            for cve in cves:
                cve_clean = cve.strip().upper()
                if cve_clean in cve_map and len(cve_map[cve_clean]) > 1:
                    corroborated = True
                    break

            risk_meta = cls.calculate_finding_risk(f, corroborated=corroborated)
            f_score = risk_meta["risk_score"]
            total_risk_sum += f_score
            if risk_meta["verified"]:
                verified_count += 1
            else:
                unverified_count += 1

            contributions.append({
                "finding_id": f.get("finding_id"),
                "title": f.get("title"),
                "severity": sev,
                "score_source": risk_meta["score_source"],
                "base_score": risk_meta["base_score"],
                "verification_factor": risk_meta["verification_factor"],
                "confidence_factor": risk_meta["confidence_factor"],
                "corroborated": corroborated,
                "risk_points": f_score,
            })

            finding_risks.append({
                **f,
                "calculated_risk_score": f_score,
                "corroborated": corroborated
            })

        # Asymptotic exposure curve bounded 0 - 100
        exposure_score = round(100.0 * (1.0 - math.exp(-total_risk_sum / EXPOSURE_SCALE_DIVISOR)), 1)
        exposure_score = min(100.0, max(0.0, exposure_score))

        # Qualitative level
        if exposure_score >= 80.0:
            level = "Critical"
        elif exposure_score >= 60.0:
            level = "High"
        elif exposure_score >= 40.0:
            level = "Medium"
        elif exposure_score >= 20.0:
            level = "Low"
        else:
            level = "Informational"

        # Prioritize top findings
        prioritized = sorted(finding_risks, key=lambda x: x.get("calculated_risk_score", 0), reverse=True)

        return {
            "exposure_score": exposure_score,
            "exposure_level": level,
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "prioritized_findings": prioritized,
            "scoring_formula": (
                "Exposure = 100 * (1 - exp(-Sum(Risk_i) / 150)) where Risk_i = "
                "(CVSS*10 or SeverityWeight*10) * VerificationFactor(1.0 verified / 0.85 observed) "
                "* ConfidenceFactor * CorroborationBoost(1.15 multi-scanner)"
            ),
            "scoring_breakdown": {
                "total_risk_sum": round(total_risk_sum, 2),
                "scale_divisor": EXPOSURE_SCALE_DIVISOR,
                "verified_count": verified_count,
                "observed_or_unverified_count": unverified_count,
                "open_ports_count": ports_count,
                "open_ports_scored_directly": False,
                "per_finding_contributions": contributions[:20],
            },
        }

