"""
OSINT-RECON Confidence Engine Module
Computes transparent, rule-based, deterministic confidence classifications
and reproducible scores based on evidence quality and source independence.
"""

from typing import List, Tuple, Dict, Any, Optional
from src.schema import EvidenceReference


# Documented Heuristic Confidence Baselines
CONFIDENCE_LEVELS = {
    "CORROBORATED": {
        "base_score": 0.95,
        "description": "Multi-source consensus: confirmed independently by 2+ distinct toolchains or collectors."
    },
    "DIRECT": {
        "base_score": 0.85,
        "description": "Direct primary observation: verified by an explicit technical probe, query, or standard handshake."
    },
    "INDIRECT": {
        "base_score": 0.65,
        "description": "Associative inference: derived from contextual heuristics, naming conventions, or secondary metadata."
    },
    "UNCONFIRMED": {
        "base_score": 0.40,
        "description": "Low assurance: single unverified third-party scraping result or incomplete technical response."
    }
}


class ConfidenceEngine:
    """
    Evaluates evidence backing relationships to determine confidence classification,
    numeric score, and human-readable explanation.
    """

    def __init__(self, custom_thresholds: Optional[Dict[str, Any]] = None):
        self.thresholds = custom_thresholds or CONFIDENCE_LEVELS

    def evaluate_relationship(
        self,
        relationship_type: str,
        evidence_list: List[EvidenceReference]
    ) -> Tuple[str, float, str]:
        """
        Evaluates a relationship against supporting EvidenceReference objects.
        Returns: (confidence_classification, confidence_score, explanation_str)
        """
        if not evidence_list:
            return (
                "UNCONFIRMED",
                0.20,
                "Insufficient evidence: zero supporting evidence references provided for this relationship."
            )

        # Count distinct independent source modules (avoiding duplicate counting)
        distinct_sources = set(ev.source_module for ev in evidence_list)
        distinct_types = set(ev.evidence_type for ev in evidence_list)
        total_evidence_count = len(evidence_list)

        # 1. Corroborated: 2+ distinct independent toolchains/modules confirm the fact
        if len(distinct_sources) >= 2:
            base = self.thresholds["CORROBORATED"]["base_score"]
            explanation = (
                f"CORROBORATED (Confidence: {base:.2f}): Independently confirmed across "
                f"{len(distinct_sources)} distinct sources ({', '.join(sorted(distinct_sources))}) "
                f"with {total_evidence_count} supporting observation(s)."
            )
            return ("CORROBORATED", base, explanation)

        # 2. Relationship Type specific rules for single source
        source_name = list(distinct_sources)[0]
        ev_types_str = ", ".join(sorted(distinct_types))

        # Direct primary technical probes (e.g. DNS A/AAAA resolution, Nmap SYN-ACK open port, Nmap probed banner)
        direct_types = {
            "dns_a_record",
            "dns_aaaa_record",
            "dns_cname_record",
            "dns_ns_record",
            "nmap_open_port",
            "nmap_service_probe",
            "nmap_cpe_identifier",
            "nmap_reverse_hostname"
        }
        has_direct_evidence = any(ev.evidence_type in direct_types for ev in evidence_list)

        if has_direct_evidence:
            base = self.thresholds["DIRECT"]["base_score"]
            explanation = (
                f"DIRECT (Confidence: {base:.2f}): Confirmed via direct technical observation from "
                f"source '{source_name}' ({ev_types_str})."
            )
            return ("DIRECT", base, explanation)

        # Contextual / Indirect relationships (e.g. email domain association, WHOIS registrar context)
        indirect_types = {
            "whois_registrar",
            "whois_email",
            "harvested_email",
            "whois_nameserver"
        }
        has_indirect_evidence = any(ev.evidence_type in indirect_types for ev in evidence_list)

        if has_indirect_evidence or relationship_type in ("EMAIL_DOMAIN_ASSOCIATION", "DOMAIN_HAS_REGISTRAR"):
            base = self.thresholds["INDIRECT"]["base_score"]
            explanation = (
                f"INDIRECT (Confidence: {base:.2f}): Associative/contextual relationship derived from "
                f"source '{source_name}' ({ev_types_str}); does not guarantee operational control."
            )
            return ("INDIRECT", base, explanation)

        # Unconfirmed fallback
        base = self.thresholds["UNCONFIRMED"]["base_score"]
        explanation = (
            f"UNCONFIRMED (Confidence: {base:.2f}): Sourced exclusively from uncorroborated "
            f"observation '{ev_types_str}' by '{source_name}'."
        )
        return ("UNCONFIRMED", base, explanation)

