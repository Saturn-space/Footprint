"""
OSINT-RECON Deduplicator Module
Deduplicates findings across multiple collectors while strictly preserving source attribution,
multiple evidence references, and collector provenance.
"""

from typing import List, Dict, Tuple
from src.schema import NormalizedFinding


class FindingDeduplicator:
    """
    Deduplicates finding records by (finding_type, finding_value).
    Merges source tools, preserves evidence references, and aggregates context.
    """

    def __init__(self):
        pass

    def deduplicate(self, findings: List[NormalizedFinding]) -> List[NormalizedFinding]:
        """
        Deduplicates a list of NormalizedFinding objects.
        Returns a clean list of findings with merged provenance.
        """
        grouped: Dict[Tuple[str, str], NormalizedFinding] = {}

        for finding in findings:
            key = (finding.finding_type, finding.finding_value.strip().lower())
            if key not in grouped:
                # First time seeing this finding: make a copy
                grouped[key] = finding.model_copy(deep=True)
            else:
                existing = grouped[key]
                # 1. Merge source tools without duplicates
                for tool in finding.source_tools:
                    if tool and tool not in existing.source_tools:
                        existing.source_tools.append(tool)

                # 2. Merge source details dictionary
                if finding.source_details:
                    merged_details = dict(existing.source_details)
                    for k, v in finding.source_details.items():
                        if k not in merged_details:
                            merged_details[k] = v
                        elif merged_details[k] != v:
                            # If values differ, store as list or compound value
                            if isinstance(merged_details[k], list):
                                if v not in merged_details[k]:
                                    merged_details[k].append(v)
                            else:
                                merged_details[k] = [merged_details[k], v]
                    existing.source_details = merged_details

                # 3. Preserve combined evidence references
                if finding.evidence_reference and existing.evidence_reference:
                    existing_refs = [r.strip() for r in existing.evidence_reference.split(";")]
                    if finding.evidence_reference not in existing_refs:
                        existing.evidence_reference = f"{existing.evidence_reference}; {finding.evidence_reference}"
                elif finding.evidence_reference:
                    existing.evidence_reference = finding.evidence_reference

                # 4. Status upgrade (if any source reported VALID, overall is VALID)
                if finding.status == "VALID":
                    existing.status = "VALID"

        return list(grouped.values())

