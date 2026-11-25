"""
OSINT-RECON Week 4 Correlation Package
Exports core asset resolution, relationship correlation, confidence evaluation,
intelligence graph representation, profile synthesis, and correlation orchestration.
"""

from src.correlation.asset_resolver import AssetResolver, generate_asset_id
from src.correlation.evidence_linker import EvidenceLinker, generate_evidence_id
from src.correlation.confidence_engine import ConfidenceEngine, CONFIDENCE_LEVELS
from src.correlation.relationship_builder import RelationshipBuilder, generate_relationship_id
from src.correlation.intelligence_graph import IntelligenceGraph
from src.correlation.asset_profile_builder import AssetProfileBuilder
from src.correlation.correlation_engine import CorrelationEngine, generate_correlation_id

__all__ = [
    "AssetResolver",
    "generate_asset_id",
    "EvidenceLinker",
    "generate_evidence_id",
    "ConfidenceEngine",
    "CONFIDENCE_LEVELS",
    "RelationshipBuilder",
    "generate_relationship_id",
    "IntelligenceGraph",
    "AssetProfileBuilder",
    "CorrelationEngine",
    "generate_correlation_id",
]

