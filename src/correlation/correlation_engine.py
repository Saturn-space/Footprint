"""
OSINT-RECON Week 4 Correlation Engine Orchestrator
Coordinates multi-source intelligence ingestion, evidence linking, asset resolution,
relationship derivation, confidence calculation, intelligence graph generation, and dual reporting.
"""

import os
import sys
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from src.schema import (
    CorrelationResult,
    PassivePipelineResult,
    ActiveReconResult,
    Asset,
    AssetRelationship,
    EvidenceReference,
    UnifiedAssetProfile
)
from src.correlation.asset_resolver import AssetResolver
from src.correlation.relationship_builder import RelationshipBuilder
from src.correlation.evidence_linker import EvidenceLinker
from src.correlation.confidence_engine import ConfidenceEngine
from src.correlation.intelligence_graph import IntelligenceGraph
from src.correlation.asset_profile_builder import AssetProfileBuilder
from src.reporting.correlation_report import CorrelationReportGenerator


def generate_correlation_id() -> str:
    """Generates a unique, timestamped correlation session ID."""
    now_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rand_suffix = uuid.uuid4().hex[:4]
    return f"CORR-{now_str}-{rand_suffix}"


class CorrelationEngine:
    """
    Master orchestrator for Week 4 Intelligence Correlation.
    Consumes passive and active scan results in read-only mode and synthesizes unified intelligence.
    """

    def __init__(
        self,
        base_dir: Optional[str] = None,
        config_path: Optional[str] = None,
        enable_pdf: bool = True
    ):
        self.base_dir = os.path.abspath(base_dir or os.getcwd())
        self.config_path = config_path or os.path.join(self.base_dir, "config", "correlation_config.json")
        self.enable_pdf = enable_pdf

        # Load configuration
        self.config = self._load_config()

        # Initialize sub-engines
        lab_subnets = self.config.get("environment_boundaries", {}).get("lab_subnets", ["192.168.56.0/24"])
        lab_hosts = self.config.get("environment_boundaries", {}).get("lab_hosts", ["192.168.56.111"])

        self.asset_resolver = AssetResolver(lab_subnets=lab_subnets, lab_hosts=lab_hosts)
        self.evidence_linker = EvidenceLinker()
        self.confidence_engine = ConfidenceEngine(self.config.get("confidence_thresholds"))
        self.relationship_builder = RelationshipBuilder(confidence_engine=self.confidence_engine)
        self.graph = IntelligenceGraph()
        self.profile_builder = AssetProfileBuilder(lab_subnets=lab_subnets, lab_hosts=lab_hosts)

        self.reports_dir = os.path.join(self.base_dir, "reports")
        self.processed_dir = os.path.join(self.base_dir, "data", "processed")
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.processed_dir, exist_ok=True)

        self.reporter = CorrelationReportGenerator(output_dir=self.reports_dir)

    def _load_config(self) -> Dict[str, Any]:
        """Loads correlation configuration or returns defaults."""
        if os.path.isfile(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def load_passive_file(self, filepath: str) -> Tuple[Optional[PassivePipelineResult], Optional[str]]:
        """Safely loads and validates a W2 PassivePipelineResult JSON file."""
        if not os.path.isfile(filepath):
            return None, f"Passive scan file not found: {filepath}"
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Validate via Pydantic
            result = PassivePipelineResult.model_validate(data)
            return result, None
        except Exception as e:
            return None, f"Failed to parse passive result file '{filepath}': {str(e)}"

    def load_active_file(self, filepath: str) -> Tuple[Optional[ActiveReconResult], Optional[str]]:
        """Safely loads and validates a W3 ActiveReconResult JSON file."""
        if not os.path.isfile(filepath):
            return None, f"Active scan file not found: {filepath}"
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Validate via Pydantic
            result = ActiveReconResult.model_validate(data)
            return result, None
        except Exception as e:
            return None, f"Failed to parse active result file '{filepath}': {str(e)}"

    def correlate(
        self,
        passive_files: Optional[List[str]] = None,
        active_files: Optional[List[str]] = None,
        passive_results: Optional[List[PassivePipelineResult]] = None,
        active_results: Optional[List[ActiveReconResult]] = None,
        correlation_id: Optional[str] = None
    ) -> CorrelationResult:
        """
        Executes end-to-end intelligence correlation across passive and active scan inputs.
        """
        start_time = datetime.now(timezone.utc).isoformat()
        cid = correlation_id or generate_correlation_id()
        warnings: List[str] = []
        errors: List[str] = []

        loaded_passive: List[PassivePipelineResult] = list(passive_results or [])
        loaded_active: List[ActiveReconResult] = list(active_results or [])

        # Load passive files
        for pf in (passive_files or []):
            res, err = self.load_passive_file(pf)
            if err:
                warnings.append(err)
            elif res:
                loaded_passive.append(res)

        # Load active files
        for af in (active_files or []):
            res, err = self.load_active_file(af)
            if err:
                warnings.append(err)
            elif res:
                loaded_active.append(res)

        source_scan_ids = []
        for p in loaded_passive:
            if p.scan_id not in source_scan_ids:
                source_scan_ids.append(p.scan_id)
        for a in loaded_active:
            if a.scan_id not in source_scan_ids:
                source_scan_ids.append(a.scan_id)

        # Check if we have zero inputs
        if not loaded_passive and not loaded_active:
            errors.append("No valid passive or active scan inputs provided for correlation.")
            end_time = datetime.now(timezone.utc).isoformat()
            return CorrelationResult(
                correlation_id=cid,
                source_scan_ids=[],
                overall_status="FAILED",
                start_time_utc=start_time,
                end_time_utc=end_time,
                assets=[],
                relationships=[],
                evidence=[],
                profiles=[],
                graph={},
                confidence_summary={},
                unresolved_relationships=[],
                warnings=warnings,
                errors=errors,
                processing_metadata={"input_passive_count": 0, "input_active_count": 0}
            )

        # -------------------------------------------------------------
        # STEP 1: Link Evidence References
        # -------------------------------------------------------------
        for p in loaded_passive:
            self.evidence_linker.link_passive_records(
                scan_id=p.scan_id,
                records=p.collector_records,
                raw_files=p.raw_files
            )

        for a in loaded_active:
            self.evidence_linker.link_active_result(a)

        all_evidence = self.evidence_linker.get_all_evidence()

        # -------------------------------------------------------------
        # STEP 2: Resolve & Normalize Assets
        # -------------------------------------------------------------
        for p in loaded_passive:
            self.asset_resolver.resolve_passive_findings(
                target_domain=p.target_domain,
                findings=p.deduplicated_findings,
                records=p.collector_records
            )

        for a in loaded_active:
            self.asset_resolver.resolve_active_findings(a)

        all_assets = self.asset_resolver.get_all_assets()
        assets_map = {a.asset_id: a for a in all_assets}

        # -------------------------------------------------------------
        # STEP 3: Build Evidence-Backed Relationships
        # -------------------------------------------------------------
        for p in loaded_passive:
            target_asset_id = f"ASSET:DOMAIN:{p.target_domain.strip().lower()}"
            target_asset = assets_map.get(target_asset_id)
            if target_asset:
                self.relationship_builder.build_passive_relationships(
                    target_domain_asset=target_asset,
                    assets_map=assets_map,
                    findings=p.deduplicated_findings,
                    records=p.collector_records,
                    evidence_registry=self.evidence_linker.registry
                )

        for a in loaded_active:
            self.relationship_builder.build_active_relationships(
                active_result=a,
                assets_map=assets_map,
                evidence_registry=self.evidence_linker.registry
            )

        all_relationships = self.relationship_builder.get_all_relationships()

        # -------------------------------------------------------------
        # STEP 4: Build Intelligence Graph
        # -------------------------------------------------------------
        self.graph.build_from(assets=all_assets, relationships=all_relationships)
        graph_dict = self.graph.to_dict()

        # -------------------------------------------------------------
        # STEP 5: Generate Unified Asset Profiles
        # -------------------------------------------------------------
        profiles: List[UnifiedAssetProfile] = []

        # Domain profiles for primary domain targets
        for a in all_assets:
            if a.asset_type == "domain":
                # Find matching passive records if any
                matching_records = []
                for p in loaded_passive:
                    if p.target_domain.strip().lower() == a.canonical_value:
                        matching_records.extend(p.collector_records)

                prof = self.profile_builder.build_domain_profile(
                    domain_asset=a,
                    relationships=all_relationships,
                    assets_map=assets_map,
                    passive_records=matching_records,
                    evidence_registry=self.evidence_linker.registry
                )
                profiles.append(prof)

            elif a.asset_type in ("ipv4", "ipv6") and ("active_scanned" in a.tags or "lab" in a.tags or "target" in a.tags):
                prof = self.profile_builder.build_ip_profile(
                    ip_asset=a,
                    relationships=all_relationships,
                    assets_map=assets_map,
                    active_results=loaded_active,
                    evidence_registry=self.evidence_linker.registry
                )
                profiles.append(prof)

        # -------------------------------------------------------------
        # STEP 6: Confidence Summary & Unresolved Ambiguities
        # -------------------------------------------------------------
        conf_counts = {"CORROBORATED": 0, "DIRECT": 0, "INDIRECT": 0, "UNCONFIRMED": 0}
        total_score = 0.0
        for r in all_relationships:
            if r.confidence in conf_counts:
                conf_counts[r.confidence] += 1
            total_score += r.confidence_score

        avg_score = round(total_score / len(all_relationships), 4) if all_relationships else 0.0
        confidence_summary = {
            "counts": conf_counts,
            "average_confidence_score": avg_score,
            "total_relationships": len(all_relationships)
        }

        # Identify isolated nodes / disconnected components as unresolved/isolated
        unresolved = [
            f"Isolated asset: {nid} has zero confirmed relationships to other assets."
            for nid in self.graph.get_isolated_nodes()
        ]

        # Overall status evaluation
        if loaded_passive and loaded_active:
            overall_status = "SUCCESS"
        else:
            overall_status = "PARTIAL"
            warnings.append("Partial correlation executed: either passive or active scan source was not provided.")

        end_time = datetime.now(timezone.utc).isoformat()

        # Build CorrelationResult object
        result = CorrelationResult(
            correlation_id=cid,
            investigation_id=None,
            source_scan_ids=source_scan_ids,
            overall_status=overall_status,
            start_time_utc=start_time,
            end_time_utc=end_time,
            assets=all_assets,
            relationships=all_relationships,
            evidence=all_evidence,
            profiles=profiles,
            graph=graph_dict,
            confidence_summary=confidence_summary,
            unresolved_relationships=unresolved,
            warnings=warnings,
            errors=errors,
            processing_metadata={
                "input_passive_count": len(loaded_passive),
                "input_active_count": len(loaded_active),
                "total_assets_resolved": len(all_assets),
                "total_relationships_built": len(all_relationships),
                "total_evidence_references": len(all_evidence),
                "graph_density": graph_dict.get("metrics", {}).get("graph_density", 0.0)
            }
        )

        # -------------------------------------------------------------
        # STEP 7: Generate Dual Reports (JSON & PDF)
        # -------------------------------------------------------------
        json_path = os.path.join(self.processed_dir, f"{cid}_correlation_report.json")
        self.reporter.generate_json_report(result, output_path=json_path)
        result.json_report_path = json_path

        if self.enable_pdf:
            try:
                pdf_path = os.path.join(self.reports_dir, f"{cid}_correlation_report.pdf")
                self.reporter.generate_pdf_report(result, output_path=pdf_path)
                result.pdf_report_path = pdf_path
            except Exception as pe:
                result.warnings.append(f"PDF generation failed: {str(pe)}")

        return result

