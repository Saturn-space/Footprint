"""
OSINT-RECON Passive Reconnaissance Orchestration Pipeline
Coordinates independent collector execution, normalization, deduplication,
schema validation, evidence persistence, and reporting.
"""

import os
import re
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

import jsonschema

from src.schema import (
    ReconRecord,
    TargetInfo,
    ToolInfo,
    NormalizedFinding,
    PassivePipelineResult
)
from src.collectors.whois_collector import WhoisCollector
from src.collectors.dns_collector import DNSCollector
from src.collectors.theharvester_collector import TheHarvesterCollector
from src.processors.normalizer import FindingNormalizer, clean_domain
from src.processors.deduplicator import FindingDeduplicator
from src.processors.correlator import FindingCorrelator
from src.reporting.pdf_generator import PDFReportGenerator


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_SCHEMA_PATH = os.path.join(PROJECT_ROOT, "config", "recon_schema.json")


def generate_scan_id() -> str:
    """Generates a timestamped, unique scan ID (e.g. SCAN-20261109-103522-a1b2)."""
    now = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rand_hex = uuid.uuid4().hex[:4]
    return f"SCAN-{now}-{rand_hex}"


class PassiveReconPipeline:
    """
    End-to-end passive reconnaissance orchestrator.
    Manages collector lifecycles, error boundaries, schema compliance, and output artifacts.
    """

    def __init__(
        self,
        base_dir: Optional[str] = None,
        schema_path: Optional[str] = None,
        timeout: int = 30,
        enable_pdf: bool = True
    ):
        self.base_dir = base_dir or PROJECT_ROOT
        self.schema_path = schema_path or DEFAULT_SCHEMA_PATH
        self.timeout = timeout
        self.enable_pdf = enable_pdf

        # Directories
        self.raw_dir = os.path.join(self.base_dir, "data", "raw_outputs")
        self.processed_dir = os.path.join(self.base_dir, "data", "processed")
        self.reports_dir = os.path.join(self.base_dir, "reports")

        os.makedirs(self.raw_dir, exist_ok=True)
        os.makedirs(self.processed_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)

        # Processors and reporting
        self.normalizer = FindingNormalizer()
        self.deduplicator = FindingDeduplicator()
        self.correlator = FindingCorrelator()
        self.pdf_generator = PDFReportGenerator(output_dir=self.reports_dir)

        # Load JSON Schema
        self.json_schema = self._load_schema()

    def _load_schema(self) -> Optional[Dict[str, Any]]:
        """Loads the draft 2020-12 JSON Schema for validation."""
        if os.path.exists(self.schema_path):
            try:
                with open(self.schema_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    def validate_target(self, target: str) -> str:
        """Validates target domain structure."""
        if not target or not isinstance(target, str):
            raise ValueError("Target domain must be a non-empty string")
        clean = clean_domain(target)
        if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", clean):
            raise ValueError(f"Invalid target domain format: '{target}'")
        return clean

    def run(
        self,
        target_domain: str,
        category: str = "normal_benchmark_domain",
        scope: Optional[str] = None,
        scan_id: Optional[str] = None
    ) -> PassivePipelineResult:
        """
        Executes full passive reconnaissance pipeline:
        Target Validation -> Independent Collectors -> Normalization ->
        Deduplication -> Correlation -> Schema Validation -> JSON & PDF Generation.
        """
        start_time = datetime.now(timezone.utc).isoformat()
        sid = scan_id or generate_scan_id()
        scan_raw_dir = os.path.join(self.raw_dir, sid)
        os.makedirs(scan_raw_dir, exist_ok=True)

        pipeline_errors: List[str] = []

        # 1. Target Validation
        try:
            clean_target = self.validate_target(target_domain)
        except ValueError as ve:
            end_time = datetime.now(timezone.utc).isoformat()
            return PassivePipelineResult(
                scan_id=sid,
                target_domain=str(target_domain),
                start_time_utc=start_time,
                end_time_utc=end_time,
                overall_status="FAILED",
                errors=[str(ve)]
            )

        target_scope = scope or f"{clean_target} (Passive Reconnaissance Scope)"

        # Initialize collectors with isolated raw directory
        whois_col = WhoisCollector(timeout=self.timeout, raw_dir=scan_raw_dir)
        dns_col = DNSCollector(timeout=5.0, lifetime=10.0, raw_dir=scan_raw_dir)
        harv_col = TheHarvesterCollector(timeout=self.timeout, raw_dir=scan_raw_dir)

        collector_records: List[ReconRecord] = []
        raw_files_dict: Dict[str, str] = {}

        # 2. Independent Collector Executions
        # A. WHOIS
        try:
            w_rec = whois_col.collect(clean_target, scan_id=sid)
            collector_records.append(w_rec)
            if w_rec.raw_output_reference:
                raw_files_dict["whois"] = w_rec.raw_output_reference
            if w_rec.errors_and_warnings:
                pipeline_errors.extend(w_rec.errors_and_warnings)
        except Exception as e:
            pipeline_errors.append(f"WHOIS collector uncaught error: {str(e)}")

        # B. DNS
        try:
            d_rec = dns_col.collect(clean_target, scan_id=sid)
            collector_records.append(d_rec)
            if d_rec.raw_output_reference:
                raw_files_dict["dns"] = d_rec.raw_output_reference
            if d_rec.errors_and_warnings:
                pipeline_errors.extend(d_rec.errors_and_warnings)
        except Exception as e:
            pipeline_errors.append(f"DNS collector uncaught error: {str(e)}")

        # C. theHarvester
        try:
            h_rec = harv_col.collect(clean_target, scan_id=sid)
            collector_records.append(h_rec)
            if h_rec.raw_output_reference:
                raw_files_dict["theHarvester"] = h_rec.raw_output_reference
            if h_rec.errors_and_warnings:
                pipeline_errors.extend(h_rec.errors_and_warnings)
        except Exception as e:
            pipeline_errors.append(f"theHarvester collector uncaught error: {str(e)}")

        # 3. JSON Schema Validation on every collector record
        if self.json_schema:
            for rec in collector_records:
                try:
                    rec_dict = json.loads(rec.model_dump_json())
                    jsonschema.validate(instance=rec_dict, schema=self.json_schema)
                except jsonschema.ValidationError as ve:
                    pipeline_errors.append(f"JSON Schema validation error on {rec.recon_category}: {ve.message}")
                except Exception as ex:
                    pipeline_errors.append(f"Schema check error: {str(ex)}")

        # 4. Normalization
        all_findings: List[NormalizedFinding] = []
        for rec in collector_records:
            all_findings.extend(self.normalizer.normalize_record(rec))

        # 5. Deduplication (Provenance Preserved)
        deduped_findings = self.deduplicator.deduplicate(all_findings)

        # 6. Correlation & Defensive Analysis
        summary, observations, recommendations = self.correlator.correlate(
            clean_target, deduped_findings, collector_records
        )

        # 7. Overall Pipeline Status Evaluation
        collector_statuses = [r.scan_status for r in collector_records]
        if not collector_statuses or all(s == "FAILED" for s in collector_statuses):
            overall_status = "FAILED"
        elif all(s == "SUCCESS" for s in collector_statuses) and not pipeline_errors:
            overall_status = "SUCCESS"
        else:
            overall_status = "PARTIAL"

        end_time = datetime.now(timezone.utc).isoformat()

        # Build pipeline result
        result = PassivePipelineResult(
            scan_id=sid,
            target_domain=clean_target,
            start_time_utc=start_time,
            end_time_utc=end_time,
            overall_status=overall_status,
            collector_records=collector_records,
            deduplicated_findings=deduped_findings,
            summary=summary,
            defensive_observations=observations,
            recommended_actions=recommendations,
            raw_files=raw_files_dict,
            errors=list(dict.fromkeys(pipeline_errors))
        )

        # 8. Generate PDF Intelligence Report (if enabled)
        if self.enable_pdf:
            try:
                pdf_path = self.pdf_generator.generate(result)
                result.pdf_report_path = pdf_path
            except Exception as pe:
                result.errors.append(f"PDF generation error: {str(pe)}")

        # 9. Save Machine-Readable JSON Report (with non-null artifact references)
        json_filename = f"{sid}_report.json"
        json_path = os.path.join(self.processed_dir, json_filename)
        result.json_report_path = os.path.abspath(json_path)
        try:
            with open(json_path, "w", encoding="utf-8") as jf:
                jf.write(result.model_dump_json(indent=2))
        except IOError as ioe:
            result.errors.append(f"Failed to write JSON report: {ioe}")

        return result

