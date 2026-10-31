"""Vulnerability assessment orchestrator coordinating GVM integration, authorization, job lifecycle, and result ingestion."""

import asyncio
from datetime import datetime, timezone
import ipaddress
import logging
import socket
import uuid
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.auth import log_audit_event
from app.database import get_db_context
from app.integrations.greenbone_adapter import GreenboneAdapter
from app.integrations.greenbone_client import (
    GreenboneClient,
    GreenboneConnectionStatus,
    GreenboneError,
    GreenboneNotConfiguredError,
    GreenboneOperationError,
)
from app.models.investigation import InvestigationModel
from app.models.recon import EntityModel, EvidenceModel, TargetAuthorizationModel, ensure_utc, utc_now
from app.models.vulnerability import VulnerabilityFindingModel, VulnerabilityScanJobModel
from app.services.evidence_store import EvidenceStore
from app.services.target_authorization import classify_target, verify_target_authorization
from app.services.vuln.normalizer import (
    generate_finding_deduplication_key,
    normalize_severity,
    parse_port_protocol,
)
from app.services.vuln.profiles import VulnProfile, validate_vuln_profile
from app.services.vuln.xml_parser import (
    MalformedReportError,
    ParsedReport,
    ReportNotCompletedError,
    ReportSecurityError,
    ReportSizeExceededError,
    VulnerabilityReportError,
    parse_greenbone_xml_report,
)

logger = logging.getLogger("footprintiq.services.vuln.orchestrator")


class VulnerabilityAssessmentError(Exception):
    """Raised when vulnerability assessment validation, authorization, or execution fails."""
    pass


class VulnerabilityAssessmentOrchestrator:
    """Manages full lifecycle of Greenbone vulnerability assessment jobs."""

    def __init__(self, adapter: Optional[GreenboneAdapter] = None):
        self.adapter = adapter or GreenboneAdapter()
        self._cancellation_requests: Dict[str, str] = {}
        self._lock = asyncio.Lock()

    def resolve_and_revalidate_target(
        self,
        db: Session,
        investigation: InvestigationModel,
        target: str,
        profile: VulnProfile,
        actor_user: Optional[Any] = None,
        client_ip: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Tuple[bool, str, List[str]]:
        """Revalidates target authorization, profile compatibility, and network addresses prior to execution."""
        target_clean = target.strip()
        target_type = classify_target(target_clean)

        # 1. Profile permitted types check
        permitted_upper = [t.upper() for t in profile.allowed_target_types]
        # Match 'ipv4' -> 'IP'
        type_mapped = "IP" if target_type == "IP" else ("DOMAIN" if target_type == "DOMAIN" else target_type)
        if type_mapped not in ("IP", "DOMAIN") and target_type not in permitted_upper:
            return (
                False,
                f"Target type '{target_type}' is not permitted by scan profile '{profile.id}' ({profile.allowed_target_types}).",
                [],
            )

        # 2. Strict authorization revalidation (SCAN_VULN operation)
        is_authz, authz_reason = verify_target_authorization(
            db=db,
            investigation=investigation,
            target=target_clean,
            operation="SCAN_VULN",
            actor_user=actor_user,
            client_ip=client_ip,
            request_id=request_id,
        )
        if not is_authz:
            return False, f"Target authorization failed: {authz_reason}", []

        # 3. DNS resolution & address verification
        resolved_ips: List[str] = []
        if target_type in ("IP", "CIDR"):
            resolved_ips = [target_clean]
        elif target_type == "DOMAIN":
            try:
                addr_infos = socket.getaddrinfo(target_clean, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                resolved_ips = list(dict.fromkeys(info[4][0] for info in addr_infos))
            except Exception as exc:
                logger.warning("DNS resolution failed for vulnerability target '%s': %s", target_clean, exc)
                return False, f"DNS resolution failed for hostname '{target_clean}': {exc}", []

            if not resolved_ips:
                return False, f"No IP addresses resolved for hostname '{target_clean}'.", []

            # Check network policy for resolved addresses
            for ip_str in resolved_ips:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.is_multicast or ip_obj.is_unspecified or ip_str == "255.255.255.255":
                        return False, f"Resolved IP '{ip_str}' violates network policy (multicast/unspecified).", []
                except ValueError:
                    pass

        return True, "Target authorized and validated.", resolved_ips

    def create_assessment_job(
        self,
        db: Session,
        investigation: InvestigationModel,
        target: str,
        profile_id: str,
        actor_user: Any,
        client_ip: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> VulnerabilityScanJobModel:
        """Validates target authorization and registers new assessment job record in QUEUED state."""
        # 1. Validate profile
        profile = validate_vuln_profile(profile_id)

        # 2. Revalidate target authorization
        is_valid, reason, resolved_ips = self.resolve_and_revalidate_target(
            db=db,
            investigation=investigation,
            target=target,
            profile=profile,
            actor_user=actor_user,
            client_ip=client_ip,
            request_id=request_id,
        )
        if not is_valid:
            log_audit_event(
                db=db,
                event_type="VULN_SCAN_DENIED",
                outcome="FAILURE",
                actor_id=actor_user.id if actor_user else None,
                request_id=request_id,
                ip_address=client_ip,
                details={
                    "investigation_id": investigation.id,
                    "target": target,
                    "profile_id": profile_id,
                    "reason": reason,
                },
            )
            raise VulnerabilityAssessmentError(f"Target authorization rejected: {reason}")

        # 3. Check for active concurrent jobs against the same target in this investigation
        active_stmt = select(VulnerabilityScanJobModel).where(
            VulnerabilityScanJobModel.investigation_id == investigation.id,
            VulnerabilityScanJobModel.target == target.strip(),
            VulnerabilityScanJobModel.status.in_(
                ["QUEUED", "AUTHORIZING", "CONFIGURING_TARGET", "CREATING_TASK", "RUNNING", "RETRIEVING_REPORT", "PARSING"]
            ),
        )
        existing_job = db.scalar(active_stmt)
        if existing_job:
            raise VulnerabilityAssessmentError(
                f"An assessment job ({existing_job.id}) is already active for target '{target}'."
            )

        job_id = f"vjob-{uuid.uuid4().hex[:12]}"
        job = VulnerabilityScanJobModel(
            id=job_id,
            investigation_id=investigation.id,
            requested_by=actor_user.id if actor_user else "system",
            target=target.strip(),
            profile_id=profile.id,
            scan_config_id=profile.gvm_config_id,
            status="QUEUED",
            progress=0,
            started_at=utc_now(),
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        log_audit_event(
            db=db,
            event_type="VULN_SCAN_REQUESTED",
            outcome="SUCCESS",
            actor_id=actor_user.id if actor_user else None,
            request_id=request_id,
            ip_address=client_ip,
            details={
                "job_id": job.id,
                "investigation_id": investigation.id,
                "target": job.target,
                "profile_id": profile.id,
                "scan_config_id": profile.gvm_config_id,
            },
        )

        return job

    async def execute_assessment_job(
        self,
        job_id: str,
        investigation_id: str,
        target: str,
        profile_id: str,
        requested_by: str,
        client_ip: Optional[str] = None,
        request_id: Optional[str] = None,
        db_factory: Optional[Any] = None,
    ) -> None:
        """Executes the complete assessment workflow: target creation, task execution, polling, and ingestion."""
        settings = get_settings()
        profile = validate_vuln_profile(profile_id)
        ctx = db_factory or get_db_context

        # Check if job was already cancelled before execution began
        if job_id in self._cancellation_requests:
            reason = self._cancellation_requests.pop(job_id)
            with ctx() as db:

                self._update_job_status(db, job_id, "CANCELLED", cancellation_reason=reason)
                log_audit_event(
                    db=db,
                    event_type="VULN_SCAN_CANCELLED",
                    outcome="SUCCESS",
                    actor_id=requested_by,
                    request_id=request_id,
                    details={"job_id": job_id, "reason": reason},
                )
            return

        # 1. Check Greenbone integration status
        availability = self.adapter.check_availability()
        status_val = availability.get("status")

        if status_val == GreenboneConnectionStatus.NOT_CONFIGURED.value:
            with ctx() as db:
                self._update_job_status(
                    db, job_id, "NOT_CONFIGURED", error_category="NOT_CONFIGURED", error_msg=availability.get("error")
                )
                log_audit_event(
                    db=db,
                    event_type="VULN_SCAN_FAILED",
                    outcome="FAILURE",
                    actor_id=requested_by,
                    request_id=request_id,
                    details={"job_id": job_id, "error": availability.get("error")},
                )
            return

        if status_val != GreenboneConnectionStatus.READY.value:
            err_msg = availability.get("error") or f"Greenbone service status is {status_val}"
            with ctx() as db:
                self._update_job_status(
                    db, job_id, "FAILED", error_category="SERVICE_UNAVAILABLE", error_msg=err_msg
                )
                log_audit_event(
                    db=db,
                    event_type="VULN_SCAN_FAILED",
                    outcome="FAILURE",
                    actor_id=requested_by,
                    request_id=request_id,
                    details={"job_id": job_id, "error": err_msg},
                )
            return

        gvm_target_id: Optional[str] = None
        gvm_task_id: Optional[str] = None
        gvm_report_id: Optional[str] = None

        try:
            # 2. Stage: CONFIGURING_TARGET
            with ctx() as db:
                self._update_job_status(db, job_id, "CONFIGURING_TARGET", progress=5)

            gvm_target_id = self.adapter.create_scan_target(investigation_id=investigation_id, target=target)

            with ctx() as db:
                job = db.get(VulnerabilityScanJobModel, job_id)
                if job:
                    job.gvm_target_id = gvm_target_id
                    db.commit()

            # 3. Stage: CREATING_TASK
            with ctx() as db:
                self._update_job_status(db, job_id, "CREATING_TASK", progress=15)

            gvm_task_id = self.adapter.create_scan_task(
                investigation_id=investigation_id,
                job_id=job_id,
                target_id=gvm_target_id,
                profile=profile,
            )

            with ctx() as db:
                job = db.get(VulnerabilityScanJobModel, job_id)
                if job:
                    job.gvm_task_id = gvm_task_id
                    db.commit()

            # 4. Stage: RUNNING
            with ctx() as db:
                self._update_job_status(db, job_id, "RUNNING", progress=20)
                log_audit_event(
                    db=db,
                    event_type="VULN_SCAN_STARTED",
                    outcome="SUCCESS",
                    actor_id=requested_by,
                    request_id=request_id,
                    details={"job_id": job_id, "gvm_task_id": gvm_task_id, "target": target},
                )

            gvm_report_id = self.adapter.start_scan_task(task_id=gvm_task_id)

            with ctx() as db:
                job = db.get(VulnerabilityScanJobModel, job_id)
                if job:
                    job.gvm_report_id = gvm_report_id
                    db.commit()

            # 5. Bounded Polling Loop
            poll_interval = settings.GVM_POLL_INTERVAL_SECONDS
            max_attempts = settings.GVM_MAX_POLL_ATTEMPTS
            attempts = 0
            is_scan_done = False

            while attempts < max_attempts:
                # Check for cancellation
                if job_id in self._cancellation_requests:
                    reason = self._cancellation_requests.pop(job_id)
                    logger.info("Cancellation recognized for job %s: %s", job_id, reason)
                    try:
                        self.adapter.stop_scan_task(gvm_task_id)
                    except Exception as stop_exc:
                        logger.warning("Error stopping GVM task %s: %s", gvm_task_id, stop_exc)

                    with ctx() as db:
                        self._update_job_status(
                            db, job_id, "CANCELLED", cancellation_reason=reason
                        )
                        log_audit_event(
                            db=db,
                            event_type="VULN_SCAN_CANCELLED",
                            outcome="SUCCESS",
                            actor_id=requested_by,
                            request_id=request_id,
                            details={"job_id": job_id, "reason": reason},
                        )
                    return

                await asyncio.sleep(poll_interval)
                attempts += 1

                try:
                    task_info = self.adapter.poll_scan_status(gvm_task_id)
                except Exception as poll_err:
                    logger.warning("Transient error polling GVM task %s: %s", gvm_task_id, poll_err)
                    continue

                task_status = task_info.get("status", "")
                progress_val = task_info.get("progress", 0)
                if task_info.get("report_id"):
                    gvm_report_id = task_info["report_id"]

                # Update job progress in database
                with ctx() as db:
                    job = db.get(VulnerabilityScanJobModel, job_id)
                    if job:
                        # Scale progress between 20% and 80%
                        scaled_progress = 20 + int(progress_val * 0.6)
                        job.progress = max(job.progress or 0, min(80, scaled_progress))
                        if gvm_report_id and not job.gvm_report_id:
                            job.gvm_report_id = gvm_report_id
                        db.commit()

                status_lower = task_status.lower()
                if status_lower in ("done", "stopped", "finished"):
                    is_scan_done = True
                    break
                elif status_lower in ("internal error", "failed", "interrupted"):
                    with ctx() as db:
                        self._update_job_status(
                            db,
                            job_id,
                            "FAILED",
                            error_category="SCANNER_ERROR",
                            error_msg=f"GVM task reported state: {task_status}",
                        )
                        log_audit_event(
                            db=db,
                            event_type="VULN_SCAN_FAILED",
                            outcome="FAILURE",
                            actor_id=requested_by,
                            request_id=request_id,
                            details={"job_id": job_id, "task_status": task_status},
                        )
                    return

            if not is_scan_done:
                # Timeout occurred
                logger.warning("Vulnerability assessment job %s timed out after %d attempts", job_id, max_attempts)
                try:
                    self.adapter.stop_scan_task(gvm_task_id)
                except Exception:
                    pass

                with ctx() as db:
                    self._update_job_status(
                        db,
                        job_id,
                        "TIMED_OUT",
                        error_category="POLLING_TIMEOUT",
                        error_msg=f"Assessment polling timed out after {max_attempts * poll_interval} seconds.",
                    )
                    log_audit_event(
                        db=db,
                        event_type="VULN_SCAN_TIMED_OUT",
                        outcome="FAILURE",
                        actor_id=requested_by,
                        request_id=request_id,
                        details={"job_id": job_id, "attempts": max_attempts},
                    )
                return

            # 6. Stage: RETRIEVING_REPORT
            with ctx() as db:
                self._update_job_status(db, job_id, "RETRIEVING_REPORT", progress=85)

            report_id_to_fetch = gvm_report_id or gvm_task_id
            try:
                report_xml = self.adapter.retrieve_report(report_id=report_id_to_fetch)
            except Exception as ret_err:
                with ctx() as db:
                    self._update_job_status(
                        db,
                        job_id,
                        "FAILED",
                        error_category="REPORT_RETRIEVAL_FAILED",
                        error_msg=f"Failed to retrieve report XML: {ret_err}",
                    )
                    log_audit_event(
                        db=db,
                        event_type="VULN_SCAN_FAILED",
                        outcome="FAILURE",
                        actor_id=requested_by,
                        request_id=request_id,
                        details={"job_id": job_id, "error": str(ret_err)},
                    )
                return

            # 7. Stage: PARSING
            with ctx() as db:
                self._update_job_status(db, job_id, "PARSING", progress=90)

            try:
                parsed_report = parse_greenbone_xml_report(report_xml)
            except (VulnerabilityReportError, ReportNotCompletedError, MalformedReportError, ReportSecurityError, ReportSizeExceededError) as parse_err:
                logger.error("Failed to parse Greenbone report XML for job %s: %s", job_id, parse_err)
                with ctx() as db:
                    self._update_job_status(
                        db,
                        job_id,
                        "FAILED",
                        error_category="REPORT_PARSING_FAILED",
                        error_msg=f"Report parsing failed: {parse_err}",
                    )
                    log_audit_event(
                        db=db,
                        event_type="VULN_SCAN_FAILED",
                        outcome="FAILURE",
                        actor_id=requested_by,
                        request_id=request_id,
                        details={"job_id": job_id, "error": str(parse_err)},
                    )
                return

            # 8. Persist Raw Evidence & Findings
            with ctx() as db:
                # Store report evidence in EvidenceStore
                evidence_store = EvidenceStore()
                evidence_id = f"evi-{uuid.uuid4().hex[:12]}"
                stored_ref, content_hash, size_bytes = evidence_store.store_evidence(
                    investigation_id=investigation_id,
                    evidence_id=evidence_id,
                    source_type="greenbone_openvas",
                    content=report_xml,
                )

                evidence = EvidenceModel(
                    id=evidence_id,
                    investigation_id=investigation_id,
                    job_id=None,
                    source_type="greenbone_openvas",
                    source_name="Greenbone Vulnerability Manager",
                    target=target,
                    collection_status="SUCCESS",
                    raw_content_path=stored_ref,
                    content_hash=content_hash,
                    content_size_bytes=size_bytes,
                    source_metadata={"job_id": job_id, "profile_id": profile_id},
                )
                db.add(evidence)
                db.commit()
                db.refresh(evidence)


                # Ingest findings
                finding_count = self._persist_findings(
                    db=db,
                    job_id=job_id,
                    investigation_id=investigation_id,
                    parsed_report=parsed_report,
                    evidence_id=evidence.id,
                )

                # Complete Job
                job = db.get(VulnerabilityScanJobModel, job_id)
                if job:
                    job.status = "COMPLETED"
                    job.progress = 100
                    job.evidence_id = evidence.id
                    job.completed_at = utc_now()
                    if job.started_at:
                        job.duration_seconds = max(
                            0.0, (ensure_utc(job.completed_at) - ensure_utc(job.started_at)).total_seconds()
                        )
                    db.commit()

                log_audit_event(
                    db=db,
                    event_type="VULN_SCAN_COMPLETED",
                    outcome="SUCCESS",
                    actor_id=requested_by,
                    request_id=request_id,
                    details={
                        "job_id": job_id,
                        "findings_count": finding_count,
                        "evidence_id": evidence.id,
                        "duration_seconds": job.duration_seconds if job else None,
                    },
                )

        except Exception as e:
            logger.error("Unhandled exception during vulnerability assessment job %s: %s", job_id, e, exc_info=True)
            with ctx() as db:
                self._update_job_status(
                    db, job_id, "FAILED", error_category="INTERNAL_ERROR", error_msg=str(e)
                )
                log_audit_event(
                    db=db,
                    event_type="VULN_SCAN_FAILED",
                    outcome="FAILURE",
                    actor_id=requested_by,
                    request_id=request_id,
                    details={"job_id": job_id, "error": str(e)},
                )

    def cancel_job(
        self,
        db: Session,
        job_id: str,
        actor_user: Any,
        reason: str = "User requested cancellation",
        client_ip: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> bool:
        """Flags job for cancellation and signals Greenbone to stop running task."""
        job = db.get(VulnerabilityScanJobModel, job_id)
        if not job:
            raise VulnerabilityAssessmentError(f"Vulnerability assessment job '{job_id}' not found.")

        active_states = ["QUEUED", "AUTHORIZING", "CONFIGURING_TARGET", "CREATING_TASK", "RUNNING"]
        if job.status not in active_states:
            raise VulnerabilityAssessmentError(
                f"Job '{job_id}' cannot be cancelled in current state '{job.status}'."
            )

        self._cancellation_requests[job_id] = reason
        logger.info("Registered cancellation request for job %s: %s", job_id, reason)

        # If job is still in QUEUED state, cancel it immediately in DB
        if job.status == "QUEUED":
            job.status = "CANCELLED"
            job.cancellation_reason = reason
            job.completed_at = utc_now()
            db.commit()

        # If GVM task is already created and running, attempt immediate stop
        if job.gvm_task_id:
            try:
                self.adapter.stop_scan_task(job.gvm_task_id)
            except Exception as e:
                logger.warning("Could not send stop signal to GVM task %s: %s", job.gvm_task_id, e)

        log_audit_event(
            db=db,
            event_type="VULN_SCAN_CANCEL_REQUESTED",
            outcome="SUCCESS",
            actor_id=actor_user.id if actor_user else None,
            request_id=request_id,
            ip_address=client_ip,
            details={"job_id": job_id, "reason": reason},
        )
        return True

    def _persist_findings(
        self,
        db: Session,
        job_id: str,
        investigation_id: str,
        parsed_report: ParsedReport,
        evidence_id: str,
    ) -> int:
        """Normalizes and persists vulnerability findings, maintaining deduplication and entity correlation."""
        count = 0
        now = utc_now()

        for raw in parsed_report.findings:
            port_val, proto_val = parse_port_protocol(raw.port_str)
            norm_severity = normalize_severity(raw.severity_score, raw.threat)
            primary_cve = raw.cve_list[0] if raw.cve_list else None

            finding_id = f"vfind-{uuid.uuid4().hex[:12]}"
            finding = VulnerabilityFindingModel(
                id=finding_id,
                investigation_id=investigation_id,
                job_id=job_id,
                host=raw.host,
                port=port_val,
                protocol=proto_val or "tcp",
                name=raw.name,
                description=raw.description,
                solution=raw.solution,
                severity=norm_severity,
                raw_severity=raw.threat,
                cvss_score=raw.severity_score,
                cvss_version="3.1" if raw.severity_score is not None else None,
                cve_references=raw.cve_list,
                nvt_oid=raw.nvt_oid,
                qod=raw.qod,
                source_finding_id=raw.result_id,
                evidence_id=evidence_id,
                first_seen=now,
                last_seen=now,
            )
            db.add(finding)
            count += 1

            # Correlate into investigation entities (EntityModel)
            entity_id = f"ent-{uuid.uuid4().hex[:12]}"
            entity_val = f"{raw.name} ({raw.host}:{raw.port_str})"
            entity = EntityModel(
                id=entity_id,
                investigation_id=investigation_id,
                entity_type="vulnerability",
                canonical_value=entity_val[:512],
                original_value=entity_val,
                evidence_ids=[evidence_id],
                metadata_json={
                    "finding_id": finding_id,
                    "host": raw.host,
                    "port": port_val,
                    "protocol": proto_val or "tcp",
                    "severity": norm_severity,
                    "cvss": raw.severity_score,
                    "cves": raw.cve_list,
                    "nvt_oid": raw.nvt_oid,
                    "qod": raw.qod,
                    "source": "greenbone_openvas",
                },
                first_seen=now,
                last_seen=now,
            )
            db.add(entity)


        db.commit()
        return count

    @staticmethod
    def _update_job_status(
        db: Session,
        job_id: str,
        status: str,
        progress: Optional[int] = None,
        error_category: Optional[str] = None,
        error_msg: Optional[str] = None,
        cancellation_reason: Optional[str] = None,
    ) -> None:
        """Internal helper to safely update status fields on a vulnerability scan job."""
        job = db.get(VulnerabilityScanJobModel, job_id)
        if not job:
            return

        job.status = status
        if progress is not None:
            job.progress = progress
        if error_category:
            job.error_category = error_category
        if error_msg:
            job.error_message = error_msg
        if cancellation_reason:
            job.cancellation_reason = cancellation_reason

        if status in ("COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT", "NOT_CONFIGURED"):
            job.completed_at = utc_now()
            if job.started_at:
                job.duration_seconds = max(
                    0.0, (ensure_utc(job.completed_at) - ensure_utc(job.started_at)).total_seconds()
                )

        db.commit()


_global_vuln_orchestrator: Optional[VulnerabilityAssessmentOrchestrator] = None


def get_vuln_orchestrator() -> VulnerabilityAssessmentOrchestrator:
    """Returns singleton instance of the vulnerability assessment orchestrator."""
    global _global_vuln_orchestrator
    if _global_vuln_orchestrator is None:
        _global_vuln_orchestrator = VulnerabilityAssessmentOrchestrator()
    return _global_vuln_orchestrator
