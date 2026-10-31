"""Secure Nmap subprocess execution runner, concurrency management, and result ingestion."""

import asyncio
import ipaddress
import logging
import os
import shutil
import socket
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.auth import log_audit_event
from app.models.investigation import InvestigationModel
from app.models.recon import EvidenceModel, EntityModel, utc_now, ensure_utc
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel, ScanFindingPortModel
from app.services.active.nmap_detector import get_nmap_detector
from app.services.active.profiles import ScanProfile, get_scan_profile
from app.services.active.xml_parser import parse_nmap_xml, NmapXmlParseError, ParsedNmapResult
from app.services.evidence_store import EvidenceStore
from app.services.target_authorization import classify_target, verify_target_authorization

logger = logging.getLogger("footprintiq.nmap.runner")


class NmapExecutionError(Exception):
    """Raised when scan validation, authorization, or execution fails."""
    pass


class NmapRunner:
    """Manages secure, authorized execution of Nmap processes with concurrency and cancellation controls."""

    def __init__(self):
        settings = get_settings()
        self.max_concurrency = settings.NMAP_MAX_CONCURRENCY
        self._semaphore = asyncio.Semaphore(self.max_concurrency)
        self._active_processes: Dict[str, asyncio.subprocess.Process] = {}
        self._cancellation_requests: Dict[str, str] = {}
        self._lock = asyncio.Lock()

    def resolve_and_revalidate_target(
        self,
        db: Session,
        investigation: InvestigationModel,
        target: str,
        profile: ScanProfile,
        actor_user: Optional[Any] = None,
        client_ip: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Tuple[bool, str, List[str]]:
        """Revalidates target authorization and resolves DNS immediately prior to execution."""
        target_clean = target.strip()
        target_type = classify_target(target_clean)

        # 1. Profile permitted types check
        permitted_upper = [t.upper() for t in profile.permitted_target_types]
        if target_type not in permitted_upper:
            return (
                False,
                f"Target type '{target_type}' is not permitted by scan profile '{profile.id}' ({profile.permitted_target_types}).",
                [],
            )

        # 2. Strict authorization revalidation (SCAN_ACTIVE operation)
        is_authz, authz_reason = verify_target_authorization(
            db=db,
            investigation=investigation,
            target=target_clean,
            operation="SCAN_ACTIVE",
            actor_user=actor_user,
            client_ip=client_ip,
            request_id=request_id,
        )
        if not is_authz:
            return False, f"Target authorization failed: {authz_reason}", []

        # 3. DNS resolution & IP policy verification
        resolved_ips: List[str] = []
        if target_type in ("IP", "CIDR"):
            resolved_ips = [target_clean]
        elif target_type == "DOMAIN":
            try:
                addr_infos = socket.getaddrinfo(target_clean, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                resolved_ips = list(dict.fromkeys(info[4][0] for info in addr_infos))
            except Exception as exc:
                logger.warning("DNS resolution failed for target '%s': %s", target_clean, exc)
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

    async def create_scan_job(
        self,
        db: Session,
        investigation: InvestigationModel,
        target: str,
        profile_id: str,
        actor_user: Any,
        client_ip: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> ActiveScanJobModel:
        """Validates scope, registers new scan job record in QUEUED/RUNNING state."""
        profile = get_scan_profile(profile_id)
        if not profile:
            raise NmapExecutionError(f"Unknown or disabled scan profile: '{profile_id}'")

        if not investigation.active_scanning_enabled:
            raise NmapExecutionError("Active scanning is not enabled for this investigation.")

        # Revalidate authorization & resolve IPs
        is_valid, reason, resolved_ips = self.resolve_and_revalidate_target(
            db=db,
            investigation=investigation,
            target=target,
            profile=profile,
            actor_user=actor_user,
            client_ip=client_ip,
            request_id=request_id,
        )

        actor_id = getattr(actor_user, "id", "system")

        if not is_valid:
            log_audit_event(
                db=db,
                event_type="SCAN_ACTIVE_DENIED",
                outcome="FAILURE",
                actor_id=actor_id,
                request_id=request_id,
                ip_address=client_ip,
                details={
                    "investigation_id": investigation.id,
                    "target": target,
                    "profile_id": profile_id,
                    "reason": reason,
                },
            )
            raise NmapExecutionError(f"Pre-scan validation failed: {reason}")

        # Guard against duplicate concurrent scans on same target & profile
        existing_stmt = select(ActiveScanJobModel).where(
            ActiveScanJobModel.investigation_id == investigation.id,
            ActiveScanJobModel.target == target.strip(),
            ActiveScanJobModel.scan_profile == profile.id,
            ActiveScanJobModel.status.in_(["QUEUED", "RUNNING", "AUTHORIZING"]),
        )
        existing_job = db.scalars(existing_stmt).first()
        if existing_job:
            raise NmapExecutionError(
                f"A scan job ({existing_job.id}) is already {existing_job.status} for target '{target}'."
            )

        job_id = f"nmap-{uuid.uuid4().hex[:12]}"
        job = ActiveScanJobModel(
            id=job_id,
            investigation_id=investigation.id,
            requested_by=actor_id,
            target=target.strip(),
            resolved_ips=resolved_ips,
            scan_profile=profile.id,
            scan_profile_version=profile.version,
            status="QUEUED",
            started_at=utc_now(),
            command_summary=f"nmap {' '.join(profile.args)} {target.strip()}",
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        log_audit_event(
            db=db,
            event_type="SCAN_ACTIVE_QUEUED",
            outcome="SUCCESS",
            actor_id=actor_id,
            request_id=request_id,
            ip_address=client_ip,
            details={
                "job_id": job.id,
                "investigation_id": investigation.id,
                "target": target.strip(),
                "profile_id": profile.id,
                "resolved_ips": resolved_ips,
            },
        )

        return job

    async def execute_scan(
        self,
        db_factory: Any,
        job_id: str,
        client_ip: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        """Executes Nmap via bounded subprocess, streams XML to evidence, and persists findings."""
        detector = get_nmap_detector()
        binary_path = detector.resolve_binary_path()

        # Temporary working directory for scan XML
        temp_dir = Path("data/temp_scans")
        temp_dir.mkdir(parents=True, exist_ok=True)
        xml_output_file = temp_dir / f"nmap_{job_id}_{uuid.uuid4().hex[:8]}.xml"

        with db_factory() as db:
            job = db.get(ActiveScanJobModel, job_id)
            if not job:
                logger.error("Scan job %s not found for execution", job_id)
                return

            profile = get_scan_profile(job.scan_profile)
            if not profile:
                job.status = "FAILED"
                job.error_category = "INVALID_PROFILE"
                job.error_message = f"Profile '{job.scan_profile}' not found or disabled."
                job.completed_at = utc_now()
                db.commit()
                return

            if not binary_path:
                job.status = "FAILED"
                job.error_category = "TOOL_UNAVAILABLE"
                job.error_message = "Nmap executable not found on host system."
                job.completed_at = utc_now()
                db.commit()
                log_audit_event(
                    db=db,
                    event_type="SCAN_ACTIVE_FAILED",
                    outcome="FAILURE",
                    actor_id=job.requested_by,
                    request_id=request_id,
                    ip_address=client_ip,
                    details={"job_id": job.id, "error_category": job.error_category},
                )
                return

            target = job.target
            requested_by = job.requested_by
            investigation_id = job.investigation_id
            job.status = "RUNNING"
            db.commit()

        # Command construction: fixed args + -oX output_file + target
        # Target passed strictly at end as target argument
        cmd: List[str] = [binary_path] + list(profile.args) + ["-oX", str(xml_output_file.resolve()), target]

        async with self._semaphore:
            # Check for cancellation before process start
            async with self._lock:
                if job_id in self._cancellation_requests:
                    reason = self._cancellation_requests.pop(job_id)
                    with db_factory() as db:
                        j = db.get(ActiveScanJobModel, job_id)
                        if j:
                            j.status = "CANCELLED"
                            j.cancellation_reason = reason
                            j.completed_at = utc_now()
                            db.commit()
                    return

            proc: Optional[asyncio.subprocess.Process] = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                async with self._lock:
                    self._active_processes[job_id] = proc

                with db_factory() as db:
                    j = db.get(ActiveScanJobModel, job_id)
                    if j:
                        log_audit_event(
                            db=db,
                            event_type="SCAN_ACTIVE_STARTED",
                            outcome="SUCCESS",
                            actor_id=j.requested_by,
                            request_id=request_id,
                            ip_address=client_ip,
                            details={"job_id": j.id, "target": j.target, "profile": profile.id},
                        )

                # Await subprocess with profile timeout
                stdout_data, stderr_data = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=profile.timeout_seconds,
                )
                exit_code = proc.returncode

            except asyncio.TimeoutError:
                logger.warning("Scan job %s timed out after %ds", job_id, profile.timeout_seconds)
                if proc:
                    try:
                        proc.kill()
                        await proc.wait()
                    except Exception as k_err:
                        logger.error("Error terminating timed-out scan process: %s", k_err)

                with db_factory() as db:
                    j = db.get(ActiveScanJobModel, job_id)
                    if j:
                        j.status = "TIMED_OUT"
                        j.error_category = "TIMEOUT"
                        j.error_message = f"Scan exceeded configured profile timeout of {profile.timeout_seconds} seconds."
                        j.completed_at = utc_now()
                        if j.started_at:
                            j.duration_seconds = (ensure_utc(j.completed_at) - ensure_utc(j.started_at)).total_seconds()
                        db.commit()
                        log_audit_event(
                            db=db,
                            event_type="SCAN_ACTIVE_TIMED_OUT",
                            outcome="FAILURE",
                            actor_id=j.requested_by,
                            request_id=request_id,
                            ip_address=client_ip,
                            details={"job_id": j.id, "timeout_seconds": profile.timeout_seconds},
                        )
                return

            except Exception as exc:
                logger.exception("Subprocess execution failure for job %s: %s", job_id, exc)
                with db_factory() as db:
                    j = db.get(ActiveScanJobModel, job_id)
                    if j:
                        j.status = "FAILED"
                        j.error_category = "SUBPROCESS_ERROR"
                        j.error_message = str(exc)
                        j.completed_at = utc_now()
                        db.commit()
                return

            finally:
                async with self._lock:
                    self._active_processes.pop(job_id, None)

        # Check if cancellation was triggered during execution
        async with self._lock:
            if job_id in self._cancellation_requests:
                reason = self._cancellation_requests.pop(job_id)
                with db_factory() as db:
                    j = db.get(ActiveScanJobModel, job_id)
                    if j:
                        j.status = "CANCELLED"
                        j.cancellation_reason = reason
                        j.completed_at = utc_now()
                        if j.started_at:
                            j.duration_seconds = (ensure_utc(j.completed_at) - ensure_utc(j.started_at)).total_seconds()
                        db.commit()
                        log_audit_event(
                            db=db,
                            event_type="SCAN_ACTIVE_CANCELLED",
                            outcome="SUCCESS",
                            actor_id=j.requested_by,
                            request_id=request_id,
                            ip_address=client_ip,
                            details={"job_id": j.id, "reason": reason},
                        )
                # Cleanup temp file if exists
                if xml_output_file.exists():
                    try:
                        xml_output_file.unlink()
                    except Exception:
                        pass
                return

        # Process XML output file
        with db_factory() as db:
            j = db.get(ActiveScanJobModel, job_id)
            if not j:
                return

            j.exit_code = exit_code
            j.completed_at = utc_now()
            if j.started_at:
                j.duration_seconds = (ensure_utc(j.completed_at) - ensure_utc(j.started_at)).total_seconds()

            if not xml_output_file.exists():
                logger.error("Nmap output XML file %s missing after execution", xml_output_file)
                j.status = "FAILED"
                j.error_category = "OUTPUT_FILE_MISSING"
                j.error_message = stderr_data.decode("utf-8", errors="replace")[:500] or "Nmap XML output file not generated."
                db.commit()
                log_audit_event(
                    db=db,
                    event_type="SCAN_ACTIVE_FAILED",
                    outcome="FAILURE",
                    actor_id=j.requested_by,
                    request_id=request_id,
                    ip_address=client_ip,
                    details={"job_id": j.id, "error_category": j.error_category},
                )
                return

            xml_content = xml_output_file.read_text(encoding="utf-8", errors="replace")

            # Store forensic evidence
            evidence_store = EvidenceStore()
            evidence_id = f"ev-nmap-{uuid.uuid4().hex[:12]}"
            rel_path, content_hash, size_bytes = evidence_store.store_evidence(
                investigation_id=j.investigation_id,
                evidence_id=evidence_id,
                source_type="nmap",
                content=xml_content,
            )

            evidence_record = EvidenceModel(
                id=evidence_id,
                investigation_id=j.investigation_id,
                job_id=None,  # Points to collection_jobs table in FK, stored in metadata instead
                source_type="nmap",
                source_name=f"Nmap {profile.name}",
                target=j.target,
                collection_status="SUCCESS" if exit_code == 0 else "PARTIAL",
                raw_content_path=rel_path,
                content_hash=content_hash,
                content_size_bytes=size_bytes,
                source_metadata={
                    "active_scan_job_id": j.id,
                    "profile_id": profile.id,
                    "exit_code": exit_code,
                },
                collected_at=utc_now(),
            )
            db.add(evidence_record)
            j.evidence_id = evidence_id

            # Parse XML and persist structured findings
            try:
                parsed_result: ParsedNmapResult = parse_nmap_xml(xml_content)

                # Persist hosts and ports
                for host in parsed_result.hosts:
                    host_id = f"host-{uuid.uuid4().hex[:12]}"
                    primary_hostname = host.hostnames[0] if host.hostnames else None
                    host_record = ScanFindingHostModel(
                        id=host_id,
                        investigation_id=j.investigation_id,
                        job_id=j.id,
                        address=host.address,
                        address_type=host.address_type,
                        status=host.status,
                        hostname=primary_hostname,
                        os_match=host.os_match,
                        evidence_id=evidence_id,
                        created_at=utc_now(),
                    )
                    db.add(host_record)

                    # Persist open/closed/filtered ports
                    for port in host.ports:
                        port_id = f"port-{uuid.uuid4().hex[:12]}"
                        port_record = ScanFindingPortModel(
                            id=port_id,
                            host_id=host_id,
                            job_id=j.id,
                            protocol=port.protocol,
                            port_number=port.port,
                            state=port.state,
                            service_name=port.service.name,
                            product=port.service.product,
                            version=port.service.version,
                            extra_info=port.service.extrainfo,
                            cpe=port.service.cpe,
                            method=port.service.method,
                            confidence=port.service.confidence,
                            created_at=utc_now(),
                        )
                        db.add(port_record)

                        # Upsert service entity if open
                        if port.state == "open":
                            self._upsert_service_entity(
                                db=db,
                                investigation_id=j.investigation_id,
                                host_address=host.address,
                                port=port,
                                evidence_id=evidence_id,
                            )

                    # Upsert host IP entity
                    self._upsert_ip_entity(
                        db=db,
                        investigation_id=j.investigation_id,
                        host=host,
                        evidence_id=evidence_id,
                    )

                j.status = "COMPLETED" if exit_code == 0 else "PARTIAL"
                db.commit()

                log_audit_event(
                    db=db,
                    event_type="SCAN_ACTIVE_COMPLETED",
                    outcome="SUCCESS",
                    actor_id=j.requested_by,
                    request_id=request_id,
                    ip_address=client_ip,
                    details={
                        "job_id": j.id,
                        "status": j.status,
                        "hosts_found": len(parsed_result.hosts),
                        "evidence_id": evidence_id,
                    },
                )

            except NmapXmlParseError as pe:
                logger.error("XML parse failure for job %s: %s", job_id, pe)
                j.status = "FAILED"
                j.error_category = "XML_PARSE_ERROR"
                j.error_message = str(pe)
                db.commit()
                log_audit_event(
                    db=db,
                    event_type="SCAN_ACTIVE_FAILED",
                    outcome="FAILURE",
                    actor_id=j.requested_by,
                    request_id=request_id,
                    ip_address=client_ip,
                    details={"job_id": j.id, "error": str(pe)},
                )

            finally:
                if xml_output_file.exists():
                    try:
                        xml_output_file.unlink()
                    except Exception:
                        pass

    def _upsert_ip_entity(
        self,
        db: Session,
        investigation_id: str,
        host: Any,
        evidence_id: str,
    ) -> None:
        """Upserts an IP entity in the entities table with provenance."""
        canonical_ip = host.address.strip()
        existing = db.scalars(
            select(EntityModel).where(
                EntityModel.investigation_id == investigation_id,
                EntityModel.entity_type == "ip",
                EntityModel.canonical_value == canonical_ip,
            )
        ).first()

        now = utc_now()
        if existing:
            existing.last_seen = now
            if evidence_id not in (existing.evidence_ids or []):
                existing.evidence_ids = (existing.evidence_ids or []) + [evidence_id]
        else:
            new_entity = EntityModel(
                id=f"ent-ip-{uuid.uuid4().hex[:12]}",
                investigation_id=investigation_id,
                entity_type="ip",
                canonical_value=canonical_ip,
                original_value=canonical_ip,
                first_seen=now,
                last_seen=now,
                evidence_ids=[evidence_id],
                metadata_json={
                    "status": host.status,
                    "hostnames": host.hostnames,
                    "os_match": host.os_match,
                },
            )
            db.add(new_entity)

    def _upsert_service_entity(
        self,
        db: Session,
        investigation_id: str,
        host_address: str,
        port: Any,
        evidence_id: str,
    ) -> None:
        """Upserts a discovered open port/service entity."""
        canonical_val = f"{host_address}:{port.port}/{port.protocol}"
        existing = db.scalars(
            select(EntityModel).where(
                EntityModel.investigation_id == investigation_id,
                EntityModel.entity_type == "service",
                EntityModel.canonical_value == canonical_val,
            )
        ).first()

        now = utc_now()
        if existing:
            existing.last_seen = now
            if evidence_id not in (existing.evidence_ids or []):
                existing.evidence_ids = (existing.evidence_ids or []) + [evidence_id]
        else:
            new_entity = EntityModel(
                id=f"ent-svc-{uuid.uuid4().hex[:12]}",
                investigation_id=investigation_id,
                entity_type="service",
                canonical_value=canonical_val,
                original_value=f"{port.service.name} on {port.port}/{port.protocol}",
                first_seen=now,
                last_seen=now,
                evidence_ids=[evidence_id],
                metadata_json={
                    "service_name": port.service.name,
                    "product": port.service.product,
                    "version": port.service.version,
                    "state": port.state,
                    "cpe": port.service.cpe,
                },
            )
            db.add(new_entity)

    async def cancel_scan(
        self,
        db: Session,
        job_id: str,
        actor_id: str,
        reason: str = "User cancelled scan",
    ) -> bool:
        """Cancels a running or queued scan job and terminates child process."""
        async with self._lock:
            self._cancellation_requests[job_id] = reason
            proc = self._active_processes.get(job_id)
            if proc:
                try:
                    proc.kill()
                except Exception as exc:
                    logger.warning("Error killing process for job %s: %s", job_id, exc)

        job = db.get(ActiveScanJobModel, job_id)
        if job and job.status in ("QUEUED", "RUNNING", "AUTHORIZING"):
            job.status = "CANCELLED"
            job.cancellation_reason = reason
            job.completed_at = utc_now()
            if job.started_at:
                job.duration_seconds = (ensure_utc(job.completed_at) - ensure_utc(job.started_at)).total_seconds()
            db.commit()
            log_audit_event(
                db=db,
                event_type="SCAN_ACTIVE_CANCELLED",
                outcome="SUCCESS",
                actor_id=actor_id,
                details={"job_id": job.id, "reason": reason},
            )
            return True

        return False


_runner_instance: Optional[NmapRunner] = None


def get_nmap_runner() -> NmapRunner:
    """Returns singleton instance of NmapRunner."""
    global _runner_instance
    if _runner_instance is None:
        _runner_instance = NmapRunner()
    return _runner_instance
