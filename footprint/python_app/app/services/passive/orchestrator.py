"""Passive reconnaissance orchestration engine coordinating collectors, evidence persistence, and normalization."""

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from app.config import settings
from app.core.auth import log_audit_event
from app.models.investigation import InvestigationModel
from app.models.recon import CollectionJobModel, EvidenceModel, EntityModel
from app.models.user import UserModel
from app.services.evidence_store import get_evidence_store
from app.services.normalizer import EntityNormalizer
from app.services.target_authorization import verify_target_authorization
from app.services.collectors.base import BaseCollector, CollectorResult
from app.services.collectors.rdap import RDAPCollector
from app.services.collectors.dns_collector import DNSCollector
from app.services.collectors.crtsh import CertificateTransparencyCollector
from app.services.collectors.theharvester import TheHarvesterCollector
from app.services.collectors.search_collector import PublicSearchCollector


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class PassiveReconOrchestrator:
    """Coordinates target authorization validation, collector execution, raw evidence storage, and entity normalization."""

    def __init__(self, db: Session, investigation_id: str, actor_user: UserModel):
        self.db = db
        self.investigation_id = investigation_id
        self.actor_user = actor_user
        self.evidence_store = get_evidence_store()
        self.normalizer = EntityNormalizer(db, investigation_id)

    def _get_registered_collectors(self) -> Dict[str, BaseCollector]:
        """Returns map of supported collector instances."""
        return {
            "rdap": RDAPCollector(),
            "dns": DNSCollector(),
            "crtsh": CertificateTransparencyCollector(),
            "theharvester": TheHarvesterCollector(),
            "search": PublicSearchCollector(),
        }

    async def run(
        self,
        target: str,
        requested_collectors: Optional[List[str]] = None,
        client_ip: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Executes full passive reconnaissance workflow with strict authorization and failure isolation."""
        clean_target = target.strip().lower()

        # 1. Fetch Investigation
        investigation = self.db.get(InvestigationModel, self.investigation_id)
        if not investigation:
            raise ValueError(f"Investigation '{self.investigation_id}' not found.")

        # 2. Strict Target Authorization Check
        is_authorized, auth_reason = verify_target_authorization(
            db=self.db,
            investigation=investigation,
            target=clean_target,
            operation="RECON_PASSIVE",
            actor_user=self.actor_user,
            client_ip=client_ip,
            request_id=request_id,
        )

        if not is_authorized:
            raise PermissionError(f"Target reconnaissance authorization denied: {auth_reason}")

        # 3. Log Audit: PASSIVE_RECON_STARTED
        log_audit_event(
            db=self.db,
            event_type="PASSIVE_RECON_STARTED",
            outcome="SUCCESS",
            actor_id=self.actor_user.id,
            request_id=request_id,
            ip_address=client_ip,
            details={
                "investigation_id": self.investigation_id,
                "target": clean_target,
                "requested_collectors": requested_collectors,
            },
        )

        # 4. Filter collectors to run
        available_collectors = self._get_registered_collectors()
        if requested_collectors:
            selected_collectors = {
                k: v for k, v in available_collectors.items() if k.lower() in [c.lower() for c in requested_collectors]
            }
        else:
            selected_collectors = available_collectors

        # 5. Create collection jobs
        jobs_map: Dict[str, CollectionJobModel] = {}
        for coll_key, coll_instance in selected_collectors.items():
            job = CollectionJobModel(
                id=f"job-{uuid.uuid4().hex[:16]}",
                investigation_id=self.investigation_id,
                target=clean_target,
                collector_name=coll_instance.name,
                status="RUNNING",
                started_at=utc_now(),
                result_summary={},
            )
            self.db.add(job)
            jobs_map[coll_key] = job

        self.db.commit()
        for j in jobs_map.values():
            self.db.refresh(j)

        # 6. Execute collectors concurrently with bounded concurrency
        semaphore = asyncio.Semaphore(settings.RECON_MAX_CONCURRENCY)

        async def _execute_with_isolation(coll_key: str, coll_obj: BaseCollector) -> tuple[str, CollectorResult]:
            async with semaphore:
                try:
                    result = await coll_obj.collect(clean_target)
                    return coll_key, result
                except Exception as exc:
                    return coll_key, CollectorResult(
                        collector_name=coll_obj.name,
                        source_type=getattr(coll_obj, "source_type", "GENERIC"),
                        source_name="internal_error",
                        target=clean_target,
                        status="FAILED",
                        raw_content=str(exc),
                        content_format="text",
                        error_category="UNHANDLED_EXCEPTION",
                        error_message=str(exc),
                    )

        tasks = [
            _execute_with_isolation(key, collector)
            for key, collector in selected_collectors.items()
        ]
        results = await asyncio.gather(*tasks)

        # 7. Ingest findings, store raw evidence, update collection jobs
        created_evidence_count = 0
        total_findings_count = 0

        for coll_key, coll_result in results:
            job = jobs_map[coll_key]
            job.completed_at = utc_now()
            job.status = coll_result.status
            job.error_category = coll_result.error_category
            job.error_message = coll_result.error_message
            job.result_summary = {
                "source_type": coll_result.source_type,
                "source_name": coll_result.source_name,
                "findings_count": len(coll_result.findings),
                "metadata": coll_result.source_metadata,
            }

            # Only persist evidence if collector was actually executed (not unconfigured without attempt)
            if coll_result.status != "NOT_CONFIGURED" or coll_result.raw_content:
                evidence_id = f"evi-{uuid.uuid4().hex[:16]}"
                try:
                    rel_path, sha_hash, size_bytes = self.evidence_store.store_evidence(
                        investigation_id=self.investigation_id,
                        evidence_id=evidence_id,
                        source_type=coll_result.source_type,
                        content=coll_result.raw_content,
                    )
                except Exception as store_err:
                    job.error_message = f"Evidence persistence error: {store_err}"
                    rel_path, sha_hash, size_bytes = None, "storage_failure", 0

                evidence_model = EvidenceModel(
                    id=evidence_id,
                    investigation_id=self.investigation_id,
                    job_id=job.id,
                    source_type=coll_result.source_type,
                    source_name=coll_result.source_name,
                    target=clean_target,
                    collection_status=coll_result.status,
                    raw_content_path=rel_path,
                    content_hash=sha_hash,
                    content_size_bytes=size_bytes,
                    source_metadata=coll_result.source_metadata or {},
                    collected_at=utc_now(),
                )
                self.db.add(evidence_model)
                created_evidence_count += 1

                # Normalize and deduplicate findings
                for finding in coll_result.findings:
                    self.normalizer.ingest_finding(
                        entity_type=finding.entity_type,
                        raw_value=finding.raw_value,
                        evidence_id=evidence_id,
                        metadata=finding.metadata,
                    )
                    total_findings_count += 1

            self.db.commit()

        # 8. Determine overall reconnaissance status
        all_statuses = [j.status for j in jobs_map.values()]
        if all(s == "SUCCESS" for s in all_statuses):
            overall_status = "COMPLETED"
        elif all(s in ("FAILED", "NOT_CONFIGURED") for s in all_statuses):
            overall_status = "FAILED" if any(s == "FAILED" for s in all_statuses) else "NOT_CONFIGURED"
        elif any(s == "SUCCESS" for s in all_statuses):
            overall_status = "PARTIAL" if any(s in ("FAILED", "PARTIAL") for s in all_statuses) else "COMPLETED"
        else:
            overall_status = "PARTIAL"

        # 9. Query current total counts for this investigation
        total_entities_count = self.db.scalar(
            select(func.count(EntityModel.id)).where(EntityModel.investigation_id == self.investigation_id)
        ) or 0

        # 10. Log Audit: PASSIVE_RECON_COMPLETED
        log_audit_event(
            db=self.db,
            event_type="PASSIVE_RECON_COMPLETED",
            outcome="SUCCESS" if overall_status in ("COMPLETED", "PARTIAL") else "FAILURE",
            actor_id=self.actor_user.id,
            request_id=request_id,
            ip_address=client_ip,
            details={
                "investigation_id": self.investigation_id,
                "target": clean_target,
                "overall_status": overall_status,
                "jobs_count": len(jobs_map),
                "created_evidence_count": created_evidence_count,
                "total_findings_count": total_findings_count,
            },
        )

        orchestrator_job_id = f"orch-{uuid.uuid4().hex[:12]}"
        return {
            "investigation_id": self.investigation_id,
            "target": clean_target,
            "orchestrator_job_id": orchestrator_job_id,
            "status": overall_status,
            "collectors": [
                {
                    "id": j.id,
                    "collector_name": j.collector_name,
                    "status": j.status,
                    "result_summary": j.result_summary or {},
                    "error_category": j.error_category,
                    "error_message": j.error_message,
                }
                for j in jobs_map.values()
            ],
            "evidence_collected": created_evidence_count,
            "new_entities_discovered": total_findings_count,
            "total_entities_count": total_entities_count,
        }
