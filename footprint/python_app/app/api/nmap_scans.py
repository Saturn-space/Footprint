"""FastAPI router for Nmap tool availability, scan profiles, dispatch, and results."""

import asyncio
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.database import get_db, SessionLocal
from app.models.investigation import InvestigationModel
from app.models.recon import EvidenceModel
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel
from app.models.user import UserModel
from app.api.deps import get_current_user, require_permission
from app.services.active.nmap_detector import get_nmap_detector
from app.services.active.profiles import list_scan_profiles, get_scan_profile
from app.services.active.runner import get_nmap_runner, NmapExecutionError
from app.services.evidence_store import get_evidence_store
from app.schemas.scan import (
    NmapStatusResponse,
    ScanProfileResponse,
    ScanJobCreate,
    ScanJobResponse,
    ScanCancelRequest,
    ScanPortResponse,
    ScanHostResponse,
    ScanResultsResponse,
)

router = APIRouter(tags=["Active Nmap Reconnaissance"])


# 1. Tool availability
@router.get(
    "/api/v1/tools/nmap/status",
    response_model=NmapStatusResponse,
    summary="Get Nmap tool availability and runtime status",
)
def get_nmap_status(
    current_user: UserModel = Depends(get_current_user),
) -> NmapStatusResponse:
    """Safe diagnostic report of Nmap installation, version, and execution capability."""
    detector = get_nmap_detector()
    report = detector.check_availability()
    return NmapStatusResponse(**report)


# 2. Vetted scan profiles
@router.get(
    "/api/v1/nmap/profiles",
    response_model=List[ScanProfileResponse],
    summary="List permitted Nmap scan profiles",
)
def get_scan_profiles(
    current_user: UserModel = Depends(get_current_user),
) -> List[ScanProfileResponse]:
    """Returns list of vetted, administrator-configured scan profiles."""
    profiles = list_scan_profiles()
    return [ScanProfileResponse(**p.to_dict()) for p in profiles]


# 3. Trigger active scan
@router.post(
    "/api/v1/investigations/{investigation_id}/nmap-scans",
    response_model=ScanJobResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Dispatch an authorized Nmap active scan",
)
async def dispatch_nmap_scan(
    investigation_id: str,
    payload: ScanJobCreate,
    request: Request,
    current_user: UserModel = Depends(require_permission("recon.active")),
    db: Session = Depends(get_db),
) -> ScanJobResponse:
    """Dispatches a vetted Nmap scan against an explicitly authorized target."""
    investigation = db.get(InvestigationModel, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found.",
        )

    if not investigation.active_scanning_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Active scanning is not enabled for this investigation.",
        )

    client_ip = request.client.host if request.client else None
    req_id = getattr(request.state, "request_id", None)
    runner = get_nmap_runner()

    try:
        job = await runner.create_scan_job(
            db=db,
            investigation=investigation,
            target=payload.target,
            profile_id=payload.profile_id,
            actor_user=current_user,
            client_ip=client_ip,
            request_id=req_id,
        )
    except NmapExecutionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

    # Launch background scan execution
    asyncio.create_task(
        runner.execute_scan(
            db_factory=SessionLocal,
            job_id=job.id,
            client_ip=client_ip,
            request_id=req_id,
        )
    )

    return ScanJobResponse(**job.to_dict())


# 4. List scans for investigation
@router.get(
    "/api/v1/investigations/{investigation_id}/nmap-scans",
    response_model=List[ScanJobResponse],
    summary="List active scan jobs for an investigation",
)
def list_investigation_scans(
    investigation_id: str,
    current_user: UserModel = Depends(require_permission("investigation.view")),
    db: Session = Depends(get_db),
) -> List[ScanJobResponse]:
    """Retrieves all active scan jobs registered under an investigation."""
    investigation = db.get(InvestigationModel, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found.",
        )

    stmt = (
        select(ActiveScanJobModel)
        .where(ActiveScanJobModel.investigation_id == investigation_id)
        .order_by(ActiveScanJobModel.started_at.desc())
    )
    jobs = db.scalars(stmt).all()
    return [ScanJobResponse(**j.to_dict()) for j in jobs]


# 5. Get scan job by ID
@router.get(
    "/api/v1/nmap-scans/{job_id}",
    response_model=ScanJobResponse,
    summary="Get status and details of an Nmap scan job",
)
def get_scan_job(
    job_id: str,
    current_user: UserModel = Depends(require_permission("investigation.view")),
    db: Session = Depends(get_db),
) -> ScanJobResponse:
    """Retrieves current execution status and metadata for a scan job."""
    job = db.get(ActiveScanJobModel, job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job '{job_id}' not found.",
        )
    return ScanJobResponse(**job.to_dict())


# 6. Cancel scan job
@router.post(
    "/api/v1/nmap-scans/{job_id}/cancel",
    response_model=ScanJobResponse,
    summary="Cancel a running or queued scan job",
)
async def cancel_scan_job(
    job_id: str,
    payload: ScanCancelRequest,
    current_user: UserModel = Depends(require_permission("recon.active")),
    db: Session = Depends(get_db),
) -> ScanJobResponse:
    """Terminates subprocess and marks scan job as cancelled."""
    job = db.get(ActiveScanJobModel, job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job '{job_id}' not found.",
        )

    if job.status not in ("QUEUED", "RUNNING", "AUTHORIZING"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan job cannot be cancelled because it is in '{job.status}' state.",
        )

    runner = get_nmap_runner()
    await runner.cancel_scan(
        db=db,
        job_id=job_id,
        actor_id=current_user.id,
        reason=payload.reason or "User requested cancellation",
    )
    db.refresh(job)
    return ScanJobResponse(**job.to_dict())


# 7. Get scan findings / results
@router.get(
    "/api/v1/nmap-scans/{job_id}/results",
    response_model=ScanResultsResponse,
    summary="Get parsed findings and port data for a scan job",
)
def get_scan_results(
    job_id: str,
    current_user: UserModel = Depends(require_permission("investigation.view")),
    db: Session = Depends(get_db),
) -> ScanResultsResponse:
    """Returns normalized host and port findings discovered during the scan."""
    job = db.get(ActiveScanJobModel, job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job '{job_id}' not found.",
        )

    stmt = select(ScanFindingHostModel).where(ScanFindingHostModel.job_id == job_id)
    hosts = db.scalars(stmt).all()

    host_responses: List[ScanHostResponse] = []
    total_ports = 0

    for h in hosts:
        port_responses: List[ScanPortResponse] = []
        for p in h.ports:
            port_responses.append(
                ScanPortResponse(
                    id=p.id,
                    protocol=p.protocol,
                    port_number=p.port_number,
                    state=p.state,
                    service_name=p.service_name,
                    product=p.product,
                    version=p.version,
                    extra_info=p.extra_info,
                    cpe=p.cpe,
                    method=p.method,
                    confidence=p.confidence,
                    created_at=p.created_at,
                )
            )
            total_ports += 1

        host_responses.append(
            ScanHostResponse(
                id=h.id,
                address=h.address,
                address_type=h.address_type,
                status=h.status,
                hostname=h.hostname,
                os_match=h.os_match,
                ports=port_responses,
            )
        )

    return ScanResultsResponse(
        job_id=job.id,
        investigation_id=job.investigation_id,
        target=job.target,
        scan_profile=job.scan_profile,
        status=job.status,
        evidence_id=job.evidence_id,
        hosts=host_responses,
        total_hosts=len(host_responses),
        total_ports=total_ports,
    )


# 8. Download raw XML evidence
@router.get(
    "/api/v1/nmap-scans/{job_id}/xml",
    summary="Download raw Nmap XML evidence",
)
def download_scan_xml(
    job_id: str,
    current_user: UserModel = Depends(require_permission("investigation.view")),
    db: Session = Depends(get_db),
) -> Response:
    """Streams the raw Nmap XML evidence with cryptographic hash header."""
    job = db.get(ActiveScanJobModel, job_id)
    if not job or not job.evidence_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence for scan job '{job_id}' not found.",
        )

    evidence = db.get(EvidenceModel, job.evidence_id)
    if not evidence or not evidence.raw_content_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Raw evidence file not found.",
        )

    evidence_store = get_evidence_store()
    try:
        content_bytes = evidence_store.retrieve_evidence_bytes(evidence.raw_content_path)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence file missing on disk.",
        )

    return Response(
        content=content_bytes,
        media_type="application/xml",
        headers={
            "Content-Disposition": f'attachment; filename="nmap_{job.id}.xml"',
            "X-Content-SHA256": evidence.content_hash,
        },
    )
