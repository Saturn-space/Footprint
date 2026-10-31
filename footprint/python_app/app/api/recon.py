"""FastAPI router for passive reconnaissance orchestration, evidence, and entity endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.database import get_db
from app.models.investigation import InvestigationModel
from app.models.recon import CollectionJobModel, EvidenceModel, EntityModel
from app.models.user import UserModel
from app.schemas.recon import (
    PassiveReconRequest,
    PassiveReconResponse,
    CollectionJobSummary,
    EvidenceResponse,
    EntityResponse,
    TargetValidationRequest,
    TargetValidationResponse,
)
from app.api.deps import get_current_user, require_permission
from app.services.passive.orchestrator import PassiveReconOrchestrator
from app.services.evidence_store import get_evidence_store
from app.services.target_authorization import (
    verify_target_authorization,
    is_target_in_investigation_scope,
    classify_target,
)

router = APIRouter(prefix="/api/v1/investigations/{investigation_id}", tags=["Passive Reconnaissance"])


@router.post(
    "/passive-recon",
    response_model=PassiveReconResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger passive reconnaissance collection",
)
async def trigger_passive_recon(
    investigation_id: str,
    payload: PassiveReconRequest,
    request: Request,
    current_user: UserModel = Depends(require_permission("recon.passive")),
    db: Session = Depends(get_db),
):
    """Triggers passive reconnaissance pipeline with strict authorization and isolated collector execution."""
    client_ip = request.client.host if request.client else None
    req_id = getattr(request.state, "request_id", None)

    orchestrator = PassiveReconOrchestrator(
        db=db,
        investigation_id=investigation_id,
        actor_user=current_user,
    )

    try:
        result = await orchestrator.run(
            target=payload.target,
            requested_collectors=payload.collectors,
            client_ip=client_ip,
            request_id=req_id,
        )
        return result
    except PermissionError as perm_err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(perm_err),
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(val_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Reconnaissance orchestration failed: {exc}",
        )


@router.post(
    "/validate-target",
    response_model=TargetValidationResponse,
    summary="Validate target authorization without executing reconnaissance",
)
def validate_target(
    investigation_id: str,
    payload: TargetValidationRequest,
    request: Request,
    current_user: UserModel = Depends(require_permission("investigation.view")),
    db: Session = Depends(get_db),
):
    """Validates target classification, scope membership, and authorization validity."""
    investigation = db.get(InvestigationModel, investigation_id)
    if not investigation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    target_type = classify_target(payload.target)
    in_scope = is_target_in_investigation_scope(investigation, payload.target)
    client_ip = request.client.host if request.client else None
    req_id = getattr(request.state, "request_id", None)

    is_authorized, reason = verify_target_authorization(
        db=db,
        investigation=investigation,
        target=payload.target,
        operation=payload.operation,
        actor_user=current_user,
        client_ip=client_ip,
        request_id=req_id,
    )

    return TargetValidationResponse(
        target=payload.target,
        target_type=target_type,
        in_scope=in_scope,
        is_authorized=is_authorized,
        reason=reason,
    )


@router.get(
    "/passive-recon",
    response_model=List[CollectionJobSummary],
    summary="List passive reconnaissance collection jobs",
)
def list_collection_jobs(
    investigation_id: str,
    current_user: UserModel = Depends(require_permission("investigation.view")),
    db: Session = Depends(get_db),
):
    """Returns all collection jobs associated with an investigation."""
    investigation = db.get(InvestigationModel, investigation_id)
    if not investigation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    stmt = (
        select(CollectionJobModel)
        .where(CollectionJobModel.investigation_id == investigation_id)
        .order_by(CollectionJobModel.started_at.desc())
    )
    jobs = db.scalars(stmt).all()
    return [j.to_dict() for j in jobs]


@router.get(
    "/entities",
    response_model=List[EntityResponse],
    summary="List normalized discovered entities",
)
def list_entities(
    investigation_id: str,
    entity_type: Optional[str] = Query(None, description="Optional entity type filter"),
    current_user: UserModel = Depends(require_permission("investigation.view")),
    db: Session = Depends(get_db),
):
    """Returns normalized deduplicated OSINT entities for the investigation."""
    investigation = db.get(InvestigationModel, investigation_id)
    if not investigation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    stmt = select(EntityModel).where(EntityModel.investigation_id == investigation_id)
    if entity_type:
        stmt = stmt.where(EntityModel.entity_type == entity_type.upper().strip())
    stmt = stmt.order_by(EntityModel.last_seen.desc())

    entities = db.scalars(stmt).all()
    return [e.to_dict() for e in entities]


@router.get(
    "/evidence",
    response_model=List[EvidenceResponse],
    summary="List collection evidence metadata",
)
def list_evidence(
    investigation_id: str,
    current_user: UserModel = Depends(require_permission("investigation.view")),
    db: Session = Depends(get_db),
):
    """Returns evidence records for an investigation."""
    investigation = db.get(InvestigationModel, investigation_id)
    if not investigation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    stmt = (
        select(EvidenceModel)
        .where(EvidenceModel.investigation_id == investigation_id)
        .order_by(EvidenceModel.collected_at.desc())
    )
    evidence_items = db.scalars(stmt).all()
    return [evi.to_dict() for evi in evidence_items]


@router.get(
    "/evidence/{evidence_id}/raw",
    summary="Retrieve raw collection evidence with cryptographic hash verification",
)
def get_raw_evidence(
    investigation_id: str,
    evidence_id: str,
    current_user: UserModel = Depends(require_permission("investigation.view")),
    db: Session = Depends(get_db),
):
    """Streams raw collected evidence payload, verifying SHA-256 integrity."""
    evidence = db.get(EvidenceModel, evidence_id)
    if not evidence or evidence.investigation_id != investigation_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence record not found")

    if not evidence.raw_content_path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No raw content stored for this evidence")

    store = get_evidence_store()
    try:
        content_bytes, computed_hash = store.read_evidence(evidence.raw_content_path)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence file missing on server")
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error reading evidence: {exc}")

    # Determine media type
    if evidence.raw_content_path.endswith(".json"):
        media_type = "application/json"
    elif evidence.raw_content_path.endswith(".bin"):
        media_type = "application/octet-stream"
    else:
        media_type = "text/plain; charset=utf-8"

    return Response(
        content=content_bytes,
        media_type=media_type,
        headers={
            "X-Content-SHA256": evidence.content_hash,
            "X-Computed-SHA256": computed_hash,
            "X-Evidence-Integrity": "VERIFIED" if computed_hash == evidence.content_hash else "CORRUPTED",
        },
    )
