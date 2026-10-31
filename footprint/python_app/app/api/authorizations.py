"""FastAPI router for administrative target authorization management."""

import uuid
from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.database import get_db
from app.models.investigation import InvestigationModel
from app.models.recon import TargetAuthorizationModel, ensure_utc
from app.models.user import UserModel
from app.schemas.recon import TargetAuthorizationCreate, TargetAuthorizationResponse
from app.api.deps import require_permission
from app.core.auth import log_audit_event
from app.services.target_authorization import classify_target

router = APIRouter(prefix="/api/v1/investigations/{investigation_id}/authorizations", tags=["Target Authorizations"])


@router.post(
    "",
    response_model=TargetAuthorizationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create administrative target authorization",
)
def create_target_authorization(
    investigation_id: str,
    payload: TargetAuthorizationCreate,
    request: Request,
    current_user: UserModel = Depends(require_permission("scope.manage")),
    db: Session = Depends(get_db),
):
    """Issues an explicit administrative target authorization record permitting reconnaissance operations."""
    investigation = db.get(InvestigationModel, investigation_id)
    if not investigation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    target_type = classify_target(payload.target)
    client_ip = request.client.host if request.client else None
    req_id = getattr(request.state, "request_id", None)

    auth_record = TargetAuthorizationModel(
        id=f"auth-{uuid.uuid4().hex[:16]}",
        investigation_id=investigation_id,
        target=payload.target.strip().lower(),
        target_type=target_type,
        allowed_operations=payload.allowed_operations,
        authorization_reference=payload.authorization_reference.strip(),
        approved_by=(payload.approved_by.strip() if payload.approved_by else None) or current_user.username,
        valid_from=ensure_utc(payload.valid_from) or ensure_utc(datetime.now(timezone.utc)),
        valid_to=ensure_utc(payload.valid_to),
        is_revoked=False,
        notes=payload.notes,
    )
    db.add(auth_record)
    db.commit()
    db.refresh(auth_record)

    log_audit_event(
        db=db,
        event_type="TARGET_AUTHORIZATION_CREATED",
        outcome="SUCCESS",
        actor_id=current_user.id,
        request_id=req_id,
        ip_address=client_ip,
        details={
            "authorization_id": auth_record.id,
            "investigation_id": investigation_id,
            "target": auth_record.target,
            "allowed_operations": auth_record.allowed_operations,
            "reference": auth_record.authorization_reference,
        },
    )

    return auth_record.to_dict()


@router.get(
    "",
    response_model=List[TargetAuthorizationResponse],
    summary="List target authorizations for investigation",
)
def list_target_authorizations(
    investigation_id: str,
    current_user: UserModel = Depends(require_permission("investigation.view")),
    db: Session = Depends(get_db),
):
    """Returns all authorization records associated with an investigation."""
    investigation = db.get(InvestigationModel, investigation_id)
    if not investigation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    stmt = (
        select(TargetAuthorizationModel)
        .where(TargetAuthorizationModel.investigation_id == investigation_id)
        .order_by(TargetAuthorizationModel.created_at.desc())
    )
    records = db.scalars(stmt).all()
    return [r.to_dict() for r in records]


@router.delete(
    "/{authorization_id}",
    summary="Revoke target authorization",
)
def revoke_target_authorization(
    investigation_id: str,
    authorization_id: str,
    request: Request,
    current_user: UserModel = Depends(require_permission("scope.manage")),
    db: Session = Depends(get_db),
):
    """Revokes a target authorization record, preventing further reconnaissance against that target."""
    record = db.get(TargetAuthorizationModel, authorization_id)
    if not record or record.investigation_id != investigation_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorization record not found")

    record.is_revoked = True
    db.commit()

    client_ip = request.client.host if request.client else None
    req_id = getattr(request.state, "request_id", None)
    log_audit_event(
        db=db,
        event_type="TARGET_AUTHORIZATION_REVOKED",
        outcome="SUCCESS",
        actor_id=current_user.id,
        request_id=req_id,
        ip_address=client_ip,
        details={
            "authorization_id": authorization_id,
            "investigation_id": investigation_id,
            "target": record.target,
        },
    )

    return {"message": "Authorization record successfully revoked", "authorization_id": authorization_id}
