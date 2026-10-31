import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.database import get_db
from app.models.investigation import InvestigationModel
from app.schemas.investigation import InvestigationCreate, InvestigationResponse
from app.logging_config import get_logger

from app.api.deps import get_current_user_optional
from app.core.security import has_permission
from app.core.auth import log_audit_event
from app.services.reporting.graphml_generator import GraphMLExporter
from app.models.user import UserModel

logger = get_logger("footprintiq.api.investigations")

router = APIRouter(prefix="/api/v1/investigations", tags=["Investigations"])


@router.get("", response_model=List[InvestigationResponse])
def list_investigations(
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Lists all registered investigations in the database."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not has_permission(current_user.role, "investigation.view"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires permission: investigation.view",
        )

    stmt = select(InvestigationModel).order_by(InvestigationModel.created_at.desc())
    results = db.scalars(stmt).all()

    # Map model attributes to response schema
    responses = []
    for inv in results:
        data = inv.to_dict()
        responses.append(InvestigationResponse(
            id=data["id"],
            name=data["name"],
            organization_name=data["organization_name"],
            description=data["description"],
            lead_investigator=data["lead_investigator"],
            team_members=data["team_members"],
            status=data["status"],
            scope=data["scope"],
            active_scanning_enabled=data["active_scanning_enabled"],
            authorization_reference=data["authorization_reference"],
            authorization_expiry=inv.authorization_expiry,
            created_at=inv.created_at,
            updated_at=inv.updated_at
        ))
    return responses


@router.post("", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
def create_investigation(
    payload: InvestigationCreate,
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Registers a new investigation and persists target scopes."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not has_permission(current_user.role, "investigation.create"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires permission: investigation.create",
        )
    """Registers a new investigation and persists target scopes."""
    inv_id = payload.id or f"inv-{uuid.uuid4().hex[:8]}"

    existing = db.get(InvestigationModel, inv_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Investigation with identifier '{inv_id}' already exists."
        )

    model = InvestigationModel(
        id=inv_id,
        name=payload.name,
        organization_name=payload.organization_name,
        description=payload.description,
        lead_investigator=payload.lead_investigator,
        team_members=payload.team_members,
        status=payload.status,
        owned_domains=payload.scope.owned_domains,
        approved_ips=payload.scope.approved_ips,
        approved_cidrs=payload.scope.approved_cidrs,
        active_targets=payload.scope.active_targets,
        active_scanning_enabled=payload.active_scanning_enabled,
        authorization_reference=payload.authorization_reference,
        authorization_expiry=payload.authorization_expiry
    )

    db.add(model)
    db.commit()
    db.refresh(model)

    logger.info(f"Created investigation '{model.name}' ({model.id}) for '{model.organization_name}' by user '{current_user.username}'")

    data = model.to_dict()
    return InvestigationResponse(
        id=data["id"],
        name=data["name"],
        organization_name=data["organization_name"],
        description=data["description"],
        lead_investigator=data["lead_investigator"],
        team_members=data["team_members"],
        status=data["status"],
        scope=data["scope"],
        active_scanning_enabled=data["active_scanning_enabled"],
        authorization_reference=data["authorization_reference"],
        authorization_expiry=model.authorization_expiry,
        created_at=model.created_at,
        updated_at=model.updated_at
    )


@router.get("/{investigation_id}", response_model=InvestigationResponse)
def get_investigation(
    investigation_id: str,
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Retrieves an individual investigation by ID."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not has_permission(current_user.role, "investigation.view"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires permission: investigation.view",
        )

    model = db.get(InvestigationModel, investigation_id)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found."
        )

    data = model.to_dict()
    return InvestigationResponse(
        id=data["id"],
        name=data["name"],
        organization_name=data["organization_name"],
        description=data["description"],
        lead_investigator=data["lead_investigator"],
        team_members=data["team_members"],
        status=data["status"],
        scope=data["scope"],
        active_scanning_enabled=data["active_scanning_enabled"],
        authorization_reference=data["authorization_reference"],
        authorization_expiry=model.authorization_expiry,
        created_at=model.created_at,
        updated_at=model.updated_at
    )


@router.get("/{investigation_id}/export/graphml")
def export_investigation_graphml(
    investigation_id: str,
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Exports investigation entities, hosts, ports, and vulnerabilities as standard GraphML XML."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not has_permission(current_user.role, "investigation.view"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires permission: investigation.view",
        )

    model = db.get(InvestigationModel, investigation_id)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found.",
        )

    try:
        xml_content = GraphMLExporter.generate_graphml(investigation_id=investigation_id, db=db)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate GraphML export: {str(e)}",
        )

    log_audit_event(
        db=db,
        event_type="REPORT_EXPORT",
        actor_id=current_user.id,
        outcome="SUCCESS",
        details={"investigation_id": investigation_id, "format": "GRAPHML"},
    )

    filename = f"knowledge_graph_{investigation_id}.graphml"
    return Response(
        content=xml_content,
        media_type="application/xml",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )

