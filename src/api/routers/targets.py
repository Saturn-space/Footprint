"""
FootprintIQ - Authorized Targets Router
Endpoints:
- POST /api/v1/targets (Register authorized scope target - Investigator owner/shared only)
- GET  /api/v1/targets (List authorized scope targets - Role & ownership scoped)
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from src.db.repository import FootprintIQRepository
from src.api.dependencies import get_repository, get_current_user, require_investigator
from src.services.rbac_service import (
    enforce_investigation_access,
    filter_accessible_investigation_ids,
    record_security_audit,
)

router = APIRouter(prefix="/api/v1/targets", tags=["Authorized Targets"])


class AddTargetRequest(BaseModel):
    investigation_id: str = Field(..., example="INV-20261110-001")
    target: str = Field(..., example="192.0.2.10")
    name: str = Field(..., example="Authorized Target Host")
    scope: str = Field(..., example="Authorized Assessment Scope")
    permitted_profiles: str = Field("lab-basic,lab-safe-minimal", example="lab-basic")
    allowed_ports: str = Field("1-65535", example="1-65535")


@router.post("", status_code=status.HTTP_201_CREATED)
@router.post("/", status_code=status.HTTP_201_CREATED, include_in_schema=False)
def add_authorized_target(
    req: AddTargetRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository)
):
    enforce_investigation_access(
        repo,
        current_user,
        req.investigation_id,
        require_execution=True,
        request=request,
        action_label="TARGET_AUTHORIZE",
    )
    target_rec = repo.add_authorized_target(
        investigation_id=req.investigation_id,
        target=req.target,
        name=req.name,
        scope=req.scope,
        permitted_profiles=req.permitted_profiles,
        allowed_ports=req.allowed_ports,
        authorized_by=current_user.get("username", "investigator")
    )
    record_security_audit(
        repo,
        user=current_user,
        action="TARGET_AUTHORIZED",
        target_resource=req.target,
        details={"investigation_id": req.investigation_id, "scope": req.scope},
        outcome="SUCCESS",
        request=request,
    )
    return target_rec


@router.get("")
@router.get("/", include_in_schema=False)
def list_targets(
    request: Request,
    investigation_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    if investigation_id:
        enforce_investigation_access(repo, current_user, investigation_id, request=request, action_label="TARGET_LIST")
        return repo.list_authorized_targets(investigation_id=investigation_id)

    targets = repo.list_authorized_targets()
    accessible = filter_accessible_investigation_ids(repo, current_user)
    if accessible is None:
        return targets
    return [t for t in targets if t.get("investigation_id") in accessible]
