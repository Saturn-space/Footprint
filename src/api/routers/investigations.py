"""
FootprintIQ - Investigations Router
Endpoints:
- POST /api/v1/investigations (Create new investigation - Investigator only)
- GET  /api/v1/investigations (List investigations - Admin all, Investigator owner/shared)
- GET  /api/v1/investigations/{id} (Retrieve investigation details & exposure summary)
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from src.db.repository import FootprintIQRepository
from src.api.dependencies import (
    get_repository,
    get_current_user,
    require_investigator,
)
from src.services.rbac_service import (
    enforce_investigation_access,
    filter_accessible_investigation_ids,
    record_security_audit,
)

router = APIRouter(prefix="/api/v1/investigations", tags=["Investigations"])


class CreateInvestigationRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=200, example="External Security Audit")
    description: Optional[str] = Field("", example="Authorized reconnaissance and vulnerability assessment")


@router.post("", status_code=status.HTTP_201_CREATED)
@router.post("/", status_code=status.HTTP_201_CREATED, include_in_schema=False)
def create_investigation(
    req: CreateInvestigationRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository)
):
    uid = current_user.get("id")
    inv = repo.create_investigation(
        title=req.title,
        description=req.description or "",
        creator_id=uid
    )
    record_security_audit(
        repo,
        user=current_user,
        action="INVESTIGATION_CREATED",
        target_resource=inv["investigation_id"],
        details={"title": inv["title"]},
        outcome="SUCCESS",
        request=request,
    )
    return inv


@router.get("")
@router.get("/", include_in_schema=False)
def list_investigations(
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    invs = repo.list_investigations()
    accessible = filter_accessible_investigation_ids(repo, current_user)
    if accessible is None:
        return invs
    return [i for i in invs if i.get("investigation_id") in accessible]


@router.get("/{investigation_id}")
def get_investigation(
    investigation_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    enforce_investigation_access(repo, current_user, investigation_id, request=request, action_label="INVESTIGATION_VIEW")
    inv = repo.get_investigation(investigation_id)
    if not inv:
        camp = repo.get_recon_campaign(investigation_id)
        if not camp:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation '{investigation_id}' not found.")
        inv = camp

    targets = repo.list_authorized_targets(investigation_id)
    scans = repo.list_scans(investigation_id)
    findings = repo.list_findings(investigation_id)
    evidence = repo.list_evidence(investigation_id)

    return {
        **inv,
        "targets_count": len(targets),
        "scans_count": len(scans),
        "findings_count": len(findings),
        "evidence_count": len(evidence)
    }
