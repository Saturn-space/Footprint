"""
FootprintIQ - Vulnerability Findings Router
Endpoints:
- GET /api/v1/findings (Filtered findings list - Role & ownership scoped)
- GET /api/v1/findings/{finding_id} (Finding details)
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from typing import Dict, Any, Optional
from src.db.repository import FootprintIQRepository
from src.services.exposure_scoring import ExposureScoringEngine
from src.api.dependencies import get_repository, get_current_user
from src.services.rbac_service import (
    enforce_investigation_access,
    filter_accessible_investigation_ids,
)

router = APIRouter(prefix="/api/v1/findings", tags=["Vulnerability Findings"])


@router.get("")
@router.get("/", include_in_schema=False)
def list_findings(
    request: Request,
    investigation_id: Optional[str] = None,
    severity: Optional[str] = None,
    target_ip: Optional[str] = None,
    detection_source: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    if investigation_id:
        enforce_investigation_access(repo, current_user, investigation_id, request=request, action_label="FINDINGS_LIST")

    findings = repo.list_findings(
        investigation_id=investigation_id,
        severity=severity,
        target_ip=target_ip
    )
    accessible = filter_accessible_investigation_ids(repo, current_user)
    if accessible is not None:
        findings = [f for f in findings if f.get("investigation_id") in accessible]

    if detection_source:
        findings = [f for f in findings if f.get("detection_source") == detection_source]

    enriched = []
    for f in findings:
        risk_info = ExposureScoringEngine.calculate_finding_risk(f)
        enriched.append({**f, "risk_calculation": risk_info})

    return enriched


@router.get("/{finding_id}")
def get_finding(
    finding_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    f = repo.get_finding(finding_id)
    if not f:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding '{finding_id}' not found.")

    inv_id = f.get("investigation_id")
    if inv_id:
        enforce_investigation_access(repo, current_user, inv_id, request=request, action_label="FINDING_VIEW")
    elif current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    risk_info = ExposureScoringEngine.calculate_finding_risk(f)
    return {**f, "risk_calculation": risk_info}
