"""
FootprintIQ - Scans Execution Router
Endpoints:
- POST /api/v1/scans (Launch authorized scan execution - Investigator owner/shared only)
- GET  /api/v1/scans (List scans - Admin all, Investigator owner/shared)
- GET  /api/v1/scans/{scan_id} (Scan execution details & status)
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from src.db.repository import FootprintIQRepository
from src.orchestration.unified_orchestrator import UnifiedScanOrchestrator
from src.authorization.target_authorizer import TargetAuthorizationError
from src.api.dependencies import get_repository, get_current_user, require_investigator
from src.services.rbac_service import (
    enforce_investigation_access,
    filter_accessible_investigation_ids,
    record_security_audit,
)

router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])


class LaunchScanRequest(BaseModel):
    investigation_id: str = Field(..., example="INV-20261110-001")
    scan_type: str = Field(
        ...,
        example="combined",
        description="One of: 'passive', 'network_discovery', 'nmap_services', 'nmap_nse', 'nuclei', 'nessus', 'combined'"
    )
    target: str = Field(..., example="192.0.2.10")
    profile: Optional[str] = Field("lab-basic", example="lab-basic")
    custom_scripts: Optional[List[str]] = Field(None, example=["ftp-vsftpd-backdoor", "http-title"])
    nuclei_profile: Optional[str] = Field("http-security", example="http-security")
    nuclei_tags: Optional[List[str]] = Field(None)
    nuclei_severities: Optional[List[str]] = Field(None)


@router.post("", status_code=status.HTTP_200_OK)
@router.post("/", status_code=status.HTTP_200_OK, include_in_schema=False)
def launch_scan(
    req: LaunchScanRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository)
):
    if (req.scan_type or "").strip().lower() == "greenbone":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active Greenbone/OpenVAS execution has been deprecated and removed. Use 'nuclei' or 'nmap_nse' for vulnerability scanning (historical Greenbone findings remain preserved)."
        )

    enforce_investigation_access(
        repo,
        current_user,
        req.investigation_id,
        require_execution=True,
        request=request,
        action_label="SCAN_LAUNCH",
    )
    orchestrator = UnifiedScanOrchestrator(repo=repo)

    # 1. Global target authorization & syntax safety check (Fail-closed upfront)
    if req.scan_type in ("network_discovery", "nmap_services", "nmap_nse", "nuclei", "nessus", "combined"):
        try:
            auth_rec = orchestrator.authorizer.authorize_target(
                req.target,
                profile=req.profile or "lab-basic"
            )
            if not auth_rec.authorized:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Target '{req.target}' is unauthorized: {getattr(auth_rec, 'failure_reason', 'Not authorized')}"
                )
        except TargetAuthorizationError as e:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

    # 2. Verify target is registered under this specific investigation
    if req.scan_type in ("network_discovery", "nmap_services", "nmap_nse", "nuclei", "nessus", "combined"):
        try:
            orchestrator.authorizer.authorize_target(
                req.target,
                profile=req.profile or "lab-basic",
                investigation_id=req.investigation_id,
                repo=repo
            )
        except TargetAuthorizationError as e:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

    try:
        result = orchestrator.execute_scan(
            investigation_id=req.investigation_id,
            scan_type=req.scan_type,
            target=req.target,
            profile=req.profile or "default",
            custom_scripts=req.custom_scripts,
            nuclei_profile=req.nuclei_profile,
            nuclei_tags=req.nuclei_tags,
            nuclei_severities=req.nuclei_severities,
        )
        if result.get("status") == "FAILED":
            err_msg = result.get("error", "Scan execution failed")
            if "strictly prohibited" in err_msg or "unauthorized" in err_msg.lower():
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=err_msg)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)

        record_security_audit(
            repo,
            user=current_user,
            action="SCAN_EXECUTED",
            target_resource=req.target,
            details={"investigation_id": req.investigation_id, "scan_type": req.scan_type, "status": result.get("status")},
            outcome="SUCCESS",
            request=request,
        )
        return result
    except HTTPException:
        raise
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("")
@router.get("/", include_in_schema=False)
def list_scans(
    request: Request,
    investigation_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    if investigation_id:
        enforce_investigation_access(repo, current_user, investigation_id, request=request, action_label="SCAN_LIST")
        return repo.list_scans(investigation_id=investigation_id)

    scans = repo.list_scans()
    accessible = filter_accessible_investigation_ids(repo, current_user)
    if accessible is None:
        return scans
    return [s for s in scans if (s.get("investigation_id") in accessible or s.get("recon_id") in accessible)]


@router.get("/{scan_id}")
def get_scan(
    scan_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    scan = repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found.")

    inv_id = scan.get("investigation_id") or scan.get("recon_id")
    if inv_id:
        enforce_investigation_access(repo, current_user, inv_id, request=request, action_label="SCAN_VIEW")
    elif current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    findings = [f for f in repo.list_findings(investigation_id=inv_id) if f.get("scan_id") == scan_id]
    return {**scan, "findings": findings, "findings_count": len(findings)}
