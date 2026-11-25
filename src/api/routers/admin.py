"""
FootprintIQ - Administrator Scope, Scanner, Sharing, Audit Logs & System Administration Router
Strictly guarded by administrator RBAC (Depends(require_admin)).
"""

import os
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from src.api.dependencies import require_admin, get_repository
from src.db.repository import FootprintIQRepository
from src.authorization.target_authorizer import TargetAuthorizer, TargetAuthorizationError, TargetSyntaxError
from src.collectors.nmap_collector import NmapCollector
from src.collectors.nessus_collector import NessusCollector
from src.storage.seaweedfs_client import SeaweedFSClient
from src.services.rbac_service import record_security_audit

router = APIRouter(prefix="/api/v1/admin", tags=["Administration"])


class AddLabRangeRequest(BaseModel):
    range_spec: str = Field(..., example="198.51.100.0/24")
    description: str = Field("Approved Private Assessment Range")


class RemoveLabRangeRequest(BaseModel):
    range_spec: str


class AddAuthorizedDomainRequest(BaseModel):
    domain: str = Field(..., example="lab.internal.local")
    scope_notes: str = Field("Explicitly authorized security assessment domain")


class RemoveAuthorizedDomainRequest(BaseModel):
    domain: str


class ShareInvestigationRequest(BaseModel):
    username: str = Field(..., example="investigator2")
    permission_level: str = Field("read_write", example="read_write")


@router.get("/scope", dependencies=[Depends(require_admin)])
def get_admin_scope():
    return TargetAuthorizer().get_scope_summary()


@router.post("/scope/ranges")
def add_lab_range(
    req: AddLabRangeRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(require_admin),
    repo: FootprintIQRepository = Depends(get_repository)
):
    auth = TargetAuthorizer()
    try:
        entry = auth.add_approved_lab_range(
            range_spec=req.range_spec,
            description=req.description,
            added_by=admin.get("username", "admin")
        )
        record_security_audit(
            repo,
            user=admin,
            action="ADMIN_ADD_LAB_RANGE",
            target_resource=entry["range"],
            details={"description": req.description},
            outcome="SUCCESS",
            request=request,
        )
        return {"status": "SUCCESS", "entry": entry}
    except (TargetAuthorizationError, TargetSyntaxError, ValueError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/scope/ranges")
def remove_lab_range(
    range_spec: str,
    request: Request,
    admin: Dict[str, Any] = Depends(require_admin),
    repo: FootprintIQRepository = Depends(get_repository)
):
    auth = TargetAuthorizer()
    removed = auth.remove_approved_lab_range(range_spec)
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Lab range '{range_spec}' not found.")
    record_security_audit(
        repo,
        user=admin,
        action="ADMIN_REMOVE_LAB_RANGE",
        target_resource=range_spec,
        outcome="SUCCESS",
        request=request,
    )
    return {"status": "SUCCESS", "removed": range_spec}


@router.post("/scope/domains")
def add_authorized_domain(
    req: AddAuthorizedDomainRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(require_admin),
    repo: FootprintIQRepository = Depends(get_repository)
):
    auth = TargetAuthorizer()
    try:
        entry = auth.add_authorized_domain(
            domain=req.domain,
            scope_notes=req.scope_notes,
            added_by=admin.get("username", "admin")
        )
        record_security_audit(
            repo,
            user=admin,
            action="ADMIN_ADD_AUTH_DOMAIN",
            target_resource=entry["domain"],
            details={"scope_notes": req.scope_notes},
            outcome="SUCCESS",
            request=request,
        )
        return {"status": "SUCCESS", "entry": entry}
    except (TargetAuthorizationError, TargetSyntaxError, ValueError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/scope/domains")
def remove_authorized_domain(
    domain: str,
    request: Request,
    admin: Dict[str, Any] = Depends(require_admin),
    repo: FootprintIQRepository = Depends(get_repository)
):
    auth = TargetAuthorizer()
    removed = auth.remove_authorized_domain(domain)
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Authorized domain '{domain}' not found.")
    record_security_audit(
        repo,
        user=admin,
        action="ADMIN_REMOVE_AUTH_DOMAIN",
        target_resource=domain,
        outcome="SUCCESS",
        request=request,
    )
    return {"status": "SUCCESS", "removed": domain}


@router.get("/system", dependencies=[Depends(require_admin)])
def get_admin_system_diagnostics(repo: FootprintIQRepository = Depends(get_repository)):
    """Detailed infrastructure and scanner diagnostics restricted to Administrators."""
    db_ok = getattr(repo, "db", None) is not None
    storage = SeaweedFSClient().check_health()
    nmap = NmapCollector()
    nessus = NessusCollector().get_api_capabilities()
    from src.collectors.nuclei_collector import NucleiCollector
    nuclei = NucleiCollector().check_readiness()
    from src.services.graph_intelligence_service import GraphIntelligenceService
    graph_runtime = GraphIntelligenceService.get_maltego_runtime_status()
    return {
        "database": {"engine": "Microsoft SQL Server", "available": db_ok},
        "storage": storage,
        "nmap": {"version": nmap.version, "capabilities": nmap.capabilities},
        "nessus": nessus,
        "nuclei": nuclei,
        "maltego_graph": graph_runtime,
        "public_api_docs_enabled": os.getenv("ENABLE_PUBLIC_API_DOCS", "false").lower() == "true"
    }


@router.get("/audit-logs", dependencies=[Depends(require_admin)])
def get_audit_logs(
    limit: int = 150,
    action: Optional[str] = None,
    outcome: Optional[str] = None,
    repo: FootprintIQRepository = Depends(get_repository)
):
    """Returns read-only security audit trail entries for Administrators."""
    safe_limit = max(1, min(int(limit), 500))
    return repo.list_audit_logs(limit=safe_limit, action=action, outcome=outcome)


@router.post("/investigations/{investigation_id}/share")
def share_investigation_with_user(
    investigation_id: str,
    req: ShareInvestigationRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(require_admin),
    repo: FootprintIQRepository = Depends(get_repository)
):
    inv = repo.get_investigation(investigation_id)
    camp = repo.get_recon_campaign(investigation_id)
    if not inv and not camp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation '{investigation_id}' not found.")
    target_user = repo.get_user_by_username(req.username)
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{req.username}' not found.")
    if target_user.get("role") != "investigator":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Investigation shares apply only to investigator accounts.")

    target_inv_id = (inv or {}).get("investigation_id") or (camp or {}).get("investigation_id") or investigation_id
    repo.share_investigation(
        investigation_id=target_inv_id,
        user_id=target_user["id"],
        granted_by_id=admin.get("id"),
        permission_level=req.permission_level,
    )
    record_security_audit(
        repo,
        user=admin,
        action="INVESTIGATION_SHARED",
        target_resource=investigation_id,
        details={"shared_with": req.username, "permission_level": req.permission_level},
        outcome="SUCCESS",
        request=request,
    )
    return {"status": "SUCCESS", "investigation_id": investigation_id, "shared_with": req.username}


@router.delete("/investigations/{investigation_id}/share/{username}")
def revoke_investigation_share(
    investigation_id: str,
    username: str,
    request: Request,
    admin: Dict[str, Any] = Depends(require_admin),
    repo: FootprintIQRepository = Depends(get_repository)
):
    target_user = repo.get_user_by_username(username)
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{username}' not found.")
    inv = repo.get_investigation(investigation_id)
    camp = repo.get_recon_campaign(investigation_id)
    target_inv_id = (inv or {}).get("investigation_id") or (camp or {}).get("investigation_id") or investigation_id
    removed = repo.revoke_investigation_share(target_inv_id, target_user["id"])
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Share grant not found.")
    record_security_audit(
        repo,
        user=admin,
        action="INVESTIGATION_UNSHARED",
        target_resource=investigation_id,
        details={"revoked_user": username},
        outcome="SUCCESS",
        request=request,
    )
    return {"status": "SUCCESS", "investigation_id": investigation_id, "revoked_user": username}
