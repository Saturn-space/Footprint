"""
FootprintIQ - SeaweedFS & Vault Evidence Management Router
Endpoints:
- GET /api/v1/evidence (List evidence items with IST timestamps & multi-facet filters - Role & ownership scoped)
- GET /api/v1/evidence/{evidence_id} (Retrieve full evidence metadata, SHA-256 digest & scan linkage)
- GET /api/v1/evidence/{evidence_id}/download (Retrieve raw evidence payload)
"""

import os
from fastapi import APIRouter, Depends, HTTPException, Request, status, Response
from typing import Dict, Any, Optional, List
from src.db.repository import FootprintIQRepository
from src.storage.seaweedfs_client import SeaweedFSClient
from src.api.dependencies import get_repository, get_current_user
from src.services.rbac_service import (
    enforce_investigation_access,
    filter_accessible_investigation_ids,
    is_admin_user,
    record_security_audit,
)
from src.utils.timezone import format_ist, to_ist

router = APIRouter(prefix="/api/v1/evidence", tags=["Evidence Management"])


def _enrich_evidence_item(
    ev: Dict[str, Any],
    repo: FootprintIQRepository,
    inv_cache: Dict[str, str],
    scan_cache: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    out = dict(ev)
    inv_id = ev.get("investigation_id")
    if inv_id:
        if inv_id not in inv_cache:
            camp = repo.get_recon_campaign(inv_id)
            inv = repo.get_investigation(inv_id) if not camp else None
            inv_cache[inv_id] = (camp.get("name") if camp else None) or (inv.get("title") if inv else None) or inv_id
        out["investigation_name"] = inv_cache[inv_id]
    else:
        out["investigation_name"] = "Unknown"

    sid = ev.get("scan_id")
    if sid:
        if sid not in scan_cache:
            s_rec = repo.get_scan(sid)
            scan_cache[sid] = s_rec or {}
        s_info = scan_cache[sid]
        run_num = s_info.get("run_number")
        out["run_number"] = run_num
        out["run_label"] = f"Run {int(run_num):03d}" if run_num is not None else sid
    else:
        out["run_number"] = None
        out["run_label"] = "Unlinked Run"

    out["created_at_ist"] = ev.get("created_at_ist") or format_ist(ev.get("created_at"))
    fid = str(ev.get("seaweed_fid") or "")
    lpath = str(ev.get("local_path") or "")
    has_local = bool(lpath and os.path.isfile(lpath))
    has_remote = bool(fid and not fid.startswith("local-"))
    if has_remote and has_local:
        out["storage_status"] = "SeaweedFS + Local"
        out["storage_available"] = True
    elif has_remote:
        out["storage_status"] = "SeaweedFS Archived"
        out["storage_available"] = True
    elif has_local or fid:
        out["storage_status"] = "Local Vault" if has_local else "Local Reference"
        out["storage_available"] = has_local
    else:
        out["storage_status"] = "Missing"
        out["storage_available"] = False

    out["download_url"] = f"/api/v1/evidence/{ev.get('evidence_id')}/download"
    return out


@router.get("")
@router.get("/", include_in_schema=False)
def list_evidence(
    request: Request,
    investigation_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    scanner_source: Optional[str] = None,
    evidence_type: Optional[str] = None,
    search: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    if investigation_id:
        enforce_investigation_access(repo, current_user, investigation_id, request=request, action_label="EVIDENCE_LIST")
        raw_items = repo.list_evidence(
            investigation_id=investigation_id,
            scan_id=scan_id,
            scanner_source=scanner_source,
            evidence_type=evidence_type,
        )
    else:
        raw_items = repo.list_evidence(
            scan_id=scan_id,
            scanner_source=scanner_source,
            evidence_type=evidence_type,
        )
        accessible = filter_accessible_investigation_ids(repo, current_user)
        if accessible is not None:
            raw_items = [e for e in raw_items if e.get("investigation_id") in accessible]

    inv_cache: Dict[str, str] = {}
    scan_cache: Dict[str, Dict[str, Any]] = {}
    enriched: List[Dict[str, Any]] = []
    for e in raw_items:
        item = _enrich_evidence_item(e, repo, inv_cache, scan_cache)
        if date_from or date_to:
            ist_dt = to_ist(item.get("created_at"))
            ist_day = ist_dt.strftime("%Y-%m-%d") if ist_dt else ""
            if date_from and ist_day and ist_day < date_from:
                continue
            if date_to and ist_day and ist_day > date_to:
                continue
        if search:
            q = search.strip().lower()
            hay = " ".join([
                str(item.get("evidence_id") or ""),
                str(item.get("file_name") or ""),
                str(item.get("investigation_id") or ""),
                str(item.get("investigation_name") or ""),
                str(item.get("scan_id") or ""),
                str(item.get("run_label") or ""),
                str(item.get("scanner_source") or ""),
                str(item.get("evidence_type") or ""),
                str(item.get("sha256_hash") or ""),
                str(item.get("target") or ""),
            ]).lower()
            if q not in hay:
                continue
        enriched.append(item)
    return enriched


@router.get("/{evidence_id}")
def get_evidence_metadata(
    evidence_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository),
):
    target_ev = repo.get_evidence(evidence_id)
    if not target_ev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence '{evidence_id}' not found.")

    inv_id = target_ev.get("investigation_id")
    if inv_id:
        enforce_investigation_access(repo, current_user, inv_id, request=request, action_label="EVIDENCE_METADATA")
    elif not is_admin_user(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    enriched = _enrich_evidence_item(target_ev, repo, {}, {})
    record_security_audit(
        repo,
        user=current_user,
        action="EVIDENCE_VIEWED",
        target_resource=evidence_id,
        details={"investigation_id": inv_id, "scan_id": target_ev.get("scan_id")},
        outcome="SUCCESS",
        request=request,
    )
    return enriched


@router.get("/{evidence_id}/download")
def download_evidence(
    evidence_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    target_ev = repo.get_evidence(evidence_id)
    if not target_ev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence '{evidence_id}' not found.")

    inv_id = target_ev.get("investigation_id")
    if inv_id:
        enforce_investigation_access(repo, current_user, inv_id, request=request, action_label="EVIDENCE_DOWNLOAD")
    elif not is_admin_user(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    storage_client = SeaweedFSClient()
    content = storage_client.download_content(
        seaweed_fid=target_ev.get("seaweed_fid"),
        local_path=target_ev.get("local_path")
    )

    if content is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence content could not be retrieved from Evidence Vault.")

    record_security_audit(
        repo,
        user=current_user,
        action="EVIDENCE_DOWNLOADED",
        target_resource=evidence_id,
        details={"investigation_id": inv_id, "file_name": target_ev.get("file_name")},
        outcome="SUCCESS",
        request=request,
    )

    content_type = target_ev.get("content_type", "application/octet-stream")
    file_name = target_ev.get("file_name", "evidence.bin")

    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'}
    )
