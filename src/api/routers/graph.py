"""
FootprintIQ - Investigation Entity Graph & Maltego Interchange API Router
Endpoints:
- GET  /api/v1/graph/status (Host Maltego & Graph Interchange runtime readiness)
- GET  /api/v1/investigations/{investigation_id}/graph
- POST /api/v1/investigations/{investigation_id}/graph/rebuild
- POST /api/v1/investigations/{investigation_id}/graph/entities
- POST /api/v1/investigations/{investigation_id}/graph/relationships
- GET  /api/v1/investigations/{investigation_id}/graph/export?fmt=graphml|csv|json
- POST /api/v1/investigations/{investigation_id}/graph/import
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from typing import Any, Dict, Optional

from src.api.dependencies import get_current_user, get_repository, require_investigator
from src.db.repository import FootprintIQRepository
from src.services.graph_intelligence_service import GraphIntelligenceService
from src.services.rbac_service import enforce_investigation_access, record_security_audit

router = APIRouter(prefix="/api/v1", tags=["Entity Graph & Maltego"])


class AddEntityRequest(BaseModel):
    entity_type: str = Field(..., example="domain")
    value: str = Field(..., example="portal.example.com")
    label: Optional[str] = Field(None, example="portal.example.com")
    source_tool: str = Field("analyst_manual", example="maltego_import")
    evidence_ref: Optional[str] = Field(None, example="OSINT-manual-01")
    risk_level: str = Field("info", example="info")
    confidence: float = Field(0.85, ge=0.1, le=1.0)
    link_to_node_id: Optional[str] = None
    relationship_type: str = Field("RELATED_TO", example="HAS_SUBDOMAIN")


class AddRelationshipRequest(BaseModel):
    source_node_id: str = Field(..., example="ENT:DOMAIN:abcdef123456")
    target_node_id: str = Field(..., example="ENT:IP:123456abcdef")
    relationship_type: str = Field("RESOLVES_TO", example="RESOLVES_TO")
    evidence_ref: Optional[str] = Field(None, example="manual_analyst_correlation")
    confidence: float = Field(0.85, ge=0.1, le=1.0)


@router.get("/graph/status")
def get_maltego_graph_status(
    _current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Returns truthful Maltego & native Investigation Entity Graph engine status."""
    return GraphIntelligenceService.get_maltego_runtime_status()


@router.get("/investigations/{investigation_id}/graph")
def get_investigation_graph(
    investigation_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository),
):
    enforce_investigation_access(
        repo,
        current_user,
        investigation_id,
        request=request,
        action_label="GRAPH_VIEW",
    )
    svc = GraphIntelligenceService(repo=repo)
    try:
        return svc.build_investigation_graph(investigation_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post("/investigations/{investigation_id}/graph/rebuild")
def rebuild_investigation_graph(
    investigation_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository),
):
    enforce_investigation_access(
        repo,
        current_user,
        investigation_id,
        require_execution=True,
        request=request,
        action_label="GRAPH_REBUILD",
    )
    svc = GraphIntelligenceService(repo=repo)
    graph = svc.sync_campaign_graph(investigation_id)
    if graph is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation '{investigation_id}' not found.")

    record_security_audit(
        repo,
        user=current_user,
        action="GRAPH_REBUILT",
        target_resource=investigation_id,
        details={"nodes": graph["metrics"]["node_count"], "edges": graph["metrics"]["edge_count"]},
        outcome="SUCCESS",
        request=request,
    )
    return graph


@router.post("/investigations/{investigation_id}/graph/entities", status_code=status.HTTP_201_CREATED)
def add_graph_entity(
    investigation_id: str,
    req: AddEntityRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository),
):
    enforce_investigation_access(
        repo,
        current_user,
        investigation_id,
        require_execution=True,
        request=request,
        action_label="GRAPH_ENTITY_ADD",
    )
    svc = GraphIntelligenceService(repo=repo)
    try:
        res = svc.add_manual_entity(
            investigation_id=investigation_id,
            entity_type=req.entity_type,
            value=req.value,
            label=req.label,
            source_tool=req.source_tool,
            evidence_ref=req.evidence_ref,
            risk_level=req.risk_level,
            confidence=req.confidence,
            link_to_node_id=req.link_to_node_id,
            relationship_type=req.relationship_type,
            added_by=current_user.get("username"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    record_security_audit(
        repo,
        user=current_user,
        action="GRAPH_ENTITY_ADDED",
        target_resource=investigation_id,
        details={"entity_type": req.entity_type, "value": req.value},
        outcome="SUCCESS",
        request=request,
    )
    return res


@router.post("/investigations/{investigation_id}/graph/relationships", status_code=status.HTTP_201_CREATED)
def add_graph_relationship(
    investigation_id: str,
    req: AddRelationshipRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository),
):
    enforce_investigation_access(
        repo,
        current_user,
        investigation_id,
        require_execution=True,
        request=request,
        action_label="GRAPH_RELATIONSHIP_ADD",
    )
    svc = GraphIntelligenceService(repo=repo)
    try:
        res = svc.add_manual_relationship(
            investigation_id=investigation_id,
            source_node_id=req.source_node_id,
            target_node_id=req.target_node_id,
            relationship_type=req.relationship_type,
            evidence_ref=req.evidence_ref,
            confidence=req.confidence,
            added_by=current_user.get("username"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    record_security_audit(
        repo,
        user=current_user,
        action="GRAPH_RELATIONSHIP_ADDED",
        target_resource=investigation_id,
        details={"source": req.source_node_id, "target": req.target_node_id, "type": req.relationship_type},
        outcome="SUCCESS",
        request=request,
    )
    return res


@router.get("/investigations/{investigation_id}/graph/export")
def export_investigation_graph(
    investigation_id: str,
    request: Request,
    fmt: str = "graphml",
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository),
):
    enforce_investigation_access(
        repo,
        current_user,
        investigation_id,
        request=request,
        action_label="GRAPH_EXPORT",
    )
    svc = GraphIntelligenceService(repo=repo)
    try:
        content, filename, media_type = svc.export_graph(investigation_id, fmt=fmt)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    record_security_audit(
        repo,
        user=current_user,
        action="GRAPH_EXPORTED",
        target_resource=investigation_id,
        details={"format": fmt, "file_name": filename},
        outcome="SUCCESS",
        request=request,
    )
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/investigations/{investigation_id}/graph/import")
async def import_investigation_graph(
    investigation_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository),
):
    enforce_investigation_access(
        repo,
        current_user,
        investigation_id,
        require_execution=True,
        request=request,
        action_label="GRAPH_IMPORT",
    )

    ctype = (request.headers.get("content-type") or "").lower()
    filename = "maltego_import.graphml"
    raw_bytes = b""

    if "multipart/form-data" in ctype:
        form = await request.form()
        upload = form.get("file")
        if upload is None or not hasattr(upload, "read"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Multipart field 'file' is required.")
        filename = getattr(upload, "filename", None) or filename
        raw_bytes = await upload.read()
    else:
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Provide multipart 'file' or JSON {filename, content}.")
        if not isinstance(body, dict) or not body.get("content"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="JSON payload must include non-empty 'content'.")
        filename = str(body.get("filename") or filename)
        raw_bytes = str(body["content"]).encode("utf-8")

    svc = GraphIntelligenceService(repo=repo)
    try:
        res = svc.import_graph_file(
            investigation_id=investigation_id,
            filename=filename,
            content_bytes=raw_bytes,
            imported_by=current_user.get("username"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    record_security_audit(
        repo,
        user=current_user,
        action="GRAPH_IMPORTED",
        target_resource=investigation_id,
        details={
            "file_name": filename,
            "imported_entities": res.get("imported_entities"),
            "imported_relationships": res.get("imported_relationships"),
        },
        outcome="SUCCESS",
        request=request,
    )
    return res

