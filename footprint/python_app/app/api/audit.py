"""Audit log inspection API endpoints restricted to Administrators."""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.database import get_db
from app.models.user import UserModel
from app.models.audit import AuditLogModel
from app.schemas.auth import AuditLogResponse
from app.core.security import ROLE_ADMINISTRATOR
from app.api.deps import require_role

router = APIRouter(prefix="/api/v1/audit-logs", tags=["Audit Logs"])


@router.get("", response_model=List[AuditLogResponse])
def get_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = Query(None),
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    db: Session = Depends(get_db),
):
    """Retrieves recent security and authentication audit logs. Restricted to Administrator."""
    stmt = select(AuditLogModel).order_by(AuditLogModel.timestamp.desc())
    if event_type:
        stmt = stmt.where(AuditLogModel.event_type == event_type)
    stmt = stmt.limit(limit)

    logs = db.scalars(stmt).all()
    return [log.to_dict() for log in logs]
