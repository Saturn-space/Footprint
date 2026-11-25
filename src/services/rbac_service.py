"""
FootprintIQ - Centralized Role-Based Access Control (RBAC), Ownership & Safe Audit Policy
Strictly enforces default-deny separation between:
  - admin: Full read visibility + user/scope/system/scanner/audit administration (NO investigation execution)
  - investigator: Execution-capable owner/shared-scoped workflow (NO admin controls)
"""

import json
import logging
from typing import Any, Dict, Iterable, Optional, Set
from fastapi import HTTPException, Request, status

logger = logging.getLogger("FootprintIQ.RBAC")

ROLE_ADMIN = "admin"
ROLE_INVESTIGATOR = "investigator"
VALID_ROLES: Set[str] = {ROLE_ADMIN, ROLE_INVESTIGATOR}

SENSITIVE_DETAIL_KEYS = {
    "password", "hashed_password", "secret", "secret_key", "access_key",
    "token", "access_token", "jwt", "csrf", "csrf_token", "authorization",
    "api_key", "apikey", "cookie", "fiq_session", "fiq_csrf"
}


def normalize_role(role: Optional[str]) -> Optional[str]:
    if not isinstance(role, str):
        return None
    cleaned = role.strip().lower()
    return cleaned if cleaned in VALID_ROLES else None


def is_admin_user(user: Optional[Dict[str, Any]]) -> bool:
    return bool(user and normalize_role(user.get("role")) == ROLE_ADMIN)


def is_investigator_user(user: Optional[Dict[str, Any]]) -> bool:
    return bool(user and normalize_role(user.get("role")) == ROLE_INVESTIGATOR)


def extract_client_ip(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()[:45]
    if request.client and request.client.host:
        return str(request.client.host)[:45]
    return None


def sanitize_audit_details(details: Any) -> Optional[str]:
    """Serializes audit metadata while stripping passwords, API keys, JWTs, and secrets."""
    if details is None:
        return None
    if isinstance(details, str):
        try:
            parsed = json.loads(details)
            details = parsed
        except Exception:
            return details[:1000]

    def _scrub(obj: Any) -> Any:
        if isinstance(obj, dict):
            cleaned = {}
            for k, v in obj.items():
                key_low = str(k).lower()
                if any(s in key_low for s in SENSITIVE_DETAIL_KEYS):
                    cleaned[k] = "[REDACTED]"
                else:
                    cleaned[k] = _scrub(v)
            return cleaned
        if isinstance(obj, list):
            return [_scrub(i) for i in obj[:50]]
        if isinstance(obj, str) and len(obj) > 500:
            return obj[:500] + "..."
        return obj

    try:
        return json.dumps(_scrub(details), default=str)
    except Exception:
        return json.dumps({"note": "unserializable_details"})


def record_security_audit(
    repo: Any,
    *,
    user: Optional[Dict[str, Any]],
    action: str,
    target_resource: Optional[str] = None,
    details: Any = None,
    outcome: str = "SUCCESS",
    request: Optional[Request] = None,
    actor_role: Optional[str] = None,
) -> None:
    """Safely persists an audit log entry without breaking the caller on logging failure."""
    uid = user.get("id") if isinstance(user, dict) else None
    resolved_role = actor_role or (user.get("role") if isinstance(user, dict) else None) or "anonymous"
    safe_outcome = outcome if outcome in {"SUCCESS", "DENIED", "FAILED"} else "SUCCESS"
    ip_addr = extract_client_ip(request)
    payload_dict: Dict[str, Any] = {}
    if isinstance(details, dict):
        payload_dict = dict(details)
    elif details is not None:
        payload_dict = {"detail": str(details)}
    if isinstance(user, dict) and user.get("username") and "actor_username" not in payload_dict:
        payload_dict["actor_username"] = user["username"]

    try:
        repo.log_audit(
            user_id=uid,
            actor_role=resolved_role,
            action=action,
            target_resource=target_resource,
            outcome=safe_outcome,
            details_json=sanitize_audit_details(payload_dict),
            ip_address=ip_addr,
        )
    except Exception as exc:
        logger.warning(f"Audit logging error for action={action}: {exc}")


def check_user_active_and_valid(user: Optional[Dict[str, Any]]) -> None:
    """Validates active, approved user and recognized RBAC role (default-deny)."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Sign in to access FootprintIQ resources.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    role = normalize_role(user.get("role"))
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: unrecognized or missing account role."
        )
    if not user.get("is_active", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended or inactive. Contact an administrator."
        )
    if not user.get("is_approved", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is pending administrator approval."
        )


def ensure_roles(
    user: Dict[str, Any],
    allowed_roles: Iterable[str],
    *,
    repo: Any = None,
    request: Optional[Request] = None,
    action: str = "PERMISSION_DENIED",
    target_resource: Optional[str] = None,
    detail: Optional[str] = None,
) -> Dict[str, Any]:
    """Centralized default-deny role guard with denial audit logging."""
    check_user_active_and_valid(user)
    role = normalize_role(user.get("role"))
    allowed = {normalize_role(r) for r in allowed_roles if normalize_role(r)}
    if role not in allowed:
        if repo is not None:
            record_security_audit(
                repo,
                user=user,
                action=action,
                target_resource=target_resource or (request.url.path if request else None),
                details={"required_roles": sorted(allowed), "actual_role": role},
                outcome="DENIED",
                request=request,
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail or "You do not have permission to perform this action."
        )
    return user


def user_owns_or_shares_investigation(
    repo: Any,
    user: Dict[str, Any],
    investigation_id: Optional[str],
) -> bool:
    """
    Returns True if:
      - user is admin (read visibility across all investigations — execution is blocked separately), OR
      - investigation/campaign creator_id matches user["id"], OR
      - authorized_by matches user["username"], OR
      - user has an explicit investigation_share grant in repository.
    Default-deny when unowned or owned by another investigator.
    """
    if not user or not investigation_id:
        return False
    if is_admin_user(user):
        return True
    if not is_investigator_user(user):
        return False

    uid = user.get("id")
    uname = user.get("username")

    inv = repo.get_investigation(investigation_id)
    camp = repo.get_recon_campaign(investigation_id)
    if not inv and camp and camp.get("investigation_id") and camp.get("investigation_id") != investigation_id:
        inv = repo.get_investigation(camp["investigation_id"])

    if not inv and not camp:
        return False

    if uid is not None:
        if camp and camp.get("creator_id") == uid:
            return True
        if inv and inv.get("creator_id") == uid:
            return True
    if uname and camp and camp.get("authorized_by") == uname:
        return True

    target_inv_id = (inv or {}).get("investigation_id") or (camp or {}).get("investigation_id") or investigation_id
    if uid is not None and hasattr(repo, "has_investigation_share") and repo.has_investigation_share(target_inv_id, uid):
        return True

    return False


def enforce_investigation_access(
    repo: Any,
    user: Dict[str, Any],
    investigation_id: str,
    *,
    require_execution: bool = False,
    request: Optional[Request] = None,
    action_label: str = "INVESTIGATION_ACCESS",
) -> Dict[str, Any]:
    """
    Enforces existence, role capability (admin read-only vs investigator execution),
    and owner/shared investigation access.
    """
    check_user_active_and_valid(user)
    if require_execution and is_admin_user(user):
        record_security_audit(
            repo,
            user=user,
            action="PERMISSION_DENIED",
            target_resource=investigation_id,
            details={"reason": "admin_execution_blocked", "operation": action_label},
            outcome="DENIED",
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrators have read-only oversight over investigations and cannot execute or modify investigation workflows."
        )

    camp = repo.get_recon_campaign(investigation_id)
    inv = repo.get_investigation(investigation_id)
    if not camp and not inv:
        raise HTTPException(status_code=404, detail=f"Investigation or campaign '{investigation_id}' not found.")

    if not user_owns_or_shares_investigation(repo, user, investigation_id):
        record_security_audit(
            repo,
            user=user,
            action="PERMISSION_DENIED",
            target_resource=investigation_id,
            details={"reason": "ownership_or_share_required", "operation": action_label},
            outcome="DENIED",
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: you do not have permission to access this investigation."
        )

    return camp or inv


def filter_accessible_investigation_ids(
    repo: Any,
    user: Dict[str, Any],
) -> Optional[Set[str]]:
    """
    Returns None for Admin (unfiltered full read visibility),
    or exact set of investigation_id / recon_id strings accessible to this investigator.
    """
    if is_admin_user(user):
        return None
    if not is_investigator_user(user):
        return set()

    uid = user.get("id")
    uname = user.get("username")
    allowed: Set[str] = set()

    for inv in repo.list_investigations():
        iid = inv.get("investigation_id")
        if iid and uid is not None and inv.get("creator_id") == uid:
            allowed.add(iid)

    for camp in repo.list_recon_campaigns():
        rid = camp.get("recon_id")
        iid = camp.get("investigation_id")
        if (uid is not None and camp.get("creator_id") == uid) or (uname and camp.get("authorized_by") == uname) or (iid in allowed):
            if rid:
                allowed.add(rid)
            if iid:
                allowed.add(iid)

    if uid is not None and hasattr(repo, "list_shared_investigation_ids"):
        for shared_id in repo.list_shared_investigation_ids(uid):
            allowed.add(shared_id)
            for camp in repo.list_recon_campaigns():
                if camp.get("investigation_id") == shared_id and camp.get("recon_id"):
                    allowed.add(camp["recon_id"])

    return allowed
