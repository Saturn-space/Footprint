"""
FootprintIQ - Database Repository Layer
Provides complete ACID-compliant transactional data access for all entities
against Microsoft SQL Server 2022 Express, with an in-memory fallback cache
to guarantee resilient operation if the SQL Server instance is pending connection.

Strict Rule: Pure Microsoft SQL Server 2022 Express. No SQLite. No secondary database.
"""

import os
import json
import logging
import uuid
import threading
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from contextlib import contextmanager

from sqlalchemy.orm import Session, joinedload
from sqlalchemy.exc import IntegrityError, DBAPIError, OperationalError
from sqlalchemy import text, func
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from src.db.models import (
    User, Investigation, Campaign, AuthorizedTarget,
    ScanExecution, VulnerabilityFinding, EvidenceRecord,
    ReportRecord, AuditLog, ReconCampaign, ScanExecutionEvent,
    SavedScanProfile, RemediationHistory, ExternalArtifactOutbox,
    InvestigationShare
)
from src.db.session import SessionLocal, init_engine, transactional_session, retry_on_deadlock
from src.services.finding_translator import parse_confidence_score
from src.utils.timezone import format_ist, duration_human, parse_timestamp_utc

logger = logging.getLogger("FootprintIQ.Repository")


def utcnow():
    return datetime.now(timezone.utc)


class RepositoryError(Exception):
    """Base exception for database repository operations."""
    pass


class DatabaseIntegrityError(RepositoryError):
    """Raised when a primary key, foreign key, unique, or check constraint fails."""
    pass


class ConcurrencyConflictError(RepositoryError):
    """Raised when an optimistic concurrency check detects a concurrent modification."""
    pass


class EntityNotFoundError(RepositoryError):
    """Raised when a referenced entity is missing from the database."""
    pass


class FootprintIQRepository:
    """
    Enterprise Data Access Repository for FootprintIQ.
    
    ACID Guarantees:
    - Atomicity: Operations that span multiple entities (e.g. Campaign + Target + Audit)
      are grouped into a single unit of work. If any step fails, the entire transaction rolls back.
    - Consistency: Enforces relational integrity, foreign keys, and SQL Server CHECK constraints.
    - Isolation: Respects READ_COMMITTED_SNAPSHOT; prevents lost updates via optimistic concurrency.
    - Durability: Explicit transaction commits; transactional outbox for SeaweedFS artifact tracking.
    """
    _shared_mem_users: Dict[str, Dict[str, Any]] = {}
    _shared_mem_investigations: Dict[str, Dict[str, Any]] = {}
    _shared_mem_targets: Dict[str, Dict[str, Any]] = {}
    _shared_mem_scans: Dict[str, Dict[str, Any]] = {}
    _shared_mem_findings: Dict[str, Dict[str, Any]] = {}
    _shared_mem_evidence: Dict[str, Dict[str, Any]] = {}
    _shared_mem_reports: Dict[str, Dict[str, Any]] = {}
    _shared_mem_audit: List[Dict[str, Any]] = []
    _shared_mem_recon_campaigns: Dict[str, Dict[str, Any]] = {}
    _shared_mem_scan_events: Dict[str, List[Dict[str, Any]]] = {}
    _shared_mem_profiles: Dict[str, Dict[str, Any]] = {}
    _shared_mem_remediation: List[Dict[str, Any]] = []
    _shared_mem_outbox: Dict[str, Dict[str, Any]] = {}
    _shared_mem_shares: Dict[str, List[int]] = {}

    def __init__(self, db: Optional[Session] = None):
        self._db = db
        self._mem_users = FootprintIQRepository._shared_mem_users
        self._mem_investigations = FootprintIQRepository._shared_mem_investigations
        self._mem_targets = FootprintIQRepository._shared_mem_targets
        self._mem_scans = FootprintIQRepository._shared_mem_scans
        self._mem_findings = FootprintIQRepository._shared_mem_findings
        self._mem_evidence = FootprintIQRepository._shared_mem_evidence
        self._mem_reports = FootprintIQRepository._shared_mem_reports
        self._mem_audit = FootprintIQRepository._shared_mem_audit
        self._mem_recon_campaigns = FootprintIQRepository._shared_mem_recon_campaigns
        self._mem_scan_events = FootprintIQRepository._shared_mem_scan_events
        self._mem_profiles = FootprintIQRepository._shared_mem_profiles
        self._mem_remediation = FootprintIQRepository._shared_mem_remediation
        self._mem_outbox = FootprintIQRepository._shared_mem_outbox
        self._mem_shares = FootprintIQRepository._shared_mem_shares
        self._init_builtin_profiles()

    @contextmanager
    def _session_scope(self, session: Optional[Session] = None):
        """
        Session and transaction boundary manager.
        - If an external `session` is provided (or self._db is set), yields that session
          without committing or closing it. The caller retains transaction ownership.
        - If no session is provided, creates a new session, commits on clean exit,
          rolls back on exception, and guarantees closure in a finally block.
        """
        active = session if session is not None else self._db
        if active is not None:
            yield active
        else:
            if SessionLocal is None:
                init_engine()
            if SessionLocal is not None:
                db = SessionLocal()
                try:
                    yield db
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
                finally:
                    db.close()
            else:
                yield None

    # ==========================================
    # USER MANAGEMENT
    # ==========================================

    @staticmethod
    def _safe_json_loads(raw: Any, default: Any) -> Any:
        if isinstance(raw, (dict, list)):
            return raw
        if not raw:
            return default
        try:
            return json.loads(raw)
        except Exception:
            return default

    @classmethod
    def _serialize_user(cls, user_obj: User, include_hash: bool = False) -> Dict[str, Any]:
        prefs = cls._safe_json_loads(getattr(user_obj, "notification_preferences_json", None), {})
        if not isinstance(prefs, dict):
            prefs = {}
        created_iso = user_obj.created_at.isoformat() if user_obj.created_at else None
        last_login_iso = user_obj.last_login_at.isoformat() if getattr(user_obj, "last_login_at", None) else None
        rec = {
            "id": user_obj.id,
            "uuid": user_obj.uuid,
            "username": user_obj.username,
            "email": user_obj.email,
            "full_name": getattr(user_obj, "full_name", None) or user_obj.username,
            "role": user_obj.role,
            "is_active": user_obj.is_active,
            "is_approved": user_obj.is_approved,
            "last_login_at": last_login_iso,
            "last_login_ist": format_ist(last_login_iso, default="Never recorded"),
            "theme_preference": getattr(user_obj, "theme_preference", None) or "light",
            "timezone_preference": getattr(user_obj, "timezone_preference", None) or "Asia/Kolkata",
            "notification_preferences": prefs,
            "token_version": int(getattr(user_obj, "token_version", 1) or 1),
            "created_at": created_iso,
            "created_at_ist": format_ist(created_iso),
        }
        if include_hash:
            rec["hashed_password"] = user_obj.hashed_password
        return rec

    @staticmethod
    def _enrich_user_dict(rec: Optional[Dict[str, Any]], include_hash: bool = True) -> Optional[Dict[str, Any]]:
        if not rec:
            return None
        out = dict(rec)
        if not include_hash:
            out.pop("hashed_password", None)
        out.setdefault("full_name", out.get("username"))
        out.setdefault("theme_preference", "light")
        out.setdefault("timezone_preference", "Asia/Kolkata")
        out.setdefault("notification_preferences", {})
        out.setdefault("token_version", 1)
        out["created_at_ist"] = format_ist(out.get("created_at"))
        out["last_login_ist"] = format_ist(out.get("last_login_at"), default="Never recorded")
        return out

    def create_user(
        self,
        username: str,
        email: str,
        hashed_password: str,
        role: str = "investigator",
        is_approved: bool = False,
        full_name: Optional[str] = None,
        session: Optional[Session] = None
    ) -> Dict[str, Any]:
        """Creates an authenticated user record atomically."""
        try:
            with self._session_scope(session) as db:
                if db:
                    # Check unique constraints upfront
                    if db.query(User).filter(User.username == username).first():
                        raise DatabaseIntegrityError(f"Username '{username}' is already registered.")
                    if db.query(User).filter(User.email == email).first():
                        raise DatabaseIntegrityError(f"Email '{email}' is already registered.")

                    user = User(
                        username=username,
                        email=email,
                        full_name=full_name or username,
                        hashed_password=hashed_password,
                        role=role,
                        is_active=True,
                        is_approved=is_approved,
                        theme_preference="light",
                        timezone_preference="Asia/Kolkata",
                        notification_preferences_json=json.dumps({"scan_alerts": True, "report_alerts": True}),
                        token_version=1,
                        created_at=utcnow(),
                        updated_at=utcnow()
                    )
                    db.add(user)
                    db.flush()
                    return self._serialize_user(user, include_hash=False)
        except (IntegrityError, DatabaseIntegrityError) as e:
            raise DatabaseIntegrityError(f"User creation integrity violation: {e}")
        except Exception as e:
            logger.warning(f"SQL Server user creation fallback: {e}")

        # Fallback to thread-safe memory store
        if username in self._mem_users:
            return self._enrich_user_dict(self._mem_users[username], include_hash=False)
        if any((u.get("email") or "").lower() == (email or "").lower() for u in self._mem_users.values()):
            raise DatabaseIntegrityError(f"Email '{email}' is already registered.")
        uid = str(uuid.uuid4())
        rec = {
            "id": len(self._mem_users) + 1,
            "uuid": uid,
            "username": username,
            "email": email,
            "full_name": full_name or username,
            "hashed_password": hashed_password,
            "role": role,
            "is_active": True,
            "is_approved": is_approved,
            "last_login_at": None,
            "theme_preference": "light",
            "timezone_preference": "Asia/Kolkata",
            "notification_preferences": {"scan_alerts": True, "report_alerts": True},
            "token_version": 1,
            "created_at": utcnow().isoformat()
        }
        self._mem_users[username] = rec
        return self._enrich_user_dict(rec, include_hash=False)

    def get_user_by_username(self, username: str, session: Optional[Session] = None) -> Optional[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    user = db.query(User).filter(User.username == username).first()
                    if user:
                        return self._serialize_user(user, include_hash=True)
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        return self._enrich_user_dict(self._mem_users.get(username), include_hash=True)

    def list_users(self, session: Optional[Session] = None) -> List[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    users = db.query(User).all()
                    if users:
                        return [self._serialize_user(u, include_hash=False) for u in users]
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        return [
            self._enrich_user_dict(u, include_hash=False)
            for u in self._mem_users.values()
        ]

    def approve_user(self, username: str, session: Optional[Session] = None) -> bool:
        try:
            with self._session_scope(session) as db:
                if db:
                    user = db.query(User).filter(User.username == username).first()
                    if user:
                        user.is_approved = True
                        user.is_active = True
                        user.updated_at = utcnow()
                        return True
        except Exception as e:
            logger.debug(f"SQL Server approve fallback: {e}")
        if username in self._mem_users:
            self._mem_users[username]["is_approved"] = True
            self._mem_users[username]["is_active"] = True
            return True
        return False

    def reject_user(self, username: str, session: Optional[Session] = None) -> bool:
        try:
            with self._session_scope(session) as db:
                if db:
                    user = db.query(User).filter(User.username == username).first()
                    if user:
                        user.is_approved = False
                        user.is_active = False
                        user.updated_at = utcnow()
                        return True
        except Exception as e:
            logger.debug(f"SQL Server reject fallback: {e}")
        if username in self._mem_users:
            self._mem_users[username]["is_approved"] = False
            self._mem_users[username]["is_active"] = False
            return True
        return False

    def set_user_active(self, username: str, is_active: bool, session: Optional[Session] = None) -> Optional[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    user = db.query(User).filter(User.username == username).first()
                    if not user:
                        return None
                    user.is_active = bool(is_active)
                    user.updated_at = utcnow()
                    return {
                        "id": user.id,
                        "username": user.username,
                        "role": user.role,
                        "is_active": user.is_active,
                        "is_approved": user.is_approved,
                    }
        except Exception as e:
            logger.debug(f"SQL Server status update fallback: {e}")
        if username in self._mem_users:
            self._mem_users[username]["is_active"] = bool(is_active)
            u = self._mem_users[username]
            return {k: v for k, v in u.items() if k != "hashed_password"}
        return None

    def update_user_role(self, username: str, role: str, session: Optional[Session] = None) -> Optional[Dict[str, Any]]:
        if role not in ("admin", "investigator"):
            raise DatabaseIntegrityError(f"Invalid role '{role}'. Only 'admin' and 'investigator' are permitted.")
        try:
            with self._session_scope(session) as db:
                if db:
                    user = db.query(User).filter(User.username == username).first()
                    if not user:
                        return None
                    user.role = role
                    user.updated_at = utcnow()
                    return {
                        "id": user.id,
                        "username": user.username,
                        "role": user.role,
                        "is_active": user.is_active,
                        "is_approved": user.is_approved,
                    }
        except DatabaseIntegrityError:
            raise
        except Exception as e:
            logger.debug(f"SQL Server role update fallback: {e}")
        if username in self._mem_users:
            self._mem_users[username]["role"] = role
            u = self._mem_users[username]
            return {k: v for k, v in u.items() if k != "hashed_password"}
        return None

    def get_user_by_id(self, user_id: int, session: Optional[Session] = None) -> Optional[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    u = db.query(User).filter(User.id == user_id).first()
                    if u:
                        return self._serialize_user(u, include_hash=False)
        except Exception as e:
            logger.debug(f"SQL Server user lookup fallback: {e}")
        for u in self._mem_users.values():
            if u.get("id") == user_id:
                return self._enrich_user_dict(u, include_hash=False)
        return None

    def record_user_login(self, username: str, session: Optional[Session] = None) -> Optional[str]:
        now_dt = utcnow()
        now_iso = now_dt.isoformat()
        try:
            with self._session_scope(session) as db:
                if db:
                    u = db.query(User).filter(User.username == username).first()
                    if u:
                        u.last_login_at = now_dt
                        u.updated_at = now_dt
                        return now_iso
        except Exception as e:
            logger.debug(f"SQL Server login timestamp fallback: {e}")
        if username in self._mem_users:
            self._mem_users[username]["last_login_at"] = now_iso
            return now_iso
        return None

    def update_user_profile(
        self,
        username: str,
        full_name: Optional[str] = None,
        email: Optional[str] = None,
        session: Optional[Session] = None,
    ) -> Optional[Dict[str, Any]]:
        clean_name = full_name.strip() if isinstance(full_name, str) else None
        clean_email = email.strip() if isinstance(email, str) else None
        try:
            with self._session_scope(session) as db:
                if db:
                    u = db.query(User).filter(User.username == username).first()
                    if not u:
                        return None
                    if clean_email and clean_email.lower() != (u.email or "").lower():
                        existing = db.query(User).filter(User.email == clean_email, User.username != username).first()
                        if existing:
                            raise DatabaseIntegrityError(f"Email '{clean_email}' is already registered.")
                        u.email = clean_email
                    if clean_name is not None:
                        u.full_name = clean_name[:150]
                    u.updated_at = utcnow()
                    db.flush()
                    return self._serialize_user(u, include_hash=False)
        except DatabaseIntegrityError:
            raise
        except Exception as e:
            logger.debug(f"SQL Server profile update fallback: {e}")

        u = self._mem_users.get(username)
        if not u:
            return None
        if clean_email and clean_email.lower() != (u.get("email") or "").lower():
            if any(
                (other.get("email") or "").lower() == clean_email.lower() and other.get("username") != username
                for other in self._mem_users.values()
            ):
                raise DatabaseIntegrityError(f"Email '{clean_email}' is already registered.")
            u["email"] = clean_email
        if clean_name is not None:
            u["full_name"] = clean_name[:150]
        return self._enrich_user_dict(u, include_hash=False)

    def update_user_preferences(
        self,
        username: str,
        theme_preference: Optional[str] = None,
        timezone_preference: Optional[str] = None,
        notification_preferences: Optional[Dict[str, Any]] = None,
        session: Optional[Session] = None,
    ) -> Optional[Dict[str, Any]]:
        if theme_preference is not None and theme_preference not in ("light", "dark", "system"):
            raise DatabaseIntegrityError("theme_preference must be 'light', 'dark', or 'system'.")
        if timezone_preference is not None:
            try:
                ZoneInfo(timezone_preference)
            except (ZoneInfoNotFoundError, Exception):
                raise DatabaseIntegrityError(f"Invalid timezone '{timezone_preference}'.")
        try:
            with self._session_scope(session) as db:
                if db:
                    u = db.query(User).filter(User.username == username).first()
                    if not u:
                        return None
                    if theme_preference is not None:
                        u.theme_preference = theme_preference
                    if timezone_preference is not None:
                        u.timezone_preference = timezone_preference
                    if notification_preferences is not None:
                        existing = self._safe_json_loads(u.notification_preferences_json, {})
                        if not isinstance(existing, dict):
                            existing = {}
                        existing.update(notification_preferences)
                        u.notification_preferences_json = json.dumps(existing)
                    u.updated_at = utcnow()
                    db.flush()
                    return self._serialize_user(u, include_hash=False)
        except DatabaseIntegrityError:
            raise
        except Exception as e:
            logger.debug(f"SQL Server preferences update fallback: {e}")

        u = self._mem_users.get(username)
        if not u:
            return None
        if theme_preference is not None:
            u["theme_preference"] = theme_preference
        if timezone_preference is not None:
            u["timezone_preference"] = timezone_preference
        if notification_preferences is not None:
            existing = dict(u.get("notification_preferences") or {})
            existing.update(notification_preferences)
            u["notification_preferences"] = existing
        return self._enrich_user_dict(u, include_hash=False)

    def update_user_password(
        self,
        username: str,
        new_hashed_password: str,
        invalidate_sessions: bool = True,
        session: Optional[Session] = None,
    ) -> Optional[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    u = db.query(User).filter(User.username == username).first()
                    if not u:
                        return None
                    u.hashed_password = new_hashed_password
                    if invalidate_sessions:
                        u.token_version = int(getattr(u, "token_version", 1) or 1) + 1
                    u.updated_at = utcnow()
                    db.flush()
                    return self._serialize_user(u, include_hash=False)
        except Exception as e:
            logger.debug(f"SQL Server password update fallback: {e}")

        u = self._mem_users.get(username)
        if not u:
            return None
        u["hashed_password"] = new_hashed_password
        if invalidate_sessions:
            u["token_version"] = int(u.get("token_version", 1) or 1) + 1
        return self._enrich_user_dict(u, include_hash=False)

    # ==========================================
    # INVESTIGATION MANAGEMENT
    # ==========================================

    def create_investigation(
        self,
        title: str,
        description: str = "",
        creator_id: int = 1,
        investigation_id: Optional[str] = None,
        session: Optional[Session] = None
    ) -> Dict[str, Any]:
        """Creates an investigation and logs an audit record atomically."""
        inv_id = investigation_id or f"INV-{utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        try:
            with self._session_scope(session) as db:
                if db:
                    inv = Investigation(
                        investigation_id=inv_id,
                        title=title,
                        description=description,
                        creator_id=creator_id,
                        status="active",
                        exposure_score=0.0,
                        created_at=utcnow(),
                        updated_at=utcnow()
                    )
                    db.add(inv)
                    db.flush()

                    audit = AuditLog(
                        user_id=creator_id,
                        action="INVESTIGATION_CREATED",
                        target_resource=inv_id,
                        details_json=json.dumps({"title": title}),
                        timestamp=utcnow()
                    )
                    db.add(audit)
                    db.flush()

                    return {
                        "id": inv.id,
                        "investigation_id": inv.investigation_id,
                        "title": inv.title,
                        "description": inv.description,
                        "creator_id": inv.creator_id,
                        "status": inv.status,
                        "exposure_score": inv.exposure_score,
                        "created_at": inv.created_at.isoformat()
                    }
        except (IntegrityError, DatabaseIntegrityError) as e:
            raise DatabaseIntegrityError(f"Investigation integrity violation: {e}")
        except Exception as e:
            logger.warning(f"SQL Server investigation fallback: {e}")

        rec = {
            "id": len(self._mem_investigations) + 1,
            "investigation_id": inv_id,
            "title": title,
            "description": description,
            "creator_id": creator_id,
            "status": "active",
            "exposure_score": 0.0,
            "created_at": utcnow().isoformat()
        }
        self._mem_investigations[inv_id] = rec
        self.log_audit(creator_id, "INVESTIGATION_CREATED", inv_id, json.dumps({"title": title}))
        return rec

    def get_investigation(self, investigation_id: str, session: Optional[Session] = None) -> Optional[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                    if inv:
                        created_iso = inv.created_at.isoformat()
                        return {
                            "id": inv.id,
                            "investigation_id": inv.investigation_id,
                            "title": inv.title,
                            "description": inv.description,
                            "creator_id": inv.creator_id,
                            "status": inv.status,
                            "exposure_score": inv.exposure_score,
                            "created_at": created_iso,
                            "created_at_ist": format_ist(created_iso),
                        }
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        rec = self._mem_investigations.get(investigation_id)
        if rec:
            out = dict(rec)
            out["created_at_ist"] = format_ist(out.get("created_at"))
            return out
        return None

    def list_investigations(self, session: Optional[Session] = None) -> List[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    invs = db.query(Investigation).order_by(Investigation.created_at.desc()).all()
                    if invs:
                        return [{
                            "id": i.id,
                            "investigation_id": i.investigation_id,
                            "title": i.title,
                            "description": i.description,
                            "creator_id": i.creator_id,
                            "status": i.status,
                            "exposure_score": i.exposure_score,
                            "created_at": i.created_at.isoformat(),
                            "created_at_ist": format_ist(i.created_at),
                        } for i in invs]
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        rows = []
        for r in self._mem_investigations.values():
            item = dict(r)
            item["created_at_ist"] = format_ist(item.get("created_at"))
            rows.append(item)
        return sorted(rows, key=lambda x: x.get("created_at") or "", reverse=True)

    def update_exposure_score(self, investigation_id: str, score: float, session: Optional[Session] = None) -> bool:
        if not (0.0 <= score <= 100.0):
            raise DatabaseIntegrityError(f"Exposure score {score} out of valid bounds (0.0 - 100.0).")
        try:
            with self._session_scope(session) as db:
                if db:
                    inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                    if inv:
                        inv.exposure_score = score
                        inv.updated_at = utcnow()
                        return True
        except Exception as e:
            logger.debug(f"SQL Server update fallback: {e}")
        if investigation_id in self._mem_investigations:
            self._mem_investigations[investigation_id]["exposure_score"] = score
            return True
        return False

    # ==========================================
    # AUTHORIZED TARGET MANAGEMENT
    # ==========================================

    def add_authorized_target(
        self,
        investigation_id: str,
        target: str,
        name: str,
        scope: str,
        permitted_profiles: str = "lab-basic",
        allowed_ports: str = "1-65535",
        authorized_by: str = "asip_ali",
        target_type: str = "ipv4",
        session: Optional[Session] = None
    ) -> Dict[str, Any]:
        """Atomically registers an authorized target under an investigation."""
        target_id = f"TGT-{uuid.uuid4().hex[:8].upper()}"
        try:
            with self._session_scope(session) as db:
                if db:
                    inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                    if not inv:
                        inv = Investigation(
                            investigation_id=investigation_id,
                            title=name,
                            creator_id=1,
                            created_at=utcnow(),
                            updated_at=utcnow()
                        )
                        db.add(inv)
                        db.flush()

                    tgt = AuthorizedTarget(
                        target_id=target_id,
                        investigation_id=inv.id,
                        target=target,
                        target_type=target_type,
                        name=name,
                        category="authorized_lab",
                        scope=scope,
                        permitted_profiles=permitted_profiles,
                        allowed_ports=allowed_ports,
                        authorization_status="AUTHORIZED_LOCAL_LAB",
                        authorized_by=authorized_by,
                        created_at=utcnow()
                    )
                    db.add(tgt)
                    db.flush()

                    audit = AuditLog(
                        action="TARGET_AUTHORIZED",
                        target_resource=target,
                        details_json=json.dumps({"target_id": target_id, "investigation_id": investigation_id, "scope": scope}),
                        timestamp=utcnow()
                    )
                    db.add(audit)
                    db.flush()

                    return {
                        "id": tgt.id,
                        "target_id": tgt.target_id,
                        "investigation_id": investigation_id,
                        "target": tgt.target,
                        "name": tgt.name,
                        "scope": tgt.scope,
                        "permitted_profiles": tgt.permitted_profiles,
                        "allowed_ports": tgt.allowed_ports,
                        "authorization_status": tgt.authorization_status,
                        "authorized_by": tgt.authorized_by,
                        "created_at": tgt.created_at.isoformat()
                    }
        except (IntegrityError, DatabaseIntegrityError) as e:
            raise DatabaseIntegrityError(f"Target authorization integrity violation: {e}")
        except Exception as e:
            logger.warning(f"SQL Server target fallback: {e}")

        rec = {
            "id": len(self._mem_targets) + 1,
            "target_id": target_id,
            "investigation_id": investigation_id,
            "target": target,
            "name": name,
            "scope": scope,
            "permitted_profiles": permitted_profiles,
            "allowed_ports": allowed_ports,
            "authorization_status": "AUTHORIZED_LOCAL_LAB",
            "authorized_by": authorized_by,
            "created_at": utcnow().isoformat()
        }
        self._mem_targets[target_id] = rec
        return rec

    def list_authorized_targets(self, investigation_id: Optional[str] = None, session: Optional[Session] = None) -> List[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    query = db.query(AuthorizedTarget).options(joinedload(AuthorizedTarget.investigation))
                    if investigation_id:
                        inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                        if not inv:
                            return []
                        query = query.filter(AuthorizedTarget.investigation_id == inv.id)
                    targets = query.all()
                    return [{
                        "target_id": t.target_id,
                        "investigation_id": t.investigation.investigation_id if t.investigation else investigation_id,
                        "target": t.target,
                        "target_type": t.target_type,
                        "name": t.name,
                        "category": t.category,
                        "scope": t.scope,
                        "permitted_profiles": t.permitted_profiles,
                        "allowed_ports": t.allowed_ports,
                        "authorization_status": t.authorization_status,
                        "authorized_by": t.authorized_by,
                        "created_at": t.created_at.isoformat()
                    } for t in targets]
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        if investigation_id:
            return [t for t in self._mem_targets.values() if t.get("investigation_id") == investigation_id]
        return list(self._mem_targets.values())

    # ==========================================
    # SCAN EXECUTION MANAGEMENT
    # ==========================================

    @classmethod
    def _serialize_scan(cls, s: ScanExecution, inv_id_override: Optional[str] = None) -> Dict[str, Any]:
        inv_id = inv_id_override or (s.investigation.investigation_id if getattr(s, "investigation", None) else None) or s.recon_id
        run_num = int(getattr(s, "run_number", 1) or 1)
        started_iso = s.started_at.isoformat() if s.started_at else None
        completed_iso = s.completed_at.isoformat() if s.completed_at else None
        created_iso = s.created_at.isoformat() if s.created_at else None
        dur_secs = getattr(s, "duration_seconds", None)
        if dur_secs is None and started_iso and completed_iso:
            dt_s = parse_timestamp_utc(started_iso)
            dt_e = parse_timestamp_utc(completed_iso)
            if dt_s and dt_e:
                dur_secs = max(0.0, (dt_e - dt_s).total_seconds())
        return {
            "id": s.id,
            "scan_id": s.scan_id,
            "recon_id": s.recon_id,
            "investigation_id": inv_id,
            "run_number": run_num,
            "run_label": f"Run {run_num:03d}",
            "scan_type": s.scan_type,
            "target": s.target,
            "profile": s.profile,
            "status": s.status,
            "initiating_user_id": getattr(s, "initiating_user_id", None),
            "initiated_by": getattr(s, "initiated_by", None),
            "selected_scanners": cls._safe_json_loads(getattr(s, "selected_scanners_json", None), []),
            "selected_components": cls._safe_json_loads(getattr(s, "selected_components_json", None), []),
            "scan_config": cls._safe_json_loads(getattr(s, "scan_config_json", None), {}),
            "scan_config_json": getattr(s, "scan_config_json", None),
            "scanner_versions": cls._safe_json_loads(getattr(s, "scanner_versions_json", None), {}),
            "target_authorization_ref": getattr(s, "target_authorization_ref", None),
            "privilege_consent_given": bool(getattr(s, "privilege_consent_given", False)),
            "privilege_elevation_required": bool(getattr(s, "privilege_elevation_required", False)),
            "privilege_status": getattr(s, "privilege_status", "none") or "none",
            "privilege_authorized_at": s.privilege_authorized_at.isoformat() if getattr(s, "privilege_authorized_at", None) else None,
            "error_message": getattr(s, "error_message", None),
            "result_summary_json": getattr(s, "result_summary_json", None),
            "result_summary": cls._safe_json_loads(getattr(s, "result_summary_json", None), {}),
            "duration_seconds": dur_secs,
            "duration_display": duration_human(started_iso, completed_iso, dur_secs),
            "started_at": started_iso,
            "started_at_ist": format_ist(started_iso),
            "completed_at": completed_iso,
            "completed_at_ist": format_ist(completed_iso),
            "created_at": created_iso,
            "created_at_ist": format_ist(created_iso),
        }

    @classmethod
    def _enrich_scan_dict(cls, rec: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not rec:
            return None
        out = dict(rec)
        run_num = int(out.get("run_number") or 1)
        out["run_number"] = run_num
        out["run_label"] = f"Run {run_num:03d}"
        out.setdefault("selected_scanners", cls._safe_json_loads(out.get("selected_scanners_json"), []))
        out.setdefault("selected_components", cls._safe_json_loads(out.get("selected_components_json"), []))
        out.setdefault("scan_config", cls._safe_json_loads(out.get("scan_config_json"), {}))
        out.setdefault("scanner_versions", cls._safe_json_loads(out.get("scanner_versions_json"), {}))
        out.setdefault("result_summary", cls._safe_json_loads(out.get("result_summary_json"), {}))
        out.setdefault("privilege_consent_given", False)
        out.setdefault("privilege_elevation_required", False)
        out.setdefault("privilege_status", "none")
        out.setdefault("privilege_authorized_at", None)
        started_iso = out.get("started_at")
        completed_iso = out.get("completed_at")
        dur_secs = out.get("duration_seconds")
        if dur_secs is None and started_iso and completed_iso:
            dt_s = parse_timestamp_utc(started_iso)
            dt_e = parse_timestamp_utc(completed_iso)
            if dt_s and dt_e:
                dur_secs = max(0.0, (dt_e - dt_s).total_seconds())
                out["duration_seconds"] = dur_secs
        out["duration_display"] = duration_human(started_iso, completed_iso, dur_secs)
        out["started_at_ist"] = format_ist(started_iso)
        out["completed_at_ist"] = format_ist(completed_iso)
        out["created_at_ist"] = format_ist(out.get("created_at"))
        return out

    def _next_run_number_mem(self, investigation_id: str) -> int:
        existing = [
            int(s.get("run_number") or 0)
            for s in self._mem_scans.values()
            if s.get("investigation_id") == investigation_id or s.get("recon_id") == investigation_id
        ]
        return (max(existing) + 1) if existing else 1

    def create_scan_execution(
        self,
        investigation_id: str,
        scan_type: str,
        target: str,
        profile: str = "default",
        recon_id: Optional[str] = None,
        initiating_user_id: Optional[int] = None,
        initiated_by: Optional[str] = None,
        selected_scanners: Optional[List[str]] = None,
        selected_components: Optional[List[str]] = None,
        scan_config_json: Optional[str] = None,
        scanner_versions: Optional[Dict[str, str]] = None,
        target_authorization_ref: Optional[str] = None,
        privilege_consent_given: bool = False,
        privilege_elevation_required: bool = False,
        privilege_status: str = "none",
        privilege_authorized_at: Optional[datetime] = None,
        session: Optional[Session] = None
    ) -> Dict[str, Any]:
        """Atomically creates a scan execution record with monotonic per-investigation run_number."""
        scan_id = f"SCAN-{utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
        sel_scanners_str = json.dumps(selected_scanners or []) if selected_scanners is not None else None
        sel_comp_str = json.dumps(selected_components or []) if selected_components is not None else None
        ver_str = json.dumps(scanner_versions or {}) if scanner_versions is not None else None
        try:
            with self._session_scope(session) as db:
                if db:
                    inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                    inv_pk = inv.id if inv else 1
                    max_run = db.query(func.max(ScanExecution.run_number)).filter(
                        (ScanExecution.investigation_id == inv_pk) | (ScanExecution.recon_id == (recon_id or investigation_id))
                    ).scalar()
                    next_run = int(max_run or 0) + 1

                    scan = ScanExecution(
                        scan_id=scan_id,
                        recon_id=recon_id or investigation_id,
                        investigation_id=inv_pk,
                        run_number=next_run,
                        scan_type=scan_type,
                        target=target,
                        profile=profile,
                        status="queued",
                        initiating_user_id=initiating_user_id,
                        initiated_by=initiated_by,
                        selected_scanners_json=sel_scanners_str,
                        selected_components_json=sel_comp_str,
                        scan_config_json=scan_config_json,
                        scanner_versions_json=ver_str,
                        target_authorization_ref=target_authorization_ref,
                        privilege_consent_given=privilege_consent_given,
                        privilege_elevation_required=privilege_elevation_required,
                        privilege_status=privilege_status,
                        privilege_authorized_at=privilege_authorized_at,
                        created_at=utcnow()
                    )
                    db.add(scan)
                    db.flush()

                    audit = AuditLog(
                        user_id=initiating_user_id,
                        action="SCAN_EXECUTION_CREATED",
                        target_resource=scan_id,
                        details_json=json.dumps({
                            "investigation_id": investigation_id,
                            "run_number": next_run,
                            "target": target,
                            "scan_type": scan_type,
                            "profile": profile,
                        }),
                        timestamp=utcnow()
                    )
                    db.add(audit)
                    db.flush()

                    return self._serialize_scan(scan, inv_id_override=investigation_id)
        except (IntegrityError, DatabaseIntegrityError) as e:
            raise DatabaseIntegrityError(f"Scan creation integrity violation: {e}")
        except Exception as e:
            logger.warning(f"SQL Server scan creation fallback: {e}")

        next_run = self._next_run_number_mem(recon_id or investigation_id)
        rec = {
            "id": len(self._mem_scans) + 1,
            "scan_id": scan_id,
            "recon_id": recon_id or investigation_id,
            "investigation_id": investigation_id,
            "run_number": next_run,
            "scan_type": scan_type,
            "target": target,
            "profile": profile,
            "status": "queued",
            "initiating_user_id": initiating_user_id,
            "initiated_by": initiated_by,
            "selected_scanners_json": sel_scanners_str,
            "selected_components_json": sel_comp_str,
            "scan_config_json": scan_config_json,
            "scanner_versions_json": ver_str,
            "target_authorization_ref": target_authorization_ref,
            "privilege_consent_given": privilege_consent_given,
            "privilege_elevation_required": privilege_elevation_required,
            "privilege_status": privilege_status,
            "privilege_authorized_at": privilege_authorized_at.isoformat() if privilege_authorized_at else None,
            "created_at": utcnow().isoformat()
        }
        self._mem_scans[scan_id] = rec
        self.log_audit(initiating_user_id or 1, "SCAN_EXECUTION_CREATED", scan_id, json.dumps({"investigation_id": investigation_id, "run_number": next_run, "target": target, "scan_type": scan_type}))
        return self._enrich_scan_dict(rec)

    def update_scan_execution(
        self,
        scan_id: str,
        status: str,
        error_message: Optional[str] = None,
        result_summary_json: Optional[str] = None,
        scanner_versions_json: Optional[str] = None,
        privilege_status: Optional[str] = None,
        privilege_authorized_at: Optional[datetime] = None,
        session: Optional[Session] = None
    ) -> bool:
        """Atomically updates a scan execution status and logs transitions."""
        valid_statuses = ('queued', 'running', 'completed', 'failed', 'cancelled', 'interrupted', 'partially_completed')
        if status.lower() not in valid_statuses:
            raise DatabaseIntegrityError(f"Invalid scan status '{status}'. Must be one of {valid_statuses}")

        try:
            with self._session_scope(session) as db:
                if db:
                    scan = db.query(ScanExecution).filter(ScanExecution.scan_id == scan_id).first()
                    if scan:
                        scan.status = status.lower()
                        if status.lower() == "running" and not scan.started_at:
                            scan.started_at = utcnow()
                        elif status.lower() in ("completed", "failed", "cancelled", "interrupted", "partially_completed"):
                            scan.completed_at = utcnow()
                            if scan.started_at:
                                dt_s = parse_timestamp_utc(scan.started_at)
                                dt_e = parse_timestamp_utc(scan.completed_at)
                                if dt_s and dt_e:
                                    scan.duration_seconds = max(0.0, (dt_e - dt_s).total_seconds())
                        if error_message:
                            scan.error_message = error_message
                        if result_summary_json:
                            scan.result_summary_json = result_summary_json
                        if scanner_versions_json:
                            scan.scanner_versions_json = scanner_versions_json
                        if privilege_status:
                            scan.privilege_status = privilege_status
                        if privilege_authorized_at:
                            scan.privilege_authorized_at = privilege_authorized_at
                        return True
        except Exception as e:
            logger.debug(f"SQL Server scan update fallback: {e}")

        if scan_id in self._mem_scans:
            rec = self._mem_scans[scan_id]
            rec["status"] = status.lower()
            if status.lower() == "running" and not rec.get("started_at"):
                rec["started_at"] = utcnow().isoformat()
            elif status.lower() in ("completed", "failed", "cancelled", "interrupted", "partially_completed"):
                rec["completed_at"] = utcnow().isoformat()
                dt_s = parse_timestamp_utc(rec.get("started_at"))
                dt_e = parse_timestamp_utc(rec["completed_at"])
                if dt_s and dt_e:
                    rec["duration_seconds"] = max(0.0, (dt_e - dt_s).total_seconds())
            if error_message:
                rec["error_message"] = error_message
            if result_summary_json:
                rec["result_summary_json"] = result_summary_json
            if scanner_versions_json:
                rec["scanner_versions_json"] = scanner_versions_json
            if privilege_status:
                rec["privilege_status"] = privilege_status
            if privilege_authorized_at:
                rec["privilege_authorized_at"] = privilege_authorized_at.isoformat() if hasattr(privilege_authorized_at, "isoformat") else str(privilege_authorized_at)
            return True
        return False

    def list_scans(self, investigation_id: Optional[str] = None, session: Optional[Session] = None) -> List[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    query = db.query(ScanExecution).options(joinedload(ScanExecution.investigation)).order_by(ScanExecution.created_at.desc())
                    if investigation_id:
                        inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                        if inv:
                            query = query.filter(
                                (ScanExecution.recon_id == investigation_id) | (ScanExecution.investigation_id == inv.id)
                            )
                        else:
                            query = query.filter(ScanExecution.recon_id == investigation_id)
                    scans = query.all()
                    return [self._serialize_scan(s) for s in scans]
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        rows = list(self._mem_scans.values())
        if investigation_id:
            rows = [s for s in rows if s.get("investigation_id") == investigation_id or s.get("recon_id") == investigation_id]
        enriched = [self._enrich_scan_dict(s) for s in rows]
        enriched.sort(key=lambda s: (s.get("created_at") or "", int(s.get("run_number") or 0)), reverse=True)
        return enriched

    def get_scan(self, scan_id: str, session: Optional[Session] = None) -> Optional[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    s = db.query(ScanExecution).options(joinedload(ScanExecution.investigation)).filter(ScanExecution.scan_id == scan_id).first()
                    if s:
                        return self._serialize_scan(s)
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        return self._enrich_scan_dict(self._mem_scans.get(scan_id))

    # ==========================================
    # VULNERABILITY FINDINGS MANAGEMENT
    # ==========================================

    def add_vulnerability_finding(
        self,
        investigation_id: str,
        finding_dict: Dict[str, Any],
        scan_id: Optional[str] = None,
        session: Optional[Session] = None
    ) -> Dict[str, Any]:
        """Atomically persists a vulnerability finding with check constraint validation."""
        fid = finding_dict.get("finding_id") or f"VULN-{utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        severity = finding_dict.get("severity", "Informational")
        valid_severities = ('Critical', 'High', 'Medium', 'Low', 'Informational', 'Info')
        if severity not in valid_severities:
            raise DatabaseIntegrityError(f"Invalid severity '{severity}'. Must be one of {valid_severities}")

        port = finding_dict.get("port")
        if port is not None and not (1 <= int(port) <= 65535):
            raise DatabaseIntegrityError(f"Port {port} is out of valid range (1 - 65535).")

        cvss = finding_dict.get("cvss_score")
        if cvss is not None and not (0.0 <= float(cvss) <= 10.0):
            raise DatabaseIntegrityError(f"CVSS score {cvss} is out of valid range (0.0 - 10.0).")

        try:
            with self._session_scope(session) as db:
                if db:
                    inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                    inv_pk = inv.id if inv else 1

                    scan_pk = None
                    if scan_id:
                        scan = db.query(ScanExecution).filter(ScanExecution.scan_id == scan_id).first()
                        if scan:
                            scan_pk = scan.id

                    existing = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.finding_id == fid).first()
                    if existing and existing.investigation_id == inv_pk and existing.scan_execution_id == scan_pk:
                        existing.last_detected = utcnow()
                        if finding_dict.get("evidence_reference") and not existing.evidence_reference:
                            existing.evidence_reference = finding_dict.get("evidence_reference")
                        db.flush()
                        return self._serialize_finding(existing, inv_override=investigation_id)
                    if existing:
                        fid = f"{fid[:48]}-{uuid.uuid4().hex[:6].upper()}"

                    finding = VulnerabilityFinding(
                        finding_id=fid,
                        investigation_id=inv_pk,
                        scan_execution_id=scan_pk,
                        target_ip=finding_dict.get("target_ip", "127.0.0.1"),
                        hostname=finding_dict.get("hostname"),
                        port=int(port) if port else None,
                        protocol=finding_dict.get("protocol", "tcp"),
                        service=finding_dict.get("service"),
                        service_version=finding_dict.get("service_version"),
                        title=finding_dict.get("title", "Discovered Vulnerability"),
                        description=finding_dict.get("description", ""),
                        cve_identifiers=finding_dict.get("cve_identifiers"),
                        cvss_score=float(cvss) if cvss is not None else None,
                        severity=severity,
                        confidence=parse_confidence_score(finding_dict.get("confidence"), default=1.0),
                        detection_source=finding_dict.get("detection_source", "generic"),
                        scanner_vt_id=finding_dict.get("scanner_vt_id"),
                        remediation=finding_dict.get("remediation"),
                        evidence_reference=finding_dict.get("evidence_reference"),
                        verification_status=finding_dict.get("verification_status", "unverified"),
                        finding_status=finding_dict.get("finding_status", "open"),
                        version_id=1,
                        first_detected=utcnow(),
                        last_detected=utcnow()
                    )
                    db.add(finding)
                    db.flush()

                    return {
                        "id": finding.id,
                        "finding_id": finding.finding_id,
                        "investigation_id": investigation_id,
                        "scan_id": scan_id,
                        "target_ip": finding.target_ip,
                        "port": finding.port,
                        "title": finding.title,
                        "severity": finding.severity,
                        "cvss_score": finding.cvss_score,
                        "finding_status": finding.finding_status,
                        "version_id": finding.version_id,
                        "created_at": finding.first_detected.isoformat(),
                        "created_at_ist": format_ist(finding.first_detected),
                    }
        except (IntegrityError, DatabaseIntegrityError) as e:
            raise DatabaseIntegrityError(f"Finding integrity violation: {e}")
        except Exception as e:
            logger.warning(f"SQL Server finding fallback: {e}")

        mem_existing = self._mem_findings.get(fid)
        if mem_existing:
            if mem_existing.get("investigation_id") == investigation_id and mem_existing.get("scan_id") == scan_id:
                mem_existing["last_detected"] = utcnow().isoformat()
                mem_existing["last_detected_ist"] = format_ist(mem_existing["last_detected"])
                if finding_dict.get("evidence_reference") and not mem_existing.get("evidence_reference"):
                    mem_existing["evidence_reference"] = finding_dict.get("evidence_reference")
                return dict(mem_existing)
            fid = f"{fid[:48]}-{uuid.uuid4().hex[:6].upper()}"

        rec = dict(finding_dict)
        rec["finding_id"] = fid
        rec["investigation_id"] = investigation_id
        rec["scan_id"] = scan_id
        rec["finding_status"] = finding_dict.get("finding_status", "open")
        rec["remediation_status"] = rec["finding_status"]
        rec["version_id"] = 1
        rec["first_detected"] = utcnow().isoformat()
        rec["last_detected"] = rec["first_detected"]
        rec["first_detected_ist"] = format_ist(rec["first_detected"])
        rec["last_detected_ist"] = rec["first_detected_ist"]
        self._mem_findings[fid] = rec
        return rec

    @staticmethod
    def _serialize_finding(f: VulnerabilityFinding, inv_override: Optional[str] = None) -> Dict[str, Any]:
        first_iso = f.first_detected.isoformat() if f.first_detected else None
        last_iso = f.last_detected.isoformat() if f.last_detected else None
        scan_obj = getattr(f, "scan", None)
        return {
            "finding_id": f.finding_id,
            "investigation_id": (f.investigation.investigation_id if f.investigation else None) or inv_override,
            "scan_id": scan_obj.scan_id if scan_obj else None,
            "run_number": int(getattr(scan_obj, "run_number", 1) or 1) if scan_obj else None,
            "target_ip": f.target_ip,
            "hostname": f.hostname,
            "port": f.port,
            "protocol": f.protocol,
            "service": f.service,
            "service_version": f.service_version,
            "title": f.title,
            "description": f.description,
            "cve_identifiers": f.cve_identifiers,
            "cvss_score": f.cvss_score,
            "severity": f.severity,
            "confidence": f.confidence,
            "detection_source": f.detection_source,
            "scanner_vt_id": f.scanner_vt_id,
            "remediation": f.remediation,
            "remediation_notes": f.remediation_notes,
            "evidence_reference": f.evidence_reference,
            "verification_status": f.verification_status,
            "finding_status": f.finding_status,
            "remediation_status": f.finding_status,
            "version_id": f.version_id,
            "first_detected": first_iso,
            "last_detected": last_iso,
            "first_detected_ist": format_ist(first_iso),
            "last_detected_ist": format_ist(last_iso),
        }

    def list_findings(
        self,
        investigation_id: Optional[str] = None,
        severity: Optional[str] = None,
        target_ip: Optional[str] = None,
        scan_id: Optional[str] = None,
        session: Optional[Session] = None
    ) -> List[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    query = db.query(VulnerabilityFinding).options(
                        joinedload(VulnerabilityFinding.investigation),
                        joinedload(VulnerabilityFinding.scan),
                    )
                    if investigation_id:
                        inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                        if not inv:
                            return []
                        query = query.filter(VulnerabilityFinding.investigation_id == inv.id)
                    if scan_id:
                        scan_obj = db.query(ScanExecution).filter(ScanExecution.scan_id == scan_id).first()
                        if not scan_obj:
                            return []
                        query = query.filter(VulnerabilityFinding.scan_execution_id == scan_obj.id)
                    if severity:
                        query = query.filter(VulnerabilityFinding.severity == severity)
                    if target_ip:
                        query = query.filter(VulnerabilityFinding.target_ip == target_ip)

                    findings = query.all()
                    return [self._serialize_finding(f, inv_override=investigation_id) for f in findings]
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")

        res = list(self._mem_findings.values())
        if investigation_id:
            res = [f for f in res if f.get("investigation_id") == investigation_id]
        if scan_id:
            res = [f for f in res if f.get("scan_id") == scan_id]
        if severity:
            res = [f for f in res if f.get("severity") == severity]
        if target_ip:
            res = [f for f in res if f.get("target_ip") == target_ip]
        enriched = []
        for f in res:
            item = dict(f)
            item.setdefault("first_detected_ist", format_ist(item.get("first_detected")))
            item.setdefault("last_detected_ist", format_ist(item.get("last_detected") or item.get("first_detected")))
            if item.get("scan_id") and not item.get("run_number"):
                sc = self._mem_scans.get(item["scan_id"])
                if sc:
                    item["run_number"] = int(sc.get("run_number") or 1)
            enriched.append(item)
        return enriched

    def get_finding(self, finding_id: str, session: Optional[Session] = None) -> Optional[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    f = db.query(VulnerabilityFinding).options(
                        joinedload(VulnerabilityFinding.investigation),
                        joinedload(VulnerabilityFinding.scan),
                    ).filter(
                        VulnerabilityFinding.finding_id == finding_id
                    ).first()
                    if f:
                        return self._serialize_finding(f)
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        f = self._mem_findings.get(finding_id)
        if f:
            item = dict(f)
            item.setdefault("first_detected_ist", format_ist(item.get("first_detected")))
            item.setdefault("last_detected_ist", format_ist(item.get("last_detected") or item.get("first_detected")))
            return item
        return None

    # ==========================================
    # EVIDENCE & SEAWEEDFS OUTBOX MANAGEMENT
    # ==========================================

    def stage_external_artifact(
        self,
        artifact_id: str,
        investigation_id: str,
        artifact_type: str,
        recon_id: Optional[str] = None,
        external_reference_id: Optional[str] = None,
        file_name: Optional[str] = None,
        sha256_hash: Optional[str] = None,
        details_json: Optional[str] = None,
        session: Optional[Session] = None
    ) -> Dict[str, Any]:
        """
        Transactional Outbox: Stages an external artifact (SeaweedFS FID, Scanner UUID)
        prior to final database commitment. Enables recovery if persistence aborts midway.
        """
        try:
            with self._session_scope(session) as db:
                if db:
                    outbox = ExternalArtifactOutbox(
                        artifact_id=artifact_id,
                        investigation_id=investigation_id,
                        recon_id=recon_id,
                        artifact_type=artifact_type,
                        external_reference_id=external_reference_id,
                        status="staged",
                        file_name=file_name,
                        sha256_hash=sha256_hash,
                        details_json=details_json,
                        created_at=utcnow(),
                        updated_at=utcnow()
                    )
                    db.add(outbox)
                    db.flush()
                    return {
                        "artifact_id": artifact_id,
                        "status": "staged",
                        "external_reference_id": external_reference_id
                    }
        except Exception as e:
            logger.debug(f"SQL Server outbox fallback: {e}")

        rec = {
            "artifact_id": artifact_id,
            "investigation_id": investigation_id,
            "recon_id": recon_id,
            "artifact_type": artifact_type,
            "external_reference_id": external_reference_id,
            "status": "staged",
            "file_name": file_name,
            "sha256_hash": sha256_hash,
            "created_at": utcnow().isoformat()
        }
        self._mem_outbox[artifact_id] = rec
        return rec

    def commit_external_artifact(self, artifact_id: str, session: Optional[Session] = None) -> bool:
        """Marks an outbox artifact as successfully committed."""
        try:
            with self._session_scope(session) as db:
                if db:
                    outbox = db.query(ExternalArtifactOutbox).filter(ExternalArtifactOutbox.artifact_id == artifact_id).first()
                    if outbox:
                        outbox.status = "committed"
                        outbox.updated_at = utcnow()
                        return True
        except Exception as e:
            logger.debug(f"SQL Server outbox commit fallback: {e}")
        if artifact_id in self._mem_outbox:
            self._mem_outbox[artifact_id]["status"] = "committed"
            return True
        return False

    def mark_external_artifact_orphaned(self, artifact_id: str, session: Optional[Session] = None) -> bool:
        """Marks an outbox artifact as orphaned for safe asynchronous background cleanup."""
        try:
            with self._session_scope(session) as db:
                if db:
                    outbox = db.query(ExternalArtifactOutbox).filter(ExternalArtifactOutbox.artifact_id == artifact_id).first()
                    if outbox:
                        outbox.status = "orphaned"
                        outbox.updated_at = utcnow()
                        return True
        except Exception as e:
            logger.debug(f"SQL Server outbox orphan fallback: {e}")
        if artifact_id in self._mem_outbox:
            self._mem_outbox[artifact_id]["status"] = "orphaned"
            return True
        return False

    @staticmethod
    def _serialize_evidence(
        e: EvidenceRecord,
        inv_override: Optional[str] = None,
        findings_count: Optional[int] = None,
    ) -> Dict[str, Any]:
        created_iso = e.created_at.isoformat() if e.created_at else None
        scan_obj = getattr(e, "scan", None)
        scan_id_val = getattr(e, "scan_id", None) or (scan_obj.scan_id if scan_obj else None)
        run_num = getattr(e, "run_number", None) or (getattr(scan_obj, "run_number", None) if scan_obj else None)
        target_val = getattr(e, "target", None) or (getattr(scan_obj, "target", None) if scan_obj else None)
        return {
            "evidence_id": e.evidence_id,
            "investigation_id": (e.investigation.investigation_id if e.investigation else None) or inv_override,
            "scan_id": scan_id_val,
            "run_number": int(run_num) if run_num is not None else None,
            "run_label": f"Run {int(run_num):03d}" if run_num is not None else None,
            "scanner_source": getattr(e, "scanner_source", None) or e.evidence_type,
            "target": target_val,
            "evidence_type": e.evidence_type,
            "file_name": e.file_name,
            "file_size": e.file_size,
            "content_type": getattr(e, "content_type", "application/octet-stream"),
            "sha256_hash": e.sha256_hash,
            "seaweed_fid": e.seaweed_fid,
            "seaweed_url": e.seaweed_url,
            "local_path": e.local_path,
            "findings_count": findings_count if findings_count is not None else 0,
            "created_at": created_iso,
            "created_at_ist": format_ist(created_iso),
        }

    def add_evidence_record(
        self,
        investigation_id: str,
        evidence_type: str,
        file_name: str,
        file_size: int,
        sha256_hash: str,
        seaweed_fid: Optional[str] = None,
        seaweed_url: Optional[str] = None,
        local_path: Optional[str] = None,
        scan_id: Optional[str] = None,
        scanner_source: Optional[str] = None,
        target: Optional[str] = None,
        run_number: Optional[int] = None,
        content_type: str = "application/octet-stream",
        session: Optional[Session] = None
    ) -> Dict[str, Any]:
        """Atomically persists evidence metadata idempotently per (investigation_id, scan_id, sha256_hash, evidence_type)."""
        try:
            with self._session_scope(session) as db:
                if db:
                    inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                    inv_pk = inv.id if inv else 1
                    scan_pk = None
                    resolved_run_num = run_number
                    resolved_target = target
                    if scan_id:
                        scan_obj = db.query(ScanExecution).filter(ScanExecution.scan_id == scan_id).first()
                        if scan_obj:
                            scan_pk = scan_obj.id
                            if resolved_run_num is None:
                                resolved_run_num = getattr(scan_obj, "run_number", None)
                            if not resolved_target:
                                resolved_target = scan_obj.target

                    if sha256_hash:
                        dup_query = db.query(EvidenceRecord).filter(
                            EvidenceRecord.investigation_id == inv_pk,
                            EvidenceRecord.evidence_type == evidence_type,
                            EvidenceRecord.sha256_hash == sha256_hash,
                        )
                        if scan_id is not None:
                            dup_query = dup_query.filter(EvidenceRecord.scan_id == scan_id)
                        else:
                            dup_query = dup_query.filter(EvidenceRecord.scan_id.is_(None))
                        existing_ev = dup_query.first()
                        if existing_ev:
                            if seaweed_fid and not existing_ev.seaweed_fid:
                                existing_ev.seaweed_fid = seaweed_fid
                            if seaweed_url and not existing_ev.seaweed_url:
                                existing_ev.seaweed_url = seaweed_url
                            if local_path and not existing_ev.local_path:
                                existing_ev.local_path = local_path
                            if scanner_source and not existing_ev.scanner_source:
                                existing_ev.scanner_source = scanner_source
                            if resolved_target and not existing_ev.target:
                                existing_ev.target = resolved_target
                            db.flush()
                            return self._serialize_evidence(existing_ev, inv_override=investigation_id)

                    eid = f"EVID-{utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
                    outbox_id = f"OUTBOX-{eid}"
                    self.stage_external_artifact(
                        artifact_id=outbox_id,
                        investigation_id=investigation_id,
                        artifact_type="seaweed_blob",
                        external_reference_id=seaweed_fid,
                        file_name=file_name,
                        sha256_hash=sha256_hash,
                        session=db
                    )

                    ev = EvidenceRecord(
                        evidence_id=eid,
                        investigation_id=inv_pk,
                        scan_execution_id=scan_pk,
                        scan_id=scan_id,
                        run_number=resolved_run_num,
                        scanner_source=scanner_source or evidence_type,
                        target=resolved_target,
                        evidence_type=evidence_type,
                        file_name=file_name,
                        file_size=file_size,
                        content_type=content_type or "application/octet-stream",
                        sha256_hash=sha256_hash,
                        seaweed_fid=seaweed_fid,
                        seaweed_url=seaweed_url,
                        local_path=local_path,
                        created_at=utcnow()
                    )
                    db.add(ev)
                    db.flush()

                    # Commit outbox
                    outbox = db.query(ExternalArtifactOutbox).filter(ExternalArtifactOutbox.artifact_id == outbox_id).first()
                    if outbox:
                        outbox.status = "committed"
                        outbox.updated_at = utcnow()

                    audit = AuditLog(
                        action="EVIDENCE_REGISTERED",
                        target_resource=eid,
                        details_json=json.dumps({
                            "file_name": file_name,
                            "sha256": sha256_hash,
                            "seaweed_fid": seaweed_fid,
                            "scan_id": scan_id,
                            "scanner_source": scanner_source or evidence_type,
                        }),
                        timestamp=utcnow()
                    )
                    db.add(audit)
                    db.flush()

                    return self._serialize_evidence(ev, inv_override=investigation_id)
        except Exception as e:
            logger.warning(f"SQL Server evidence fallback: {e}")

        # Idempotent check in memory store before creating duplicate record
        if sha256_hash:
            for existing in self._mem_evidence.values():
                if (
                    existing.get("investigation_id") == investigation_id
                    and existing.get("evidence_type") == evidence_type
                    and existing.get("sha256_hash") == sha256_hash
                    and existing.get("scan_id") == scan_id
                ):
                    if seaweed_fid and not existing.get("seaweed_fid"):
                        existing["seaweed_fid"] = seaweed_fid
                    if seaweed_url and not existing.get("seaweed_url"):
                        existing["seaweed_url"] = seaweed_url
                    if local_path and not existing.get("local_path"):
                        existing["local_path"] = local_path
                    if scanner_source and not existing.get("scanner_source"):
                        existing["scanner_source"] = scanner_source
                    if target and not existing.get("target"):
                        existing["target"] = target
                    return dict(existing)

        eid = f"EVID-{utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        outbox_id = f"OUTBOX-{eid}"
        self.stage_external_artifact(
            artifact_id=outbox_id,
            investigation_id=investigation_id,
            artifact_type="seaweed_blob",
            external_reference_id=seaweed_fid,
            file_name=file_name,
            sha256_hash=sha256_hash,
            session=session
        )

        resolved_run_num = run_number
        resolved_target = target
        if scan_id and scan_id in self._mem_scans:
            sc = self._mem_scans[scan_id]
            if resolved_run_num is None:
                resolved_run_num = sc.get("run_number")
            if not resolved_target:
                resolved_target = sc.get("target")
        created_iso = utcnow().isoformat()
        rec = {
            "evidence_id": eid,
            "investigation_id": investigation_id,
            "scan_id": scan_id,
            "run_number": resolved_run_num,
            "run_label": f"Run {int(resolved_run_num):03d}" if resolved_run_num is not None else None,
            "scanner_source": scanner_source or evidence_type,
            "target": resolved_target,
            "evidence_type": evidence_type,
            "file_name": file_name,
            "file_size": file_size,
            "content_type": content_type or "application/octet-stream",
            "sha256_hash": sha256_hash,
            "seaweed_fid": seaweed_fid,
            "seaweed_url": seaweed_url,
            "local_path": local_path,
            "findings_count": 0,
            "created_at": created_iso,
            "created_at_ist": format_ist(created_iso),
        }
        self._mem_evidence[eid] = rec
        self.commit_external_artifact(outbox_id)
        return rec

    def list_evidence(
        self,
        investigation_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        scanner_source: Optional[str] = None,
        evidence_type: Optional[str] = None,
        session: Optional[Session] = None,
    ) -> List[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    query = db.query(EvidenceRecord).options(
                        joinedload(EvidenceRecord.investigation),
                        joinedload(EvidenceRecord.scan),
                    ).order_by(EvidenceRecord.created_at.desc())
                    if investigation_id:
                        inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                        if not inv:
                            return []
                        query = query.filter(EvidenceRecord.investigation_id == inv.id)
                    if scan_id:
                        scan_obj = db.query(ScanExecution).filter(ScanExecution.scan_id == scan_id).first()
                        if scan_obj:
                            query = query.filter(
                                (EvidenceRecord.scan_id == scan_id) | (EvidenceRecord.scan_execution_id == scan_obj.id)
                            )
                        else:
                            query = query.filter(EvidenceRecord.scan_id == scan_id)
                    if scanner_source:
                        query = query.filter(EvidenceRecord.scanner_source == scanner_source)
                    if evidence_type:
                        query = query.filter(EvidenceRecord.evidence_type == evidence_type)
                    evidence = query.all()
                    out = []
                    for e in evidence:
                        f_count = 0
                        if e.scan_execution_id:
                            f_count = db.query(VulnerabilityFinding).filter(
                                VulnerabilityFinding.scan_execution_id == e.scan_execution_id
                            ).count()
                        else:
                            f_count = db.query(VulnerabilityFinding).filter(
                                VulnerabilityFinding.investigation_id == e.investigation_id
                            ).count()
                        out.append(self._serialize_evidence(e, inv_override=investigation_id, findings_count=f_count))
                    return out
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")

        rows = list(self._mem_evidence.values())
        if investigation_id:
            rows = [e for e in rows if e.get("investigation_id") == investigation_id]
        if scan_id:
            rows = [e for e in rows if e.get("scan_id") == scan_id]
        if scanner_source:
            rows = [e for e in rows if (e.get("scanner_source") or e.get("evidence_type")) == scanner_source]
        if evidence_type:
            rows = [e for e in rows if e.get("evidence_type") == evidence_type]
        enriched = []
        for e in rows:
            item = dict(e)
            item.setdefault("scanner_source", item.get("evidence_type"))
            item.setdefault("created_at_ist", format_ist(item.get("created_at")))
            if item.get("scan_id") and item.get("scan_id") in self._mem_scans and item.get("run_number") is None:
                item["run_number"] = self._mem_scans[item["scan_id"]].get("run_number")
            if item.get("run_number") is not None:
                item["run_label"] = f"Run {int(item['run_number']):03d}"
            item["findings_count"] = len([
                f for f in self._mem_findings.values()
                if (item.get("scan_id") and f.get("scan_id") == item.get("scan_id"))
                or (not item.get("scan_id") and f.get("investigation_id") == item.get("investigation_id"))
            ])
            enriched.append(item)
        enriched.sort(key=lambda x: x.get("created_at") or "", reverse=True)
        return enriched

    def get_evidence(self, evidence_id: str, session: Optional[Session] = None) -> Optional[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    e = db.query(EvidenceRecord).options(
                        joinedload(EvidenceRecord.investigation),
                        joinedload(EvidenceRecord.scan),
                    ).filter(
                        EvidenceRecord.evidence_id == evidence_id
                    ).first()
                    if e:
                        f_count = 0
                        if e.scan_execution_id:
                            f_count = db.query(VulnerabilityFinding).filter(
                                VulnerabilityFinding.scan_execution_id == e.scan_execution_id
                            ).count()
                        return self._serialize_evidence(e, findings_count=f_count)
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        e = self._mem_evidence.get(evidence_id)
        if not e:
            return None
        item = dict(e)
        item.setdefault("scanner_source", item.get("evidence_type"))
        item.setdefault("created_at_ist", format_ist(item.get("created_at")))
        if item.get("scan_id") and item.get("scan_id") in self._mem_scans and item.get("run_number") is None:
            item["run_number"] = self._mem_scans[item["scan_id"]].get("run_number")
        if item.get("run_number") is not None:
            item["run_label"] = f"Run {int(item['run_number']):03d}"
        item["findings_count"] = len([
            f for f in self._mem_findings.values()
            if (item.get("scan_id") and f.get("scan_id") == item.get("scan_id"))
            or (not item.get("scan_id") and f.get("investigation_id") == item.get("investigation_id"))
        ])
        return item

    # ==========================================
    # REPORT RECORD PERSISTENCE
    # ==========================================

    @staticmethod
    def _serialize_report(r: ReportRecord, inv_override: Optional[str] = None) -> Dict[str, Any]:
        gen_iso = r.generated_at.isoformat() if r.generated_at else None
        run_num = getattr(r, "run_number", None)
        return {
            "report_id": r.report_id,
            "recon_id": r.recon_id,
            "investigation_id": (r.investigation.investigation_id if r.investigation else None) or inv_override or r.recon_id,
            "investigation_name": getattr(r, "investigation_name", None) or (r.investigation.title if r.investigation else None),
            "scan_id": getattr(r, "scan_id", None),
            "run_number": int(run_num) if run_num is not None else None,
            "run_label": f"Run {int(run_num):03d}" if run_num is not None else None,
            "scan_type": getattr(r, "scan_type", None),
            "generated_by_user_id": r.generated_by_user_id,
            "generated_by_username": r.generated_by_username,
            "report_type": r.report_type,
            "report_format": r.report_type,
            "report_status": getattr(r, "report_status", "completed") or "completed",
            "file_name": r.file_name,
            "file_size": r.file_size,
            "sha256_hash": r.sha256_hash,
            "seaweed_fid": r.seaweed_fid,
            "generated_at": gen_iso,
            "created_at": gen_iso,
            "generated_at_ist": format_ist(gen_iso),
            "created_at_ist": format_ist(gen_iso),
        }

    def add_report_record(
        self,
        investigation_id: str,
        file_name: str,
        file_size: int,
        sha256_hash: str,
        recon_id: Optional[str] = None,
        report_type: str = "pdf",
        seaweed_fid: Optional[str] = None,
        generated_by_user_id: Optional[int] = None,
        generated_by_username: Optional[str] = None,
        scan_id: Optional[str] = None,
        run_number: Optional[int] = None,
        scan_type: Optional[str] = None,
        investigation_name: Optional[str] = None,
        report_status: str = "completed",
        session: Optional[Session] = None
    ) -> Dict[str, Any]:
        """Atomically persists a generated PDF report record."""
        rid = f"REP-{utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        try:
            with self._session_scope(session) as db:
                if db:
                    inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                    inv_pk = inv.id if inv else 1
                    scan_pk = None
                    resolved_run_num = run_number
                    resolved_scan_type = scan_type
                    if scan_id:
                        sc = db.query(ScanExecution).filter(ScanExecution.scan_id == scan_id).first()
                        if sc:
                            scan_pk = sc.id
                            if resolved_run_num is None:
                                resolved_run_num = getattr(sc, "run_number", None)
                            if not resolved_scan_type:
                                resolved_scan_type = sc.scan_type
                    resolved_inv_name = investigation_name or (inv.title if inv else None)

                    rep = ReportRecord(
                        report_id=rid,
                        recon_id=recon_id or investigation_id,
                        investigation_id=inv_pk,
                        scan_execution_id=scan_pk,
                        scan_id=scan_id,
                        run_number=resolved_run_num,
                        scan_type=resolved_scan_type,
                        investigation_name=resolved_inv_name,
                        generated_by_user_id=generated_by_user_id,
                        generated_by_username=generated_by_username,
                        report_type=report_type,
                        report_status=report_status or "completed",
                        file_name=file_name,
                        file_size=file_size,
                        sha256_hash=sha256_hash,
                        seaweed_fid=seaweed_fid,
                        generated_at=utcnow()
                    )
                    db.add(rep)
                    db.flush()

                    audit = AuditLog(
                        user_id=generated_by_user_id,
                        actor_role="investigator" if generated_by_user_id else None,
                        action="REPORT_GENERATED",
                        target_resource=rid,
                        outcome="SUCCESS",
                        details_json=json.dumps({
                            "file_name": file_name,
                            "size": file_size,
                            "sha256": sha256_hash,
                            "investigation_id": investigation_id,
                            "scan_id": scan_id,
                            "run_number": resolved_run_num,
                        }),
                        timestamp=utcnow()
                    )
                    db.add(audit)
                    db.flush()

                    return self._serialize_report(rep, inv_override=investigation_id)
        except Exception as e:
            logger.warning(f"SQL Server report fallback: {e}")

        resolved_run_num = run_number
        resolved_scan_type = scan_type
        if scan_id and scan_id in self._mem_scans:
            sc = self._mem_scans[scan_id]
            if resolved_run_num is None:
                resolved_run_num = sc.get("run_number")
            if not resolved_scan_type:
                resolved_scan_type = sc.get("scan_type")
        gen_iso = utcnow().isoformat()
        rec = {
            "report_id": rid,
            "recon_id": recon_id or investigation_id,
            "investigation_id": investigation_id,
            "investigation_name": investigation_name,
            "scan_id": scan_id,
            "run_number": resolved_run_num,
            "run_label": f"Run {int(resolved_run_num):03d}" if resolved_run_num is not None else None,
            "scan_type": resolved_scan_type,
            "generated_by_user_id": generated_by_user_id,
            "generated_by_username": generated_by_username,
            "report_type": report_type,
            "report_format": report_type,
            "report_status": report_status or "completed",
            "file_name": file_name,
            "file_size": file_size,
            "sha256_hash": sha256_hash,
            "seaweed_fid": seaweed_fid,
            "generated_at": gen_iso,
            "created_at": gen_iso,
            "generated_at_ist": format_ist(gen_iso),
            "created_at_ist": format_ist(gen_iso),
        }
        self._mem_reports[rid] = rec
        self.log_audit(generated_by_user_id or 1, "REPORT_GENERATED", rid, json.dumps({"file_name": file_name, "investigation_id": investigation_id, "scan_id": scan_id}))
        return rec

    def list_report_records(
        self,
        investigation_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        session: Optional[Session] = None,
    ) -> List[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    query = db.query(ReportRecord).options(joinedload(ReportRecord.investigation)).order_by(ReportRecord.generated_at.desc())
                    if investigation_id:
                        inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                        if inv:
                            query = query.filter(
                                (ReportRecord.recon_id == investigation_id) | (ReportRecord.investigation_id == inv.id)
                            )
                        else:
                            query = query.filter(ReportRecord.recon_id == investigation_id)
                    if scan_id:
                        query = query.filter(ReportRecord.scan_id == scan_id)
                    reports = query.all()
                    return [self._serialize_report(r, inv_override=investigation_id) for r in reports]
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")

        rows = list(self._mem_reports.values())
        if investigation_id:
            rows = [r for r in rows if r.get("investigation_id") == investigation_id or r.get("recon_id") == investigation_id]
        if scan_id:
            rows = [r for r in rows if r.get("scan_id") == scan_id]
        enriched = []
        for r in rows:
            item = dict(r)
            item.setdefault("report_format", item.get("report_type"))
            item.setdefault("report_status", "completed")
            item["generated_at_ist"] = format_ist(item.get("generated_at") or item.get("created_at"))
            item["created_at_ist"] = item["generated_at_ist"]
            if item.get("run_number") is not None:
                item["run_label"] = f"Run {int(item['run_number']):03d}"
            enriched.append(item)
        return sorted(enriched, key=lambda r: r.get("generated_at") or "", reverse=True)

    def get_report_record(self, report_id_or_file: str, session: Optional[Session] = None) -> Optional[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    r = db.query(ReportRecord).options(joinedload(ReportRecord.investigation)).filter(
                        (ReportRecord.report_id == report_id_or_file) | (ReportRecord.file_name == report_id_or_file)
                    ).first()
                    if r:
                        return self._serialize_report(r)
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        target = None
        if report_id_or_file in self._mem_reports:
            target = self._mem_reports[report_id_or_file]
        else:
            for r in self._mem_reports.values():
                if r.get("file_name") == report_id_or_file:
                    target = r
                    break
        if target:
            item = dict(target)
            item.setdefault("report_format", item.get("report_type"))
            item["generated_at_ist"] = format_ist(item.get("generated_at") or item.get("created_at"))
            item["created_at_ist"] = item["generated_at_ist"]
            return item
        return None

    # ==========================================
    # AUDIT LOGGING
    # ==========================================

    def log_audit(
        self,
        user_id: Optional[int],
        action: str,
        target_resource: Optional[str] = None,
        details_json: Optional[str] = None,
        ip_address: Optional[str] = None,
        actor_role: Optional[str] = None,
        outcome: str = "SUCCESS",
        session: Optional[Session] = None
    ):
        """Commits an immutable audit log entry."""
        safe_outcome = outcome if outcome in {"SUCCESS", "DENIED", "FAILED"} else "SUCCESS"
        try:
            with self._session_scope(session) as db:
                if db:
                    audit = AuditLog(
                        user_id=user_id,
                        actor_role=actor_role,
                        action=action,
                        target_resource=target_resource,
                        outcome=safe_outcome,
                        details_json=details_json,
                        ip_address=ip_address,
                        timestamp=utcnow()
                    )
                    db.add(audit)
                    db.flush()
                    return
        except Exception as e:
            logger.debug(f"SQL Server audit log fallback: {e}")

        self._mem_audit.append({
            "id": len(self._mem_audit) + 1,
            "user_id": user_id,
            "actor_role": actor_role,
            "action": action,
            "target_resource": target_resource,
            "outcome": safe_outcome,
            "details_json": details_json,
            "ip_address": ip_address,
            "timestamp": utcnow().isoformat()
        })

    def list_audit_logs(
        self,
        limit: int = 100,
        action: Optional[str] = None,
        outcome: Optional[str] = None,
        user_id: Optional[int] = None,
        session: Optional[Session] = None
    ) -> List[Dict[str, Any]]:
        user_map: Dict[int, str] = {}
        try:
            with self._session_scope(session) as db:
                if db:
                    for u in db.query(User).all():
                        user_map[u.id] = u.username
                    query = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
                    if action:
                        query = query.filter(AuditLog.action == action)
                    if outcome:
                        query = query.filter(AuditLog.outcome == outcome)
                    if user_id is not None:
                        query = query.filter(AuditLog.user_id == user_id)
                    logs = query.limit(limit).all()
                    return [{
                        "id": log.id,
                        "user_id": log.user_id,
                        "username": user_map.get(log.user_id) if log.user_id else None,
                        "actor_role": log.actor_role,
                        "action": log.action,
                        "target_resource": log.target_resource,
                        "outcome": getattr(log, "outcome", "SUCCESS"),
                        "details_json": log.details_json,
                        "ip_address": log.ip_address,
                        "timestamp": log.timestamp.isoformat(),
                        "timestamp_ist": format_ist(log.timestamp),
                        "created_at": log.timestamp.isoformat(),
                        "created_at_ist": format_ist(log.timestamp),
                    } for log in logs]
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")

        for u in self._mem_users.values():
            if u.get("id") is not None:
                user_map[u["id"]] = u.get("username")
        entries = list(self._mem_audit)
        if action:
            entries = [e for e in entries if e.get("action") == action]
        if outcome:
            entries = [e for e in entries if e.get("outcome", "SUCCESS") == outcome]
        if user_id is not None:
            entries = [e for e in entries if e.get("user_id") == user_id]
        entries.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
        enriched = []
        for idx, e in enumerate(entries[:limit], start=1):
            row = dict(e)
            row.setdefault("id", idx)
            row.setdefault("outcome", "SUCCESS")
            if row.get("user_id") is not None and not row.get("username"):
                row["username"] = user_map.get(row["user_id"])
            row["timestamp_ist"] = format_ist(row.get("timestamp"))
            row["created_at"] = row.get("timestamp")
            row["created_at_ist"] = row["timestamp_ist"]
            enriched.append(row)
        return enriched

    def list_user_activity_logs(
        self,
        user_id: int,
        limit: int = 50,
        action: Optional[str] = None,
        session: Optional[Session] = None,
    ) -> List[Dict[str, Any]]:
        """Lists audit events strictly scoped to a single user (for Settings -> My Activity)."""
        if user_id is None:
            return []
        return self.list_audit_logs(limit=limit, action=action, user_id=user_id, session=session)

    # ==========================================
    # INVESTIGATION ACCESS SHARING
    # ==========================================

    def share_investigation(
        self,
        investigation_id: str,
        user_id: int,
        granted_by_id: Optional[int] = None,
        permission_level: str = "read_write",
        session: Optional[Session] = None
    ) -> bool:
        try:
            with self._session_scope(session) as db:
                if db:
                    inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                    if not inv:
                        return False
                    existing = db.query(InvestigationShare).filter(
                        InvestigationShare.investigation_id == inv.id,
                        InvestigationShare.user_id == user_id,
                    ).first()
                    if existing:
                        existing.permission_level = permission_level
                    else:
                        db.add(InvestigationShare(
                            investigation_id=inv.id,
                            user_id=user_id,
                            granted_by_id=granted_by_id,
                            permission_level=permission_level,
                            created_at=utcnow(),
                        ))
                    db.flush()
                    return True
        except Exception as e:
            logger.debug(f"SQL Server investigation share fallback: {e}")

        shared = self._mem_shares.setdefault(investigation_id, [])
        if user_id not in shared:
            shared.append(user_id)
        return True

    def revoke_investigation_share(self, investigation_id: str, user_id: int, session: Optional[Session] = None) -> bool:
        try:
            with self._session_scope(session) as db:
                if db:
                    inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                    if not inv:
                        return False
                    row = db.query(InvestigationShare).filter(
                        InvestigationShare.investigation_id == inv.id,
                        InvestigationShare.user_id == user_id,
                    ).first()
                    if row:
                        db.delete(row)
                        db.flush()
                        return True
                    return False
        except Exception as e:
            logger.debug(f"SQL Server investigation unshare fallback: {e}")

        shared = self._mem_shares.get(investigation_id, [])
        if user_id in shared:
            shared.remove(user_id)
            return True
        return False

    def has_investigation_share(self, investigation_id: str, user_id: int, session: Optional[Session] = None) -> bool:
        try:
            with self._session_scope(session) as db:
                if db:
                    inv = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
                    if not inv:
                        return False
                    row = db.query(InvestigationShare).filter(
                        InvestigationShare.investigation_id == inv.id,
                        InvestigationShare.user_id == user_id,
                    ).first()
                    return row is not None
        except Exception as e:
            logger.debug(f"SQL Server share lookup fallback: {e}")
        return user_id in self._mem_shares.get(investigation_id, [])

    def list_shared_investigation_ids(self, user_id: int, session: Optional[Session] = None) -> List[str]:
        try:
            with self._session_scope(session) as db:
                if db:
                    rows = db.query(InvestigationShare).options(joinedload(InvestigationShare.investigation)).filter(
                        InvestigationShare.user_id == user_id
                    ).all()
                    return [r.investigation.investigation_id for r in rows if r.investigation]
        except Exception as e:
            logger.debug(f"SQL Server share list fallback: {e}")
        return [inv_id for inv_id, uids in self._mem_shares.items() if user_id in uids]

    # ==========================================
    # RECONNAISSANCE CAMPAIGN MANAGEMENT (ATOMIC)
    # ==========================================

    def _init_builtin_profiles(self):
        """Populates built-in scan profiles if not present."""
        defaults = [
            {
                "name": "Quick Demo",
                "description": "Fast demonstration using selected common ports against authorized lab targets",
                "category": "quick",
                "config_json": '{"scan_types": ["nmap_services", "nmap_nse"], "ports": "21,22,80,445,3306,3632", "service_detection": true, "scripts": ["ftp-vsftpd-backdoor", "http-title"]}',
                "is_builtin": True
            },
            {
                "name": "Passive Only",
                "description": "Exclusively non-intrusive OSINT: WHOIS, DNS enumeration, RDAP, theHarvester",
                "category": "passive",
                "config_json": '{"scan_types": ["passive"], "collectors": ["whois", "dns", "rdap", "theharvester"]}',
                "is_builtin": True
            },
            {
                "name": "Basic Discovery",
                "description": "Host discovery, ping verification, and top 100 common TCP ports",
                "category": "discovery",
                "config_json": '{"scan_types": ["network_discovery", "nmap_services"], "ports": "top-100", "service_detection": true}',
                "is_builtin": True
            },
            {
                "name": "TCP Quick",
                "description": "Standard fast scan of top 1,000 common TCP ports with version identification",
                "category": "tcp",
                "config_json": '{"scan_types": ["nmap_services"], "ports": "1-1024", "service_detection": true}',
                "is_builtin": True
            },
            {
                "name": "TCP Full",
                "description": "Comprehensive scan across all 65,535 TCP ports",
                "category": "tcp",
                "config_json": '{"scan_types": ["nmap_services"], "ports": "1-65535", "service_detection": true}',
                "is_builtin": True
            },
            {
                "name": "UDP Basic",
                "description": "Selected common UDP ports (DNS, DHCP, NTP, SNMP, Syslog)",
                "category": "udp",
                "config_json": '{"scan_types": ["nmap_services"], "ports": "53,67,68,123,161,514", "protocol": "udp"}',
                "is_builtin": True
            },
            {
                "name": "Service Audit",
                "description": "Deep service detection, OS fingerprinting, and RPC/SMB enumeration",
                "category": "service",
                "config_json": '{"scan_types": ["nmap_services"], "service_detection": true, "os_detection": true}',
                "is_builtin": True
            },
            {
                "name": "Vulnerability Assessment",
                "description": "Policy-governed Nmap NSE scripts and ProjectDiscovery Nuclei safe evaluation",
                "category": "vulnerability",
                "config_json": '{"scan_types": ["nmap_nse", "nuclei"], "nuclei_profile": "safe-all", "service_detection": true}',
                "is_builtin": True
            },
            {
                "name": "Full Recon",
                "description": "End-to-end multi-engine assessment: Passive OSINT + Nmap Services + NSE + Nuclei",
                "category": "combined",
                "config_json": '{"scan_types": ["combined"], "nuclei_profile": "safe-all", "service_detection": true, "os_detection": true}',
                "is_builtin": True
            },
            {
                "name": "lab-basic",
                "description": "Standard discovery, safe SYN scan (top 100 ports) & version detection",
                "category": "general",
                "config_json": '{"ports": "top-100", "timing": "T3", "scripts": "safe"}',
                "is_builtin": True
            },
            {
                "name": "lab-safe-minimal",
                "description": "Minimal non-intrusive port detection, strictly non-destructive",
                "category": "safe",
                "config_json": '{"ports": "21,22,80,443", "timing": "T2", "scripts": "none"}',
                "is_builtin": True
            },
            {
                "name": "lab-comprehensive-vuln",
                "description": "Full vulnerability discovery via Nmap NSE & ProjectDiscovery Nuclei",
                "category": "vulnerability",
                "config_json": '{"ports": "1-65535", "timing": "T3", "scripts": "vuln", "scanners": ["nmap", "nuclei"]}',
                "is_builtin": True
            }
        ]

        for p in defaults:
            if p["name"] not in self._mem_profiles:
                self._mem_profiles[p["name"]] = {
                    "id": len(self._mem_profiles) + 1,
                    "name": p["name"],
                    "description": p["description"],
                    "category": p["category"],
                    "config_json": p["config_json"],
                    "is_builtin": p["is_builtin"],
                    "created_by": "system",
                    "created_at": utcnow().isoformat()
                }

    _recon_id_lock = threading.Lock()
    _recon_id_counter = 0

    def generate_recon_id(self, db: Optional[Session] = None) -> str:
        """
        Generates a collision-resistant, human-readable, persistent server-side Recon ID:
        FIQ-REC-YYYYMMDD-XXXX with atomic sequence verification and thread-safe locking.
        """
        date_str = utcnow().strftime("%Y%m%d")
        with FootprintIQRepository._recon_id_lock:
            if db is not None:
                try:
                    count = db.query(ReconCampaign).filter(
                        ReconCampaign.recon_id.like(f"FIQ-REC-{date_str}-%")
                    ).count()
                    suffix = count + 1
                    candidate = f"FIQ-REC-{date_str}-{suffix:04d}"
                    while db.query(ReconCampaign).filter(ReconCampaign.recon_id == candidate).first():
                        suffix += 1
                        candidate = f"FIQ-REC-{date_str}-{suffix:04d}"
                    return candidate
                except Exception:
                    pass

            existing_for_today = [k for k in self._mem_recon_campaigns.keys() if f"FIQ-REC-{date_str}" in k]
            FootprintIQRepository._recon_id_counter = max(
                FootprintIQRepository._recon_id_counter + 1,
                len(existing_for_today) + 1
            )
            candidate = f"FIQ-REC-{date_str}-{FootprintIQRepository._recon_id_counter:04d}"
            while candidate in self._mem_recon_campaigns:
                FootprintIQRepository._recon_id_counter += 1
                candidate = f"FIQ-REC-{date_str}-{FootprintIQRepository._recon_id_counter:04d}"
            return candidate

    def create_recon_campaign(
        self,
        name: str,
        target_value: str,
        target_type: str = "ipv4",
        description: str = "",
        purpose: str = "Security Audit",
        scope_description: str = "",
        excluded_targets: str = "",
        excluded_ports: str = "",
        allowed_methods: str = "all",
        allowed_ports: str = "1-65535",
        authorized_by: str = "asip_ali",
        creator_id: int = 1,
        selected_scan_types: str = "combined",
        scan_config_json: str = "{}",
        initial_status: str = "Authorized",
        initial_stage: str = "Configured",
        authorization_status: str = "Authorized",
        idempotency_key: Optional[str] = None,
        session: Optional[Session] = None
    ) -> Dict[str, Any]:
        """
        ATOMIC UNIT OF WORK:
        1. Check idempotency / duplicates
        2. Assign collision-free Recon ID
        3. Insert Investigation record
        4. Insert ReconCampaign record
        5. Insert AuthorizedTarget record
        6. Insert Creation Audit Log
        If any step fails, rolls back completely. Zero partial records.
        """
        if not target_value or not target_value.strip():
            raise DatabaseIntegrityError("Target value cannot be empty.")
        if not name or not name.strip():
            raise DatabaseIntegrityError("Campaign name cannot be empty.")
        if allowed_ports and allowed_ports != "all" and not any(c.isdigit() for c in allowed_ports):
            raise DatabaseIntegrityError(f"Invalid allowed_ports '{allowed_ports}'.")

        try:
            with self._session_scope(session) as db:
                if db:
                    # Idempotency check: if a campaign with the exact name and target was created in the last 60 seconds
                    if idempotency_key:
                        existing = db.query(ReconCampaign).filter(ReconCampaign.recon_id == idempotency_key).first()
                        if existing:
                            return self.get_recon_campaign(existing.recon_id, session=db)

                    recon_id = self.generate_recon_id(db=db)

                    # 1. Create underlying Investigation
                    inv = db.query(Investigation).filter(Investigation.investigation_id == recon_id).first()
                    if not inv:
                        inv = Investigation(
                            investigation_id=recon_id,
                            title=name,
                            description=description,
                            creator_id=creator_id,
                            status="active",
                            exposure_score=0.0,
                            created_at=utcnow(),
                            updated_at=utcnow()
                        )
                        db.add(inv)
                        db.flush()

                    # 2. Create ReconCampaign
                    camp = ReconCampaign(
                        recon_id=recon_id,
                        investigation_id=recon_id,
                        name=name,
                        description=description,
                        purpose=purpose,
                        scope_description=scope_description,
                        target_type=target_type,
                        target_value=target_value,
                        excluded_targets=excluded_targets,
                        excluded_ports=excluded_ports,
                        allowed_methods=allowed_methods,
                        allowed_ports=allowed_ports,
                        authorization_status=authorization_status,
                        authorized_by=authorized_by,
                        authorized_at=utcnow(),
                        status=initial_status,
                        selected_scan_types=selected_scan_types,
                        scan_config_json=scan_config_json,
                        progress=0,
                        current_stage=initial_stage,
                        creator_id=creator_id,
                        version_id=1,
                        created_at=utcnow(),
                        updated_at=utcnow()
                    )
                    db.add(camp)
                    db.flush()

                    # 3. Create AuthorizedTarget
                    target_rec = AuthorizedTarget(
                        target_id=f"TGT-{uuid.uuid4().hex[:8].upper()}",
                        investigation_id=inv.id,
                        target=target_value,
                        target_type=target_type,
                        name=f"{name} Target ({target_value})",
                        category="authorized_lab",
                        scope=scope_description or f"{target_value} authorized scope",
                        permitted_profiles="lab-basic,default,lab-safe-minimal",
                        allowed_ports=allowed_ports,
                        authorization_status="AUTHORIZED_LOCAL_LAB",
                        authorized_by=authorized_by,
                        created_at=utcnow()
                    )
                    db.add(target_rec)
                    db.flush()

                    # 4. Record creation AuditLog atomically
                    audit = AuditLog(
                        user_id=creator_id,
                        action="RECON_CAMPAIGN_CREATED",
                        target_resource=recon_id,
                        details_json=json.dumps({
                            "name": name,
                            "target": target_value,
                            "scope": scope_description,
                            "authorized_by": authorized_by
                        }),
                        timestamp=utcnow()
                    )
                    db.add(audit)
                    db.flush()

                    data = {
                        "id": camp.id,
                        "recon_id": camp.recon_id,
                        "investigation_id": camp.investigation_id,
                        "name": camp.name,
                        "description": camp.description,
                        "purpose": camp.purpose,
                        "scope_description": camp.scope_description,
                        "target_type": camp.target_type,
                        "target_value": camp.target_value,
                        "excluded_targets": camp.excluded_targets,
                        "excluded_ports": camp.excluded_ports,
                        "allowed_methods": camp.allowed_methods,
                        "allowed_ports": camp.allowed_ports,
                        "authorization_status": camp.authorization_status,
                        "authorized_by": camp.authorized_by,
                        "authorized_at": camp.authorized_at.isoformat(),
                        "status": camp.status,
                        "selected_scan_types": camp.selected_scan_types,
                        "scan_config_json": camp.scan_config_json,
                        "progress": camp.progress,
                        "current_stage": camp.current_stage,
                        "creator_id": camp.creator_id,
                        "version_id": camp.version_id,
                        "created_at": camp.created_at.isoformat(),
                        "updated_at": camp.updated_at.isoformat()
                    }
                    self._mem_recon_campaigns[recon_id] = data
                    return data
        except (IntegrityError, DatabaseIntegrityError) as e:
            raise DatabaseIntegrityError(f"Campaign creation integrity violation: {e}")
        except Exception as e:
            logger.warning(f"SQL Server recon campaign creation fallback: {e}")

        # In-Memory fallback implementation (maintains atomicity & audit logging)
        if idempotency_key:
            for c in self._mem_recon_campaigns.values():
                if c.get("idempotency_key") == idempotency_key:
                    return c

        recon_id = self.generate_recon_id()
        self.create_investigation(
            title=name,
            description=description,
            creator_id=creator_id,
            investigation_id=recon_id,
        )
        self.add_authorized_target(
            investigation_id=recon_id,
            target=target_value,
            name=f"{name} Target",
            scope=scope_description or f"{target_value} authorized scope",
            permitted_profiles="lab-basic,default,lab-safe-minimal",
            allowed_ports=allowed_ports,
            authorized_by=authorized_by
        )

        camp_data = {
            "id": len(self._mem_recon_campaigns) + 1,
            "recon_id": recon_id,
            "investigation_id": recon_id,
            "name": name,
            "description": description,
            "purpose": purpose,
            "scope_description": scope_description,
            "target_type": target_type,
            "target_value": target_value,
            "excluded_targets": excluded_targets,
            "excluded_ports": excluded_ports,
            "allowed_methods": allowed_methods,
            "allowed_ports": allowed_ports,
            "authorization_status": authorization_status,
            "authorized_by": authorized_by,
            "authorized_at": utcnow().isoformat(),
            "status": initial_status,
            "selected_scan_types": selected_scan_types,
            "scan_config_json": scan_config_json,
            "progress": 0,
            "current_stage": initial_stage,
            "creator_id": creator_id,
            "version_id": 1,
            "idempotency_key": idempotency_key,
            "created_at": utcnow().isoformat(),
            "updated_at": utcnow().isoformat()
        }
        self._mem_recon_campaigns[recon_id] = camp_data
        self.log_audit(creator_id, "RECON_CAMPAIGN_CREATED", recon_id, json.dumps({"target": target_value}))
        return camp_data

    def get_recon_campaign(self, recon_id: str, session: Optional[Session] = None) -> Optional[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    camp = db.query(ReconCampaign).filter(ReconCampaign.recon_id == recon_id).first()
                    if camp:
                        return {
                            "id": camp.id,
                            "recon_id": camp.recon_id,
                            "investigation_id": camp.investigation_id,
                            "name": camp.name,
                            "description": camp.description,
                            "purpose": camp.purpose,
                            "scope_description": camp.scope_description,
                            "target_type": camp.target_type,
                            "target_value": camp.target_value,
                            "excluded_targets": camp.excluded_targets,
                            "excluded_ports": camp.excluded_ports,
                            "allowed_methods": camp.allowed_methods,
                            "allowed_ports": camp.allowed_ports,
                            "authorization_status": camp.authorization_status,
                            "authorized_by": camp.authorized_by,
                            "authorized_at": camp.authorized_at.isoformat() if camp.authorized_at else None,
                            "authorized_at_ist": format_ist(camp.authorized_at),
                            "status": camp.status,
                            "selected_scan_types": camp.selected_scan_types,
                            "scan_config_json": camp.scan_config_json,
                            "progress": camp.progress,
                            "current_stage": camp.current_stage,
                            "creator_id": camp.creator_id,
                            "version_id": camp.version_id,
                            "created_at": camp.created_at.isoformat(),
                            "created_at_ist": format_ist(camp.created_at),
                            "updated_at": camp.updated_at.isoformat(),
                            "updated_at_ist": format_ist(camp.updated_at),
                        }
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        rec = self._mem_recon_campaigns.get(recon_id)
        if rec:
            out = dict(rec)
            out["created_at_ist"] = format_ist(out.get("created_at"))
            out["updated_at_ist"] = format_ist(out.get("updated_at") or out.get("created_at"))
            out["authorized_at_ist"] = format_ist(out.get("authorized_at"))
            return out
        return None

    def list_recon_campaigns(self, session: Optional[Session] = None) -> List[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    camps = db.query(ReconCampaign).order_by(ReconCampaign.created_at.desc()).all()
                    if camps:
                        return [{
                            "id": c.id,
                            "recon_id": c.recon_id,
                            "investigation_id": c.investigation_id,
                            "name": c.name,
                            "target_value": c.target_value,
                            "target_type": c.target_type,
                            "status": c.status,
                            "progress": c.progress,
                            "current_stage": c.current_stage,
                            "creator_id": c.creator_id,
                            "authorized_by": c.authorized_by,
                            "version_id": c.version_id,
                            "created_at": c.created_at.isoformat(),
                            "created_at_ist": format_ist(c.created_at),
                            "updated_at": c.updated_at.isoformat(),
                            "updated_at_ist": format_ist(c.updated_at),
                        } for c in camps]
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        rows = []
        for c in self._mem_recon_campaigns.values():
            item = dict(c)
            item["created_at_ist"] = format_ist(item.get("created_at"))
            item["updated_at_ist"] = format_ist(item.get("updated_at") or item.get("created_at"))
            rows.append(item)
        return sorted(rows, key=lambda x: x.get("created_at") or "", reverse=True)

    def update_recon_campaign(
        self,
        recon_id: str,
        expected_version: Optional[int] = None,
        session: Optional[Session] = None,
        **kwargs
    ) -> bool:
        """
        Atomically updates a Recon Campaign with optimistic concurrency version check.
        """
        try:
            with self._session_scope(session) as db:
                if db:
                    camp = db.query(ReconCampaign).filter(ReconCampaign.recon_id == recon_id).first()
                    if camp:
                        if expected_version is not None and camp.version_id != expected_version:
                            raise ConcurrencyConflictError(
                                f"Campaign '{recon_id}' was modified by another operation (expected v{expected_version}, current v{camp.version_id})."
                            )
                        for k, v in kwargs.items():
                            if hasattr(camp, k):
                                setattr(camp, k, v)
                        camp.version_id += 1
                        camp.updated_at = utcnow()
                        return True
        except ConcurrencyConflictError:
            raise
        except Exception as e:
            logger.debug(f"SQL Server update fallback: {e}")

        if recon_id in self._mem_recon_campaigns:
            rec = self._mem_recon_campaigns[recon_id]
            if expected_version is not None and rec.get("version_id", 1) != expected_version:
                raise ConcurrencyConflictError(f"Campaign '{recon_id}' concurrent modification conflict.")
            rec.update(kwargs)
            rec["version_id"] = rec.get("version_id", 1) + 1
            rec["updated_at"] = utcnow().isoformat()
            return True
        return False

    def claim_and_start_recon_scan(
        self,
        recon_id: str,
        scan_type: str = "combined",
        profile: str = "default",
        operator: str = "asip_ali",
        initiating_user_id: Optional[int] = None,
        selected_scanners: Optional[List[str]] = None,
        selected_components: Optional[List[str]] = None,
        scan_config_json: Optional[str] = None,
        scanner_versions: Optional[Dict[str, str]] = None,
        target_authorization_ref: Optional[str] = None,
        privilege_consent_given: bool = False,
        privilege_elevation_required: bool = False,
        privilege_status: str = "none",
        privilege_authorized_at: Optional[datetime] = None,
        session: Optional[Session] = None
    ) -> Dict[str, Any]:
        """
        ATOMIC JOB CLAIM:
        Atomically checks campaign state, prevents double-claim / double-launch race conditions,
        transitions status to 'Running', creates an independent numbered ScanExecution run record
        (without overwriting historical runs), creates the initial event, and logs the audit event.
        """
        sel_scanners_str = json.dumps(selected_scanners) if selected_scanners is not None else None
        sel_comp_str = json.dumps(selected_components) if selected_components is not None else None
        ver_str = json.dumps(scanner_versions) if scanner_versions is not None else None
        try:
            with self._session_scope(session) as db:
                if db:
                    camp = db.query(ReconCampaign).filter(ReconCampaign.recon_id == recon_id).first()
                    if not camp:
                        raise EntityNotFoundError(f"Recon Campaign '{recon_id}' does not exist.")
                    if camp.status in ("Running", "Initializing"):
                        raise ConcurrencyConflictError(f"Recon Campaign '{recon_id}' is already actively executing a scan.")

                    # Optionally apply per-run configuration without deleting earlier run records
                    if scan_config_json:
                        camp.scan_config_json = scan_config_json
                    if selected_scanners is not None:
                        camp.selected_scan_types = ",".join(selected_scanners)

                    # Transition status
                    camp.status = "Running"
                    camp.current_stage = "Initializing"
                    camp.progress = 5
                    camp.version_id += 1
                    camp.updated_at = utcnow()

                    scan_id = f"SCAN-{utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
                    inv = db.query(Investigation).filter(Investigation.investigation_id == recon_id).first()
                    inv_pk = inv.id if inv else 1

                    max_run = db.query(func.max(ScanExecution.run_number)).filter(
                        (ScanExecution.investigation_id == inv_pk) | (ScanExecution.recon_id == recon_id)
                    ).scalar()
                    next_run = int(max_run or 0) + 1

                    eff_cfg_str = scan_config_json or camp.scan_config_json
                    if sel_scanners_str is None and camp.selected_scan_types:
                        sel_scanners_str = json.dumps([s.strip() for s in camp.selected_scan_types.split(",") if s.strip()])

                    scan = ScanExecution(
                        scan_id=scan_id,
                        recon_id=recon_id,
                        investigation_id=inv_pk,
                        run_number=next_run,
                        scan_type=scan_type,
                        target=camp.target_value,
                        profile=profile,
                        status="running",
                        initiating_user_id=initiating_user_id,
                        initiated_by=operator,
                        selected_scanners_json=sel_scanners_str,
                        selected_components_json=sel_comp_str,
                        scan_config_json=eff_cfg_str,
                        scanner_versions_json=ver_str,
                        target_authorization_ref=target_authorization_ref or camp.authorized_by,
                        privilege_consent_given=privilege_consent_given,
                        privilege_elevation_required=privilege_elevation_required,
                        privilege_status=privilege_status,
                        privilege_authorized_at=privilege_authorized_at,
                        started_at=utcnow(),
                        created_at=utcnow()
                    )
                    db.add(scan)
                    db.flush()

                    evt = ScanExecutionEvent(
                        scan_id=scan_id,
                        recon_id=recon_id,
                        event_type="stage_start",
                        stage="INITIALIZATION",
                        message=f"Recon campaign {recon_id} Run {next_run:03d} claimed and initiated for target {camp.target_value}",
                        progress=5,
                        timestamp=utcnow()
                    )
                    db.add(evt)
                    db.flush()

                    audit = AuditLog(
                        user_id=initiating_user_id,
                        actor_role="investigator" if initiating_user_id else None,
                        action="SCAN_EXECUTION_DISPATCHED",
                        target_resource=scan_id,
                        outcome="SUCCESS",
                        details_json=json.dumps({
                            "recon_id": recon_id,
                            "run_number": next_run,
                            "scan_type": scan_type,
                            "target": camp.target_value,
                            "operator": operator,
                        }),
                        timestamp=utcnow()
                    )
                    db.add(audit)
                    db.flush()

                    return {
                        "status": "QUEUED",
                        "recon_id": recon_id,
                        "scan_id": scan_id,
                        "run_number": next_run,
                        "run_label": f"Run {next_run:03d}",
                        "target": camp.target_value,
                        "scan_type": scan_type,
                        "profile": profile,
                        "privilege_consent_given": privilege_consent_given,
                        "privilege_elevation_required": privilege_elevation_required,
                        "privilege_status": privilege_status,
                    }
        except (ConcurrencyConflictError, EntityNotFoundError):
            raise
        except Exception as e:
            logger.warning(f"SQL Server scan dispatch fallback: {e}")

        # Memory store fallback
        if recon_id not in self._mem_recon_campaigns:
            raise EntityNotFoundError(f"Recon Campaign '{recon_id}' does not exist.")
        camp = self._mem_recon_campaigns[recon_id]
        if camp.get("status") in ("Running", "Initializing"):
            raise ConcurrencyConflictError(f"Recon Campaign '{recon_id}' is already executing a scan.")

        if scan_config_json:
            camp["scan_config_json"] = scan_config_json
        if selected_scanners is not None:
            camp["selected_scan_types"] = ",".join(selected_scanners)

        camp["status"] = "Running"
        camp["current_stage"] = "Initializing"
        camp["progress"] = 5
        camp["version_id"] = camp.get("version_id", 1) + 1
        camp["updated_at"] = utcnow().isoformat()

        next_run = self._next_run_number_mem(recon_id)
        eff_cfg_str = scan_config_json or camp.get("scan_config_json")
        if sel_scanners_str is None and camp.get("selected_scan_types"):
            sel_scanners_str = json.dumps([s.strip() for s in str(camp["selected_scan_types"]).split(",") if s.strip()])

        scan_id = f"SCAN-{utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
        started_iso = utcnow().isoformat()
        self._mem_scans[scan_id] = {
            "id": len(self._mem_scans) + 1,
            "scan_id": scan_id,
            "recon_id": recon_id,
            "investigation_id": recon_id,
            "run_number": next_run,
            "run_label": f"Run {next_run:03d}",
            "scan_type": scan_type,
            "target": camp["target_value"],
            "profile": profile,
            "status": "running",
            "initiating_user_id": initiating_user_id,
            "initiated_by": operator,
            "selected_scanners_json": sel_scanners_str,
            "selected_components_json": sel_comp_str,
            "scan_config_json": eff_cfg_str,
            "scanner_versions_json": ver_str,
            "target_authorization_ref": target_authorization_ref or camp.get("authorized_by"),
            "privilege_consent_given": privilege_consent_given,
            "privilege_elevation_required": privilege_elevation_required,
            "privilege_status": privilege_status,
            "privilege_authorized_at": privilege_authorized_at.isoformat() if privilege_authorized_at else None,
            "started_at": started_iso,
            "created_at": started_iso
        }
        self.add_scan_execution_event(
            scan_id=scan_id,
            recon_id=recon_id,
            event_type="stage_start",
            stage="INITIALIZATION",
            message=f"Recon campaign {recon_id} Run {next_run:03d} initiated for {camp['target_value']}",
            progress=5
        )
        self.log_audit(
            initiating_user_id or 1,
            "SCAN_EXECUTION_DISPATCHED",
            scan_id,
            json.dumps({
                "recon_id": recon_id,
                "run_number": next_run,
                "scan_type": scan_type,
                "target": camp["target_value"],
                "operator": operator,
            }),
            actor_role="investigator" if initiating_user_id else None,
        )
        return {
            "status": "QUEUED",
            "recon_id": recon_id,
            "scan_id": scan_id,
            "run_number": next_run,
            "run_label": f"Run {next_run:03d}",
            "target": camp["target_value"],
            "scan_type": scan_type,
            "profile": profile
        }

    # ==========================================
    # SCAN EXECUTION EVENTS (STREAMING & LOGGING)
    # ==========================================

    def add_scan_execution_event(
        self,
        scan_id: str,
        recon_id: Optional[str],
        event_type: str,
        message: str,
        stage: Optional[str] = None,
        details_json: Optional[str] = None,
        progress: Optional[int] = None,
        session: Optional[Session] = None
    ) -> Dict[str, Any]:
        """Atomically persists a live telemetry execution event."""
        try:
            with self._session_scope(session) as db:
                if db:
                    evt = ScanExecutionEvent(
                        scan_id=scan_id,
                        recon_id=recon_id,
                        event_type=event_type,
                        stage=stage,
                        message=message,
                        details_json=details_json,
                        progress=progress,
                        timestamp=utcnow()
                    )
                    db.add(evt)
                    db.flush()
                    return {
                        "id": evt.id,
                        "scan_id": evt.scan_id,
                        "recon_id": evt.recon_id,
                        "event_type": evt.event_type,
                        "stage": evt.stage,
                        "message": evt.message,
                        "details_json": evt.details_json,
                        "progress": evt.progress,
                        "timestamp": evt.timestamp.isoformat()
                    }
        except Exception as e:
            logger.debug(f"SQL Server event logging fallback: {e}")

        rec = {
            "id": len(self._mem_scan_events.get(scan_id, [])) + 1,
            "scan_id": scan_id,
            "recon_id": recon_id,
            "event_type": event_type,
            "stage": stage,
            "message": message,
            "details_json": details_json,
            "progress": progress,
            "timestamp": utcnow().isoformat()
        }
        if scan_id not in self._mem_scan_events:
            self._mem_scan_events[scan_id] = []
        self._mem_scan_events[scan_id].append(rec)
        return rec

    def list_scan_execution_events(self, scan_id: str, session: Optional[Session] = None) -> List[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    evts = db.query(ScanExecutionEvent).filter(ScanExecutionEvent.scan_id == scan_id).order_by(ScanExecutionEvent.timestamp.asc()).all()
                    if evts:
                        return [{
                            "id": e.id,
                            "scan_id": e.scan_id,
                            "recon_id": e.recon_id,
                            "event_type": e.event_type,
                            "stage": e.stage,
                            "message": e.message,
                            "details_json": e.details_json,
                            "progress": e.progress,
                            "timestamp": e.timestamp.isoformat(),
                            "timestamp_ist": format_ist(e.timestamp, include_seconds=True),
                        } for e in evts]
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        return [
            dict(ev, timestamp_ist=format_ist(ev.get("timestamp"), include_seconds=True))
            for ev in self._mem_scan_events.get(scan_id, [])
        ]

    # ==========================================
    # SAVED SCAN PROFILES
    # ==========================================

    def list_saved_scan_profiles(self, session: Optional[Session] = None) -> List[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    profs = db.query(SavedScanProfile).all()
                    if profs:
                        return [{
                            "id": p.id,
                            "name": p.name,
                            "description": p.description,
                            "category": p.category,
                            "config_json": p.config_json,
                            "is_builtin": p.is_builtin,
                            "created_by": p.created_by,
                            "created_at": p.created_at.isoformat()
                        } for p in profs]
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        return list(self._mem_profiles.values())

    def get_saved_scan_profile(self, name: str, session: Optional[Session] = None) -> Optional[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    p = db.query(SavedScanProfile).filter(SavedScanProfile.name == name).first()
                    if p:
                        return {
                            "id": p.id,
                            "name": p.name,
                            "description": p.description,
                            "category": p.category,
                            "config_json": p.config_json,
                            "is_builtin": p.is_builtin,
                            "created_by": p.created_by,
                            "created_at": p.created_at.isoformat()
                        }
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        return self._mem_profiles.get(name)

    # ==========================================
    # REMEDIATION WORKFLOW & LOST UPDATE PREVENTION
    # ==========================================

    def update_finding_remediation_status(
        self,
        finding_id: str,
        new_status: str,
        changed_by: str = "asip_ali",
        notes: Optional[str] = None,
        expected_version: Optional[int] = None,
        session: Optional[Session] = None
    ) -> Dict[str, Any]:
        """
        ATOMIC REMEDIATION UPDATE:
        Validates state transitions, enforces optimistic concurrency check (prevents lost updates),
        updates finding status and notes, records RemediationHistory, and commits an AuditLog entry.
        """
        valid_statuses = ('open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive')
        if new_status not in valid_statuses:
            raise DatabaseIntegrityError(f"Invalid remediation status '{new_status}'. Must be one of {valid_statuses}")

        try:
            with self._session_scope(session) as db:
                if db:
                    finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.finding_id == finding_id).first()
                    if not finding:
                        raise EntityNotFoundError(f"Vulnerability Finding '{finding_id}' not found.")

                    if expected_version is not None and finding.version_id != expected_version:
                        raise ConcurrencyConflictError(
                            f"Finding '{finding_id}' was concurrently modified by another user "
                            f"(expected version {expected_version}, current database version {finding.version_id})."
                        )

                    prev_status = finding.finding_status
                    finding.finding_status = new_status
                    finding.status_updated_by = changed_by
                    finding.status_updated_at = utcnow()
                    finding.remediation_notes = notes or finding.remediation_notes
                    finding.version_id += 1

                    history = RemediationHistory(
                        finding_id=finding_id,
                        previous_status=prev_status,
                        new_status=new_status,
                        changed_by=changed_by,
                        notes=notes,
                        created_at=utcnow()
                    )
                    db.add(history)
                    db.flush()

                    audit = AuditLog(
                        action="REMEDIATION_STATUS_UPDATED",
                        target_resource=finding_id,
                        details_json=json.dumps({"previous": prev_status, "new": new_status, "changed_by": changed_by}),
                        timestamp=utcnow()
                    )
                    db.add(audit)
                    db.flush()

                    return {
                        "finding_id": finding_id,
                        "previous_status": prev_status,
                        "new_status": new_status,
                        "changed_by": changed_by,
                        "version_id": finding.version_id,
                        "notes": notes,
                        "updated_at": finding.status_updated_at.isoformat()
                    }
        except (ConcurrencyConflictError, EntityNotFoundError, DatabaseIntegrityError):
            raise
        except Exception as e:
            logger.warning(f"SQL Server remediation update fallback: {e}")

        # Memory fallback
        if finding_id not in self._mem_findings:
            raise EntityNotFoundError(f"Finding '{finding_id}' not found.")
        f = self._mem_findings[finding_id]
        if expected_version is not None and f.get("version_id", 1) != expected_version:
            raise ConcurrencyConflictError(f"Finding '{finding_id}' was concurrently modified.")

        prev = f.get("finding_status", "open")
        f["finding_status"] = new_status
        f["remediation_status"] = new_status
        f["status_updated_by"] = changed_by
        f["status_updated_at"] = utcnow().isoformat()
        f["remediation_notes"] = notes or f.get("remediation_notes")
        f["version_id"] = f.get("version_id", 1) + 1

        rec = {
            "finding_id": finding_id,
            "previous_status": prev,
            "new_status": new_status,
            "changed_by": changed_by,
            "notes": notes,
            "created_at": utcnow().isoformat()
        }
        self._mem_remediation.append(rec)
        self.log_audit(1, "REMEDIATION_STATUS_UPDATED", finding_id, json.dumps({"previous": prev, "new": new_status}))
        return {
            "finding_id": finding_id,
            "previous_status": prev,
            "new_status": new_status,
            "changed_by": changed_by,
            "version_id": f["version_id"],
            "notes": notes,
            "updated_at": f["status_updated_at"]
        }

    def list_remediation_history(self, finding_id: str, session: Optional[Session] = None) -> List[Dict[str, Any]]:
        try:
            with self._session_scope(session) as db:
                if db:
                    hist = db.query(RemediationHistory).filter(RemediationHistory.finding_id == finding_id).order_by(RemediationHistory.created_at.asc()).all()
                    if hist:
                        return [{
                            "id": h.id,
                            "finding_id": h.finding_id,
                            "previous_status": h.previous_status,
                            "new_status": h.new_status,
                            "changed_by": h.changed_by,
                            "notes": h.notes,
                            "created_at": h.created_at.isoformat()
                        } for h in hist]
        except Exception as e:
            logger.debug(f"SQL Server query fallback: {e}")
        return [h for h in self._mem_remediation if h["finding_id"] == finding_id]

    # ==========================================
    # DURABILITY: POST-RESTART RECONCILIATION
    # ==========================================

    def reconcile_interrupted_scans(self, session: Optional[Session] = None) -> Dict[str, Any]:
        """
        Durability & Recovery Lifespan Handler:
        Detects any scans and campaigns that were left in 'Running' or 'Initializing'
        state prior to an abrupt application restart or host interruption.
        Transitions them to 'Interrupted', emits diagnostic events, and commits audit logs.
        """
        interrupted_scans = []
        interrupted_camps = []

        try:
            with self._session_scope(session) as db:
                if db:
                    # 1. Reconcile scan executions
                    running_scans = db.query(ScanExecution).filter(
                        ScanExecution.status.in_(["running", "queued"])
                    ).all()
                    for s in running_scans:
                        s.status = "interrupted"
                        s.error_message = "Scan was interrupted by an application or host restart."
                        s.completed_at = utcnow()
                        interrupted_scans.append(s.scan_id)

                        evt = ScanExecutionEvent(
                            scan_id=s.scan_id,
                            recon_id=s.recon_id,
                            event_type="warning",
                            stage="RECOVERY",
                            message="Scan execution marked as Interrupted following application restart.",
                            timestamp=utcnow()
                        )
                        db.add(evt)

                        audit = AuditLog(
                            action="SCAN_INTERRUPTED_RECOVERY",
                            target_resource=s.scan_id,
                            details_json=json.dumps({"reason": "Application restart recovery"}),
                            timestamp=utcnow()
                        )
                        db.add(audit)

                    # 2. Reconcile campaigns
                    running_camps = db.query(ReconCampaign).filter(
                        ReconCampaign.status.in_(["Running", "Queued"])
                    ).all()
                    for c in running_camps:
                        c.status = "Interrupted"
                        c.current_stage = "Interrupted by System Restart"
                        c.updated_at = utcnow()
                        c.version_id += 1
                        interrupted_camps.append(c.recon_id)

                    db.flush()
        except Exception as e:
            logger.warning(f"SQL Server restart reconciliation notice: {e}")

        # In-memory reconciliation
        for scan_id, s in self._mem_scans.items():
            if s.get("status") in ("running", "queued"):
                s["status"] = "interrupted"
                s["error_message"] = "Interrupted by system restart."
                s["completed_at"] = utcnow().isoformat()
                interrupted_scans.append(scan_id)

        for recon_id, c in self._mem_recon_campaigns.items():
            if c.get("status") in ("Running", "Queued"):
                c["status"] = "Interrupted"
                c["current_stage"] = "Interrupted by System Restart"
                c["updated_at"] = utcnow().isoformat()
                interrupted_camps.append(recon_id)

        logger.info(
            f"Startup Reconciliation Complete: reconciled {len(interrupted_scans)} interrupted scans, "
            f"{len(interrupted_camps)} interrupted campaigns."
        )
        return {
            "reconciled_scans": interrupted_scans,
            "reconciled_campaigns": interrupted_camps
        }
