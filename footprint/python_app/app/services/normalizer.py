"""Deterministic normalization and entity deduplication service for OSINT evidence."""

import re
import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models.recon import EntityModel


def normalize_domain(domain: str) -> Optional[str]:
    """Normalizes a domain or hostname into canonical FQDN representation."""
    if not domain or not isinstance(domain, str):
        return None

    cleaned = domain.strip().lower()
    # Strip protocols
    if cleaned.startswith("http://"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("https://"):
        cleaned = cleaned[8:]

    # Strip port if present
    if ":" in cleaned:
        cleaned = cleaned.split(":")[0]

    # Strip path or trailing slashes
    cleaned = cleaned.split("/")[0].strip()

    # Strip trailing dot
    cleaned = cleaned.rstrip(".")

    # Basic FQDN validation
    if len(cleaned) < 3 or "." not in cleaned:
        return None

    # Handle wildcard certificates (*.example.com -> example.com)
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]

    # Remove any invalid characters
    cleaned = re.sub(r"[^a-z0-9\-\.]", "", cleaned)
    return cleaned if cleaned else None


def normalize_email(email: str) -> Optional[str]:
    """Conservatively normalizes email address (lower-cased domain, trimmed localpart)."""
    if not email or not isinstance(email, str) or "@" not in email:
        return None

    parts = email.strip().split("@", 1)
    if len(parts) != 2:
        return None

    local_part = parts[0].strip()
    domain_part = parts[1].strip().lower()

    if not local_part or not domain_part or "." not in domain_part:
        return None

    return f"{local_part}@{domain_part}"


def normalize_ip(ip_str: str) -> Optional[str]:
    """Normalizes IP address using standard library ipaddress parsing."""
    if not ip_str or not isinstance(ip_str, str):
        return None
    try:
        parsed = ipaddress.ip_address(ip_str.strip())
        return str(parsed)
    except ValueError:
        return None


def normalize_entity_value(entity_type: str, raw_value: str) -> Tuple[Optional[str], str]:
    """Returns canonical normalized value and preserved original value."""
    original = str(raw_value).strip() if raw_value is not None else ""

    if entity_type in ("DOMAIN", "SUBDOMAIN", "HOST"):
        canonical = normalize_domain(original)
    elif entity_type == "EMAIL":
        canonical = normalize_email(original)
    elif entity_type == "IP_ADDRESS":
        canonical = normalize_ip(original)
    elif entity_type in ("DNS_RECORD", "CERTIFICATE", "ORGANIZATION", "URL"):
        canonical = original.strip()
    else:
        canonical = original.strip()

    return canonical, original


class EntityNormalizer:
    """Processes raw collector findings, applies deterministic normalization, and deduplicates records."""

    def __init__(self, db: Session, investigation_id: str):
        self.db = db
        self.investigation_id = investigation_id

    def ingest_finding(
        self,
        entity_type: str,
        raw_value: str,
        evidence_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[EntityModel]:
        """Normalizes and deduplicates a finding, linking evidence provenance.

        Returns:
            The created or updated EntityModel, or None if raw_value is invalid.
        """
        canonical, original = normalize_entity_value(entity_type, raw_value)
        if not canonical:
            return None

        now = datetime.now(timezone.utc)
        meta = metadata.copy() if metadata else {}

        # Query existing entity in this investigation
        stmt = select(EntityModel).where(
            EntityModel.investigation_id == self.investigation_id,
            EntityModel.entity_type == entity_type,
            EntityModel.canonical_value == canonical,
        )
        existing_entity = self.db.scalar(stmt)

        if existing_entity:
            # Update timestamps and provenance
            existing_entity.last_seen = now
            evidence_list = list(existing_entity.evidence_ids or [])
            if evidence_id not in evidence_list:
                evidence_list.append(evidence_id)
                existing_entity.evidence_ids = evidence_list

            # Merge metadata
            current_meta = dict(existing_entity.metadata_json or {})
            current_meta.update(meta)
            existing_entity.metadata_json = current_meta

            self.db.commit()
            self.db.refresh(existing_entity)
            return existing_entity

        # Create new normalized entity
        new_entity = EntityModel(
            id=f"ent-{uuid.uuid4().hex[:12]}",
            investigation_id=self.investigation_id,
            entity_type=entity_type,
            canonical_value=canonical,
            original_value=original,
            first_seen=now,
            last_seen=now,
            evidence_ids=[evidence_id],
            metadata_json=meta,
        )
        self.db.add(new_entity)
        self.db.commit()
        self.db.refresh(new_entity)
        return new_entity
