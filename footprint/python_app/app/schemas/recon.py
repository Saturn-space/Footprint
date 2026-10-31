"""Pydantic schemas for passive reconnaissance, target authorizations, evidence, and entities."""

from datetime import datetime
from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field


class TargetValidationRequest(BaseModel):
    """Payload to validate target syntax and scope membership."""
    target: str = Field(..., min_length=1, max_length=255, description="Domain, IP, or CIDR to validate")


class TargetValidationResponse(BaseModel):
    """Validation response indicating whether target syntax and scope are permissible."""
    target: str
    target_type: str  # DOMAIN, IP, CIDR, UNKNOWN
    is_valid_syntax: bool
    is_in_investigation_scope: bool
    message: str


class TargetAuthorizationCreate(BaseModel):
    """Payload for provisioning a formal administrative target authorization record."""
    target: str = Field(..., min_length=1, max_length=255)
    target_type: Literal["DOMAIN", "IP", "CIDR"]
    allowed_operations: List[str] = Field(
        default=["PASSIVE_RECON"],
        description="Permitted operations, e.g. ['PASSIVE_RECON']"
    )
    authorization_reference: str = Field(
        ..., min_length=3, max_length=128,
        description="Formal approval document or consent tracking reference"
    )
    valid_from: Optional[datetime] = Field(default=None, description="Start timestamp of authorization in UTC")
    valid_to: datetime = Field(..., description="Expiration timestamp in UTC")
    approved_by: Optional[str] = Field(default=None, description="Authorizing administrator or officer name")
    notes: Optional[str] = None


class TargetAuthorizationResponse(BaseModel):
    """Representation of an administrative target authorization record."""
    id: str
    investigation_id: str
    target: str
    target_type: str
    allowed_operations: List[str]
    authorization_reference: str
    approved_by: str
    valid_from: datetime
    valid_to: datetime
    is_revoked: bool
    notes: Optional[str] = None
    created_at: datetime


class PassiveReconRequest(BaseModel):
    """Payload to trigger passive reconnaissance for an authorized target."""
    target: str = Field(..., min_length=1, max_length=255, description="Approved domain target")
    collectors: Optional[List[str]] = Field(
        default=None,
        description="Optional list of collectors to run: 'rdap', 'dns', 'crtsh', 'theharvester'. Defaults to all."
    )


class CollectionJobSummary(BaseModel):
    """Summary of individual collector execution status."""
    id: str
    collector_name: str
    status: str
    result_summary: Dict[str, Any] = Field(default_factory=dict)
    error_category: Optional[str] = None
    error_message: Optional[str] = None


class PassiveReconResponse(BaseModel):
    """Aggregated execution summary returned by passive reconnaissance orchestrator."""
    investigation_id: str
    target: str
    orchestrator_job_id: str
    status: str  # COMPLETED, PARTIAL, FAILED
    collectors: List[CollectionJobSummary]
    evidence_collected: int
    new_entities_discovered: int
    total_entities_count: int


class EvidenceResponse(BaseModel):
    """Forensic evidence metadata representation."""
    id: str
    investigation_id: str
    job_id: Optional[str] = None
    source_type: str
    source_name: str
    target: str
    collection_status: str
    content_hash: str
    content_size_bytes: int
    source_metadata: Dict[str, Any] = Field(default_factory=dict)
    collected_at: datetime


class EntityResponse(BaseModel):
    """Normalized OSINT entity record with provenance."""
    id: str
    investigation_id: str
    entity_type: str
    canonical_value: str
    original_value: str
    first_seen: datetime
    last_seen: datetime
    evidence_ids: List[str]
    metadata: Dict[str, Any] = Field(default_factory=dict)
