"""Pydantic schemas for investigation validation and responses."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class ScopeSchema(BaseModel):
    """Scope target lists defining investigation boundaries."""
    owned_domains: List[str] = Field(default_factory=list, description="Apex domains owned by target organization")
    approved_ips: List[str] = Field(default_factory=list, description="Approved static IP addresses")
    approved_cidrs: List[str] = Field(default_factory=list, description="Approved network CIDR blocks")
    active_targets: List[str] = Field(default_factory=list, description="Explicitly allowlisted active scan IPs")


class InvestigationBase(BaseModel):
    name: str = Field(..., min_length=3, max_length=128, description="Investigation title")
    organization_name: str = Field(..., min_length=2, max_length=128, description="Target company or entity")
    description: str = Field(..., min_length=5, max_length=1024, description="Scope and purpose description")
    lead_investigator: str = Field(..., min_length=2, max_length=128, description="Primary analyst name")
    team_members: List[str] = Field(default_factory=list, description="Secondary analysts")
    status: str = Field(default="active", description="Campaign status: active, completed, archived")
    scope: ScopeSchema = Field(default_factory=ScopeSchema)
    active_scanning_enabled: bool = Field(default=False)
    authorization_reference: Optional[str] = Field(default=None, max_length=128)
    authorization_expiry: Optional[datetime] = None


class InvestigationCreate(InvestigationBase):
    id: Optional[str] = Field(default=None, description="Optional custom identifier (e.g., inv-northstar-01)")


class InvestigationResponse(InvestigationBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
