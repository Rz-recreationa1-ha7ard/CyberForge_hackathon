from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class PTESPhase(str, Enum):
    PRE_ENGAGEMENT = "Pre-engagement Interactions"
    INTELLIGENCE_GATHERING = "Intelligence Gathering"
    THREAT_MODELING = "Threat Modeling"
    VULNERABILITY_ANALYSIS = "Vulnerability Analysis"
    EXPLOITATION = "Exploitation"
    POST_EXPLOITATION = "Post Exploitation"
    REPORTING = "Reporting"


class SurfaceType(str, Enum):
    NETWORK = "network"
    WEB = "web"
    BINARY = "binary"


class FindingStatus(str, Enum):
    FLAGGED = "FLAGGED"
    CONFIRMED = "CONFIRMED"


class Finding(BaseModel):
    id: str
    host_id: str
    host_ip: str
    port: Optional[int] = None
    surface: SurfaceType
    ptes_phase: PTESPhase = PTESPhase.VULNERABILITY_ANALYSIS
    finding_type: str
    title: str
    description: str
    evidence: str
    verified: bool = False
    status: FindingStatus = FindingStatus.FLAGGED
    remediation: Optional[str] = None
    flag: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PortService(BaseModel):
    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    version: Optional[str] = None


class TargetHost(BaseModel):
    host_id: str
    ip: str
    hostname: Optional[str] = None
    status: str = "up"
    ports: List[PortService] = Field(default_factory=list)
    tested_surfaces: List[str] = Field(default_factory=list)
    claimed_by: Optional[str] = None


class AttackPathStep(BaseModel):
    step_number: int
    host_ip: str
    phase: PTESPhase
    surface: SurfaceType
    action_taken: str
    finding_ref: Optional[str] = None
    details: Optional[str] = None
