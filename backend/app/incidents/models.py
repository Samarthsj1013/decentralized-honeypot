from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


IncidentStatus = Literal["open", "acknowledged", "resolved"]
IncidentSeverity = Literal["low", "medium", "high", "critical"]


class Incident(BaseModel):
    model_config = ConfigDict(frozen=True)

    incident_id: str
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    severity: IncidentSeverity
    confidence: float = Field(ge=0, le=1)
    status: IncidentStatus = "open"
    contributing_event_ids: list[str] = Field(max_length=200)
    contributing_sensors: list[str] = Field(max_length=32)
    detection_rules: list[str] = Field(max_length=12)
    evidence_summary: list[str] = Field(max_length=12)


class IncidentStats(BaseModel):
    total: int
    open: int
    acknowledged: int
    resolved: int
    severity_counts: dict[str, int]


class IncidentPage(BaseModel):
    items: list[Incident]
    total: int
    limit: int
    offset: int
