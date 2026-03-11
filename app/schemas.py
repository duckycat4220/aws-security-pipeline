from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field, IPvAnyAddress

EventType = Literal[
    "authentication_event",
    "file_activity",
    "process_activity",
    "network_activity",
    "security_control_event",
]

SeverityLevel = Literal["low", "medium", "high", "critical"]
AssetCriticality = Literal["low", "medium", "high", "critical"]

class SecurityEvent (BaseModel):
    event_id: str = Field(..., min_length=3, max_length=128)
    timestamp: datetime
    event_type: EventType
    source: str = Field(..., min_length=2, max_length=100)

    source_ip: Optional[IPvAnyAddress] = None
    destination_ip: Optional[IPvAnyAddress] = None
    
    user_id: Optional[str] = Field(default=None, max_length=100)
    user_role: Optional[str] = Field(default=None, max_length=100)

    asset_id: str = Field(..., min_length=2, max_length=100)
    asset_type: str = Field(..., min_length=2, max_length=100)
    asset_criticality: AssetCriticality

    severity: SeverityLevel
    details: Dict[str, Any] = Field(default_factory=dict)

class IngestResponse(BaseModel):
    message: str
    event_id: str
    queue_name: str