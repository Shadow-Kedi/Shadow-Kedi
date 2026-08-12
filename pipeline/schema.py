# pipeline/schema.py

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


class EventType(str, Enum):
    BROWSER_ACTIVITY = "browser_activity"
    APP_INSTALL      = "app_install"
    APP_LAUNCH       = "app_launch"
    FILE_ACCESS      = "file_access"
    FILE_TRANSFER    = "file_transfer"
    USB_CONNECT      = "usb_connect"
    NETWORK_CONN     = "network_connection"
    DNS_QUERY        = "dns_query"
    CLOUD_UPLOAD     = "cloud_upload"
    LOGIN_EVENT      = "login_event"


class RiskCategory(str, Enum):
    LOW      = "low"       # 0-25
    MEDIUM   = "medium"    # 26-50
    HIGH     = "high"      # 51-75
    CRITICAL = "critical"  # 76-100


class ShadowKediEvent(BaseModel):
    """Universal event schema for all Shadow Kedi data"""

    # Identity
    event_id:       str             = Field(..., description="Unique event ID")
    timestamp:      datetime        = Field(..., description="When it happened")
    agent_id:       str             = Field(..., description="Endpoint agent ID")
    hostname:       str             = Field(..., description="Machine hostname")
    username:       str             = Field(..., description="User who triggered event")
    client_id:      str             = Field(..., description="MSP client/tenant ID")

    # Event Details
    event_type:     EventType       = Field(..., description="Type of event")
    source:         str             = Field(..., description="Where data came from")
    raw_data:       dict            = Field(default={}, description="Original raw log")

    # Network (optional)
    destination_ip:     Optional[str]   = None
    destination_domain: Optional[str]   = None
    destination_port:   Optional[int]   = None
    bytes_sent:         Optional[int]   = None
    bytes_received:     Optional[int]   = None

    # File (optional)
    file_path:      Optional[str]   = None
    file_name:      Optional[str]   = None
    file_size_kb:   Optional[float] = None
    file_extension: Optional[str]   = None

    # Application (optional)
    app_name:       Optional[str]   = None
    app_version:    Optional[str]   = None
    app_publisher:  Optional[str]   = None

    # Risk (filled by scoring engine)
    risk_score:     Optional[float] = Field(None, ge=0, le=100)
    risk_category:  Optional[RiskCategory] = None
    risk_reasons:   Optional[List[str]]    = None
    is_anomaly:     Optional[bool]         = None
    mitre_tags:     Optional[List[str]]    = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class UserProfile(BaseModel):
    """Tracks per-user behavioral baseline"""

    username:           str
    client_id:          str
    department:         Optional[str]   = None
    role:               Optional[str]   = None

    # Behavioral baseline stats
    avg_daily_events:   float           = 0.0
    typical_hours:      List[int]       = Field(default_factory=list)
    known_domains:      List[str]       = Field(default_factory=list)
    known_apps:         List[str]       = Field(default_factory=list)
    known_ips:          List[str]       = Field(default_factory=list)

    # Risk tracking
    current_risk_score: float           = 0.0
    risk_trend:         str             = "stable"   # rising/falling/stable
    total_alerts:       int             = 0
    last_seen:          Optional[datetime] = None