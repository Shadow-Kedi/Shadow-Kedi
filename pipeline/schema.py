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
    DEVICE_CONNECT   = "device_connect"  # generic PnP peripheral: Bluetooth,
    # camera, audio, printer, keyboard, HID -- anything that isn't storage
    # (usb_connect) or a network adapter (network_connection). Added because
    # the device scanner had nowhere accurate to put these; they were being
    # force-mapped onto usb_connect as the closest available bucket.


class RiskCategory(str, Enum):
    INFORMATIONAL = "informational"  # 0th-70th percentile (or <0.02 classifier probability)
    LOW           = "low"            # 70th-90th percentile (or 0.02-0.10)
    MEDIUM        = "medium"         # 90th-97th percentile (or 0.10-0.50/tuned)
    HIGH          = "high"           # 97th-99th percentile (or 0.50-0.90/tuned)
    CRITICAL      = "critical"       # 99th-100th percentile (or 0.90-1.0/tuned)
    # Extended from 4 tiers to 5 (added INFORMATIONAL) -- boundaries here
    # are the percentile-mode defaults from pipeline/risk_categorization.py;
    # the classifier-probability mode uses its own tuned boundaries (see
    # that module and risk_engine.py's --classifier-* / --casb-* args).
    # These comments describe the DEFAULT boundaries, not fixed values --
    # actual cutoffs are tunable per risk_engine.py's CLI args.


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

    # Device identity (optional) -- was previously only available via
    # raw_data{}, meaning it wasn't normalized/queryable consistently across
    # sources. Populated by the network/device scanners; null for sources
    # that don't have a device identity (browser activity, logins, etc.).
    mac_address:     Optional[str]   = None
    device_status:   Optional[str]   = None  # new / known / reappeared (scanner-observed, distinct from risk_category)

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