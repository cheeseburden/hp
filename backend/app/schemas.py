"""
schemas.py — Pydantic models for request/response validation.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ThreatAction(str, Enum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    BLOCK = "BLOCK"
    CRITICAL_ALERT = "CRITICAL_ALERT"


class GeoLocation(BaseModel):
    lat: float = 0.0
    lng: float = 0.0
    city: str = "Unknown"


# ── Request schemas ────────────────────────────────────────────────────────────
class NetworkEvent(BaseModel):
    """A single network/security event from the log data."""
    event_type: str = Field(default="unknown", description="Type of event")
    user: str = Field(default="unknown", description="Username")
    hostname: Optional[str] = ""
    process_name: Optional[str] = ""
    command_line: Optional[str] = ""
    source_ip: Optional[str] = ""
    destination_ip: Optional[str] = ""
    department: Optional[str] = ""
    location: Optional[str] = ""
    device_type: Optional[str] = ""
    success: Optional[str] = "true"
    session_id: Optional[str] = ""
    service_account: Optional[str] = "false"
    account: Optional[str] = ""
    event_id: Optional[str] = ""
    parent_process: Optional[str] = ""
    prevalence_score: Optional[str] = "0.0"
    log_type: Optional[str] = ""
    timestamp: Optional[str] = ""
    protocol: Optional[str] = ""
    port: Optional[str] = ""
    file_size: Optional[str] = ""
    confidence_level: Optional[str] = ""
    signed: Optional[str] = "false"

    class Config:
        json_schema_extra = {
            "example": {
                "event_type": "network_connection",
                "user": "john.doe",
                "hostname": "WS-NYC-001",
                "process_name": "chrome.exe",
                "source_ip": "10.2.3.50",
                "destination_ip": "10.1.0.10",
                "timestamp": "2025-12-21 09:30:00",
            }
        }


class BatchPredictRequest(BaseModel):
    events: List[NetworkEvent]


# ── Response schemas ───────────────────────────────────────────────────────────
class PipelineStageResult(BaseModel):
    """Result from a single pipeline stage."""
    stage_name: str
    stage_number: int
    status: str = "completed"
    latency_ms: float = 0.0
    details: Dict[str, Any] = {}
    is_real_tool: bool = False


class PredictionResult(BaseModel):
    """Full prediction result with pipeline stages."""
    event_id: str
    is_threat: bool
    threat_score: float = Field(ge=0.0, le=1.0)
    threat_action: ThreatAction
    xgb_score: float = 0.0
    lgb_score: float = 0.0
    ensemble_score: float = 0.0
    threshold: float = 0.5
    source_geo: GeoLocation = GeoLocation()
    destination_geo: GeoLocation = GeoLocation()
    pipeline_stages: List[PipelineStageResult] = []
    total_latency_ms: float = 0.0
    timestamp: str = ""
    event_summary: Dict[str, Any] = {}


class HealthResponse(BaseModel):
    status: str = "healthy"
    app_name: str = "HPE"
    version: str = "1.0.0"
    uptime_seconds: float = 0.0
    model_loaded: bool = False
    kafka_connected: bool = False
    elasticsearch_connected: bool = False
    vault_connected: bool = False
    total_requests: int = 0
    total_threats_blocked: int = 0


class MetricsResponse(BaseModel):
    total_requests: int = 0
    total_threats: int = 0
    total_allowed: int = 0
    total_monitored: int = 0
    total_blocked: int = 0
    total_critical: int = 0
    avg_latency_ms: float = 0.0
    model_metrics: Dict[str, float] = {}
    pipeline_health: Dict[str, str] = {}
    attack_types: Dict[str, int] = {}


class PipelineStatusResponse(BaseModel):
    stages: List[Dict[str, Any]] = []
    total_events_processed: int = 0


class SimulationEvent(BaseModel):
    """A simulation event streamed via WebSocket."""
    event: NetworkEvent
    prediction: PredictionResult
    pipeline_stages: List[PipelineStageResult] = []
