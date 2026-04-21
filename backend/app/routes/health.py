"""
routes/health.py — Health check and metrics endpoints.
"""

import time
from fastapi import APIRouter
from app.schemas import HealthResponse, MetricsResponse
from app.config import APP_NAME, APP_VERSION
from app import kafka_client, elastic_client, vault_client, inference
from app.threat_engine import get_metrics

router = APIRouter(prefix="/api", tags=["health"])

_start_time = time.time()


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Check health of all pipeline components."""
    metrics = get_metrics()
    return HealthResponse(
        status="healthy",
        app_name=APP_NAME,
        version=APP_VERSION,
        uptime_seconds=round(time.time() - _start_time, 1),
        model_loaded=inference.get_artifacts() is not None,
        kafka_connected=kafka_client.is_connected(),
        elasticsearch_connected=elastic_client.is_connected(),
        vault_connected=vault_client.is_connected(),
        total_requests=metrics["total_requests"],
        total_threats_blocked=metrics["total_blocked"] + metrics["total_critical"],
    )


@router.get("/metrics", response_model=MetricsResponse)
async def get_pipeline_metrics():
    """Get detailed pipeline metrics."""
    metrics = get_metrics()
    return MetricsResponse(
        total_requests=metrics["total_requests"],
        total_threats=metrics["total_threats"],
        total_allowed=metrics["total_allowed"],
        total_monitored=metrics["total_monitored"],
        total_blocked=metrics["total_blocked"],
        total_critical=metrics["total_critical"],
        avg_latency_ms=metrics["avg_latency_ms"],
        model_metrics=metrics.get("model_metrics", {}),
        pipeline_health={
            "kafka": "connected" if kafka_client.is_connected() else "disconnected",
            "elasticsearch": "connected" if elastic_client.is_connected() else "disconnected",
            "vault": "connected" if vault_client.is_connected() else "disconnected",
            "model": "loaded" if inference.get_artifacts() else "not_loaded",
        },
        attack_types=metrics.get("attack_types", {}),
    )
