"""
routes/pipeline.py — Pipeline status and stage information endpoints.
"""

from fastapi import APIRouter
from app.schemas import PipelineStatusResponse
from app.pipeline_stages import get_stage_definitions
from app.threat_engine import get_metrics
from app import kafka_client, elastic_client, vault_client

router = APIRouter(prefix="/api", tags=["pipeline"])


@router.get("/pipeline/status", response_model=PipelineStatusResponse)
async def get_pipeline_status():
    """Get status of all pipeline stages with real tool health."""
    stages = get_stage_definitions()
    metrics = get_metrics()

    enriched_stages = []
    for stage in stages:
        stage_info = {**stage}

        # Add real tool health status
        if stage["name"] == "Apache Kafka":
            stage_info["health"] = "connected" if kafka_client.is_connected() else "disconnected"
        elif stage["name"] == "AI Detection Engine":
            from app import inference
            stage_info["health"] = "loaded" if inference.get_artifacts() else "not_loaded"
        elif stage["name"] == "HashiCorp Vault":
            stage_info["health"] = "connected" if vault_client.is_connected() else "disconnected"
            stage_info["rotation_count"] = vault_client.get_rotation_count()
        elif stage["name"] == "ELK Stack / Grafana":
            stage_info["health"] = "connected" if elastic_client.is_connected() else "disconnected"
        else:
            stage_info["health"] = "active"

        enriched_stages.append(stage_info)

    return PipelineStatusResponse(
        stages=enriched_stages,
        total_events_processed=metrics["total_requests"],
    )
