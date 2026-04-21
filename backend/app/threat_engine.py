"""
threat_engine.py — Threat scoring, action determination, and full pipeline orchestration.
Combines real tools (Kafka, Elasticsearch, Vault) with simulated stages.
"""

import time
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple

from app.config import THREAT_LEVELS
from app.schemas import (
    PredictionResult, PipelineStageResult, ThreatAction, GeoLocation, NetworkEvent
)
from app import inference
from app import kafka_client
from app import elastic_client
from app import vault_client
from app import pipeline_stages

logger = logging.getLogger("hpe.threat_engine")

# ── Global metrics ─────────────────────────────────────────────────────────────
_metrics = {
    "total_requests": 0,
    "total_threats": 0,
    "total_allowed": 0,
    "total_monitored": 0,
    "total_blocked": 0,
    "total_critical": 0,
    "total_latency_ms": 0.0,
    "attack_types": {},
}


def get_metrics() -> Dict[str, Any]:
    """Get current pipeline metrics."""
    avg_latency = (_metrics["total_latency_ms"] / max(_metrics["total_requests"], 1))
    return {
        **_metrics,
        "avg_latency_ms": round(avg_latency, 2),
        "model_metrics": inference.get_artifacts().get("metrics", {}) if inference.get_artifacts() else {},
    }


def determine_action(threat_score: float) -> ThreatAction:
    """Determine the appropriate action based on threat score."""
    if threat_score < THREAT_LEVELS["ALLOW"]:
        return ThreatAction.ALLOW
    elif threat_score < THREAT_LEVELS["MONITOR"]:
        return ThreatAction.MONITOR
    elif threat_score < THREAT_LEVELS["BLOCK"]:
        return ThreatAction.BLOCK
    else:
        return ThreatAction.CRITICAL_ALERT


def process_event(event: NetworkEvent) -> PredictionResult:
    """
    Process a single event through the FULL pipeline:
    Network → Zeek/Suricata → Beats → Kafka → AI → SOAR → Vault → Rotation → Dist → ELK
    """
    t0 = time.time()
    event_id = str(uuid.uuid4())[:12]
    event_dict = event.model_dump()
    stages: List[PipelineStageResult] = []

    # ── Stage 1: Network Capture (simulated) ──
    stage1 = pipeline_stages.simulate_network_capture(event_dict)
    stages.append(stage1)

    # ── Stage 2: Zeek/Suricata (simulated) ──
    stage2 = pipeline_stages.simulate_zeek_suricata(event_dict)
    stages.append(stage2)

    # ── Stage 3: Elastic Beats (simulated) ──
    stage3 = pipeline_stages.simulate_elastic_beats(event_dict)
    stages.append(stage3)

    # ── Stage 4: Apache Kafka (REAL) ──
    kafka_t0 = time.time()
    kafka_success = kafka_client.produce_raw_event({
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **event_dict,
    })
    kafka_latency = (time.time() - kafka_t0) * 1000

    stages.append(PipelineStageResult(
        stage_name="Apache Kafka",
        stage_number=4,
        status="produced" if kafka_success else "fallback",
        latency_ms=round(kafka_latency, 2),
        details={
            "topic": "hpe-raw-events",
            "partition": "auto",
            "delivered": kafka_success,
        },
        is_real_tool=True,
    ))

    # ── Stage 5: AI Detection Engine (REAL) ──
    ai_t0 = time.time()
    try:
        xgb_score, lgb_score, ensemble_score, threshold, is_threat = inference.predict(event_dict)
    except Exception as e:
        logger.error(f"Inference error: {e}")
        xgb_score, lgb_score, ensemble_score, threshold, is_threat = 0.0, 0.0, 0.0, 0.5, False
    ai_latency = (time.time() - ai_t0) * 1000

    threat_action = determine_action(ensemble_score)

    stages.append(PipelineStageResult(
        stage_name="AI Detection Engine",
        stage_number=5,
        status="threat_detected" if is_threat else "clear",
        latency_ms=round(ai_latency, 2),
        details={
            "xgboost_score": round(xgb_score, 6),
            "lightgbm_score": round(lgb_score, 6),
            "ensemble_score": round(ensemble_score, 6),
            "threshold": round(threshold, 6),
            "is_threat": is_threat,
            "action": threat_action.value,
        },
        is_real_tool=True,
    ))

    # ── Stage 6: SOAR Automation (simulated) ──
    stage6 = pipeline_stages.simulate_soar_automation(event_dict, is_threat, ensemble_score)
    stages.append(stage6)

    # ── Stage 7: HashiCorp Vault (REAL) ──
    vault_t0 = time.time()
    vault_result = {}
    if is_threat:
        vault_result = vault_client.rotate_credentials(
            reason=f"threat_detected_score_{ensemble_score:.4f}",
            user=event_dict.get("user", "unknown"),
            threat_score=ensemble_score,
        )
    vault_latency = (time.time() - vault_t0) * 1000

    stages.append(PipelineStageResult(
        stage_name="HashiCorp Vault",
        stage_number=7,
        status="credentials_rotated" if is_threat and vault_result.get("success") else "no_action",
        latency_ms=round(vault_latency, 2),
        details=vault_result if is_threat else {"status": "no_rotation_needed"},
        is_real_tool=True,
    ))

    # ── Stage 8: Credential Rotation (simulated) ──
    stage8 = pipeline_stages.simulate_credential_rotation(is_threat, vault_result)
    stages.append(stage8)

    # ── Stage 9: Credentials Distributed (simulated) ──
    stage9 = pipeline_stages.simulate_credential_distribution(is_threat)
    stages.append(stage9)

    # ── Stage 10: ELK Stack / Grafana (REAL — Elasticsearch) ──
    elk_t0 = time.time()
    es_audit_success = elastic_client.index_audit_log(
        event_id=event_id,
        stage="pipeline_complete",
        action=threat_action.value,
        threat_score=ensemble_score,
        is_threat=is_threat,
        event_data=event_dict,
    )

    if is_threat:
        elastic_client.index_threat(event_id, {
            "event_id": event_id,
            "threat_score": round(ensemble_score, 6),
            "threat_action": threat_action.value,
            "attack_type": event_dict.get("attack_type", "unknown"),
            "source_ip": event_dict.get("source_ip", ""),
            "destination_ip": event_dict.get("destination_ip", ""),
            "user": event_dict.get("user", ""),
            "hostname": event_dict.get("hostname", ""),
            "xgb_score": round(xgb_score, 6),
            "lgb_score": round(lgb_score, 6),
            "ensemble_score": round(ensemble_score, 6),
            "vault_rotation_triggered": bool(vault_result.get("success")),
            "credentials_rotated": bool(vault_result.get("success")),
        })

        # Also produce alert to Kafka
        kafka_client.produce_alert({
            "event_id": event_id,
            "threat_score": ensemble_score,
            "action": threat_action.value,
            "user": event_dict.get("user", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    elk_latency = (time.time() - elk_t0) * 1000

    stages.append(PipelineStageResult(
        stage_name="ELK Stack / Grafana",
        stage_number=10,
        status="indexed" if es_audit_success else "fallback",
        latency_ms=round(elk_latency, 2),
        details={
            "audit_indexed": es_audit_success,
            "threat_indexed": is_threat,
            "index": "hpe-audit-logs",
        },
        is_real_tool=True,
    ))

    # ── Compute totals ──
    total_latency = (time.time() - t0) * 1000

    # Update global metrics
    _metrics["total_requests"] += 1
    _metrics["total_latency_ms"] += total_latency
    if is_threat:
        _metrics["total_threats"] += 1
    action_key = f"total_{threat_action.value.lower()}"
    if action_key in _metrics:
        _metrics[action_key] += 1
    if is_threat:
        at = event_dict.get("attack_type", "unknown")
        _metrics["attack_types"][at] = _metrics["attack_types"].get(at, 0) + 1

    # Build geo data
    src_geo = inference.ip_to_geo(event_dict.get("source_ip", ""))
    dst_geo = inference.ip_to_geo(event_dict.get("destination_ip", ""))

    return PredictionResult(
        event_id=event_id,
        is_threat=is_threat,
        threat_score=round(ensemble_score, 6),
        threat_action=threat_action,
        xgb_score=round(xgb_score, 6),
        lgb_score=round(lgb_score, 6),
        ensemble_score=round(ensemble_score, 6),
        threshold=round(threshold, 6),
        source_geo=GeoLocation(**src_geo),
        destination_geo=GeoLocation(**dst_geo),
        pipeline_stages=stages,
        total_latency_ms=round(total_latency, 2),
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_summary={
            "user": event_dict.get("user", ""),
            "event_type": event_dict.get("event_type", ""),
            "source_ip": event_dict.get("source_ip", ""),
            "destination_ip": event_dict.get("destination_ip", ""),
            "process_name": event_dict.get("process_name", ""),
            "hostname": event_dict.get("hostname", ""),
        },
    )
