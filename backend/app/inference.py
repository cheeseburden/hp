"""
inference.py — Feature engineering and ML ensemble inference.
Mirrors the exact training pipeline from export_model.py for consistent predictions.
"""

import numpy as np
import pandas as pd
import joblib
import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger("hpe.inference")

# Global model artifacts (loaded once at startup)
_artifacts = None


def load_model(model_path: str) -> Dict[str, Any]:
    """Load the serialized pipeline artifacts into memory."""
    global _artifacts
    logger.info(f"Loading model artifacts from {model_path} ...")
    _artifacts = joblib.load(model_path)
    logger.info(f"Model loaded: {len(_artifacts['feature_names'])} features, "
                f"thresholds: {_artifacts['thresholds']}")
    return _artifacts


def get_artifacts() -> Dict[str, Any]:
    """Get the loaded model artifacts."""
    return _artifacts


# ── IP → Geo-coordinate mapping (same as export_model.py) ─────────────────────
GEO_IP_MAP = {
    "10.1.": {"lat": 12.97, "lng": 77.59, "city": "Bangalore"},
    "10.2.": {"lat": 40.71, "lng": -74.01, "city": "New York"},
    "10.3.": {"lat": 37.77, "lng": -122.42, "city": "San Francisco"},
    "10.4.": {"lat": 51.51, "lng": -0.13, "city": "London"},
    "10.5.": {"lat": 35.68, "lng": 139.69, "city": "Tokyo"},
    "10.6.": {"lat": 48.86, "lng": 2.35, "city": "Paris"},
    "10.7.": {"lat": -33.87, "lng": 151.21, "city": "Sydney"},
    "10.8.": {"lat": 1.35, "lng": 103.82, "city": "Singapore"},
    "10.9.": {"lat": 55.75, "lng": 37.62, "city": "Moscow"},
    "10.10.": {"lat": 52.52, "lng": 13.41, "city": "Berlin"},
    "10.0.": {"lat": 19.08, "lng": 72.88, "city": "Mumbai"},
    "192.168.": {"lat": -23.55, "lng": -46.63, "city": "Sao Paulo"},
    "172.16.": {"lat": 25.20, "lng": 55.27, "city": "Dubai"},
}


def ip_to_geo(ip: str) -> dict:
    """Map an IP to a geo-coordinate for visualization."""
    if not ip or ip == "UNKNOWN":
        return {"lat": 0.0, "lng": 0.0, "city": "Unknown"}
    for prefix, geo in GEO_IP_MAP.items():
        if ip.startswith(prefix):
            return geo
    hash_val = hash(ip) % 360
    return {"lat": float((hash_val % 180) - 90), "lng": float((hash_val % 360) - 180), "city": "Remote"}


def engineer_single_event(event: Dict[str, Any]) -> np.ndarray:
    """
    Engineer features for a single event using pre-computed global stats.
    Must produce the exact same feature vector as the training pipeline.
    """
    if _artifacts is None:
        raise RuntimeError("Model not loaded. Call load_model() first.")

    freq_maps = _artifacts["freq_maps"]
    global_stats = _artifacts["global_stats"]
    feature_names = _artifacts["feature_names"]

    # ── Parse basic fields ──
    success = 1 if event.get("success") in ("true", True, "1", 1) else 0
    service_account = 1 if event.get("service_account") in ("true", True, "1", 1) else 0
    signed = 1 if event.get("signed") in ("true", True, "1", 1) else 0

    prevalence_score = _safe_float(event.get("prevalence_score", 0))
    file_size = _safe_float(event.get("file_size", 0))
    port = _safe_float(event.get("port", 0))
    confidence_level = _safe_float(event.get("confidence_level", 0))

    # ── Temporal features ──
    ts = pd.to_datetime(event.get("timestamp", ""), errors="coerce")
    if pd.isna(ts):
        ts = pd.Timestamp.now()

    hour = ts.hour
    minute = ts.minute
    day_of_week = ts.dayofweek
    is_business_hours = 1 if 8 <= hour <= 18 else 0
    is_weekend = 1 if day_of_week >= 5 else 0

    # ── Frequency encoding ──
    freq_cols_list = _artifacts.get("freq_cols", [])
    freq_features = {}
    for col in freq_cols_list:
        val = str(event.get(col, "UNKNOWN") or "UNKNOWN")
        fmap = freq_maps.get(col, {})
        freq_features[f"{col}_freq"] = fmap.get(val, 0.0)

    # ── Aggregate lookups ──
    user = str(event.get("user", "UNKNOWN") or "UNKNOWN")
    hostname = str(event.get("hostname", "UNKNOWN") or "UNKNOWN")

    user_event_count = global_stats.get("user_cnt", {}).get(user, 0)
    user_unique_dst_ips = global_stats.get("user_unique_dst", {}).get(user, 0)
    user_unique_processes = global_stats.get("user_unique_proc", {}).get(user, 0)
    user_success_rate = global_stats.get("user_suc_rate", {}).get(user, 0.0)
    hostname_event_count = global_stats.get("host_cnt", {}).get(hostname, 0)

    # ── Per (user, hour_bucket) ──
    hour_bucket = str(ts.floor("h"))
    uh_key = f"{user}||{hour_bucket}"
    user_hourly_event_rate = global_stats.get("uh_cnt", {}).get(uh_key, 0)
    user_hourly_unique_dst = global_stats.get("uh_unique_dst", {}).get(uh_key, 0)

    # ── Rare indicators ──
    process_name = str(event.get("process_name", "UNKNOWN") or "UNKNOWN")
    event_type = str(event.get("event_type", "UNKNOWN") or "UNKNOWN")

    pn_freq = freq_maps.get("process_name", {}).get(process_name, 0.0)
    is_rare_process = 1 if pn_freq <= global_stats.get("rare_proc_thr", 0) else 0

    et_freq = freq_maps.get("event_type", {}).get(event_type, 0.0)
    is_rare_event_type = 1 if et_freq <= global_stats.get("rare_et_thr", 0) else 0

    # ── Session ──
    session_id = str(event.get("session_id", "") or "")
    session_event_count = global_stats.get("sess_cnt", {}).get(session_id, 0) if session_id else 0

    # ── Command line length ──
    cmd = str(event.get("command_line", "") or "")
    cmd_len = len(cmd)

    # ── Build feature vector in EXACT training order ──
    feature_dict = {
        "success": float(success),
        "service_account": float(service_account),
        "signed": float(signed),
        "prevalence_score": float(prevalence_score),
        "file_size": float(file_size),
        "port": float(port),
        "confidence_level": float(confidence_level),
        "hour": float(hour),
        "minute": float(minute),
        "day_of_week": float(day_of_week),
        "is_business_hours": float(is_business_hours),
        "is_weekend": float(is_weekend),
    }

    # Add frequency features
    feature_dict.update({k: float(v) for k, v in freq_features.items()})

    # Add aggregate features
    feature_dict["user_event_count"] = float(user_event_count)
    feature_dict["user_unique_dst_ips"] = float(user_unique_dst_ips)
    feature_dict["user_unique_processes"] = float(user_unique_processes)
    feature_dict["user_success_rate"] = float(user_success_rate)
    feature_dict["hostname_event_count"] = float(hostname_event_count)
    feature_dict["user_hourly_event_rate"] = float(user_hourly_event_rate)
    feature_dict["user_hourly_unique_dst"] = float(user_hourly_unique_dst)
    feature_dict["is_rare_process"] = float(is_rare_process)
    feature_dict["is_rare_event_type"] = float(is_rare_event_type)
    feature_dict["session_event_count"] = float(session_event_count)
    feature_dict["cmd_len"] = float(cmd_len)

    # Build numpy array in exact feature order
    vector = np.array([feature_dict.get(f, 0.0) for f in feature_names], dtype=np.float32)
    return vector.reshape(1, -1)


def predict(event: Dict[str, Any]) -> Tuple[float, float, float, float, bool]:
    """
    Run the full ensemble inference on a single event.
    Returns: (xgb_score, lgb_score, ensemble_score, threshold, is_threat)
    """
    if _artifacts is None:
        raise RuntimeError("Model not loaded.")

    # Feature engineering
    X = engineer_single_event(event)

    # Scale
    scaler = _artifacts["scaler"]
    X_scaled = scaler.transform(X)

    # Isolation Forest score
    iso = _artifacts["iso_forest"]
    iso_score = iso.decision_function(X_scaled).reshape(-1, 1)
    X_aug = np.hstack([X_scaled, iso_score])

    # XGBoost prediction
    xgb_model = _artifacts["xgb_model"]
    xgb_proba = float(xgb_model.predict_proba(X_aug)[0, 1])

    # LightGBM prediction
    lgb_model = _artifacts["lgb_model"]
    lgb_proba = float(lgb_model.predict_proba(X_aug)[0, 1])

    # Ensemble (soft vote)
    ensemble_proba = 0.5 * xgb_proba + 0.5 * lgb_proba

    # Threshold
    threshold = _artifacts["thresholds"]["ensemble"]
    is_threat = ensemble_proba >= threshold

    return xgb_proba, lgb_proba, ensemble_proba, threshold, is_threat


def _safe_float(val, default=0.0) -> float:
    """Safely convert a value to float."""
    try:
        return float(val) if val is not None and val != "" else default
    except (ValueError, TypeError):
        return default
