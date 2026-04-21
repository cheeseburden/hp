"""
export_model.py — Train on 2-day sample and export production artifacts
=========================================================================
Uses the same pipeline as model_builder.py but:
  - Trains on the two-day sample dataset (lighter)
  - Exports all artifacts needed for real-time inference
  - Extracts sample events (normal + attack) with geo-IP for frontend
"""

import json
import os
import sys
import warnings
import time
import glob
import gc
import numpy as np
import pandas as pd
import joblib

from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score,
    precision_recall_curve, roc_auc_score, average_precision_score,
    precision_score, recall_score, accuracy_score, matthews_corrcoef
)
import xgboost as xgb
import lightgbm as lgb

warnings.filterwarnings("ignore")

# ── CONFIG ──────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR,
                        "two_day_sample_cyber_simulator_json_format",
                        "sample_json_20260301")
OUTPUT_DIR = os.path.join(BASE_DIR, "model_output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

RANDOM_STATE = 42
TEST_SIZE = 0.25

KEEP_COLS = [
    "event_type", "user", "hostname", "process_name", "command_line",
    "source_ip", "destination_ip", "department", "location", "device_type",
    "success", "session_id", "service_account", "account", "event_id",
    "parent_process", "prevalence_score", "log_type", "timestamp",
    "protocol", "port", "file_size", "confidence_level", "signed",
    "attack_id", "attack_type", "stage_number"
]

FREQ_COLS = [
    "event_type", "user", "hostname", "process_name", "parent_process",
    "destination_ip", "source_ip", "department", "location", "device_type",
    "log_type", "event_id", "protocol", "command_line", "account"
]

# ── IP → Geo-coordinate mapping (for frontend globe visualization) ────────────
# Maps common private IP prefixes to plausible world cities for demo
GEO_IP_MAP = {
    "10.1.": {"lat": 12.97, "lng": 77.59, "city": "Bangalore"},          # HQ
    "10.2.": {"lat": 40.71, "lng": -74.01, "city": "New York"},           # NYC Office
    "10.3.": {"lat": 37.77, "lng": -122.42, "city": "San Francisco"},     # SF Office
    "10.4.": {"lat": 51.51, "lng": -0.13, "city": "London"},              # London
    "10.5.": {"lat": 35.68, "lng": 139.69, "city": "Tokyo"},              # Tokyo
    "10.6.": {"lat": 48.86, "lng": 2.35, "city": "Paris"},                # Paris
    "10.7.": {"lat": -33.87, "lng": 151.21, "city": "Sydney"},            # Sydney
    "10.8.": {"lat": 1.35, "lng": 103.82, "city": "Singapore"},           # Singapore
    "10.9.": {"lat": 55.75, "lng": 37.62, "city": "Moscow"},              # Moscow
    "10.10.": {"lat": 52.52, "lng": 13.41, "city": "Berlin"},             # Berlin
    "10.0.": {"lat": 19.08, "lng": 72.88, "city": "Mumbai"},              # Mumbai
    "192.168.": {"lat": -23.55, "lng": -46.63, "city": "São Paulo"},      # São Paulo
    "172.16.": {"lat": 25.20, "lng": 55.27, "city": "Dubai"},             # Dubai
}

SERVER_LOCATION = {"lat": 12.97, "lng": 77.59, "city": "Bangalore"}


def ip_to_geo(ip: str) -> dict:
    """Map an IP to a geo-coordinate for visualization."""
    if not ip or ip == "UNKNOWN":
        return {"lat": 0, "lng": 0, "city": "Unknown"}
    for prefix, geo in GEO_IP_MAP.items():
        if ip.startswith(prefix):
            return geo
    # Random fallback for unknown prefixes
    hash_val = hash(ip) % 360
    return {"lat": (hash_val % 180) - 90, "lng": (hash_val % 360) - 180, "city": "Remote"}


# ── 1. DATA LOADING ─────────────────────────────────────────────────────────────
def load_jsonl_files(data_dir: str) -> pd.DataFrame:
    print(f"[1/7] Loading data from {data_dir} ...")
    json_files = sorted(glob.glob(os.path.join(data_dir, "*.json")))
    if not json_files:
        sys.exit(f"ERROR: No .json files found in {data_dir}")

    dfs = []
    total = 0
    for fpath in json_files:
        fname = os.path.basename(fpath)
        records = []
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    records.append({k: row.get(k) for k in KEEP_COLS})
                except json.JSONDecodeError:
                    continue
        chunk_df = pd.DataFrame(records)
        total += len(chunk_df)
        dfs.append(chunk_df)
        print(f"   Loaded {fname} — {len(chunk_df):,} events (total: {total:,})")
        del records
        gc.collect()

    df = pd.concat(dfs, ignore_index=True)
    del dfs
    gc.collect()
    print(f"   Total events loaded: {len(df):,}")
    return df


# ── 2. PREPROCESSING ───────────────────────────────────────────────────────────
def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    print("[2/7] Preprocessing ...")
    df["is_attack"] = df["attack_id"].notna().astype(np.int8)
    attack_n = df["is_attack"].sum()
    normal_n = len(df) - attack_n
    print(f"   Normal events : {normal_n:>10,}")
    print(f"   Attack events : {attack_n:>10,}")
    print(f"   Attack ratio  : {attack_n / len(df) * 100:.4f}%")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df.dropna(subset=["timestamp"], inplace=True)
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    for col in ["success", "service_account", "signed"]:
        if col in df.columns:
            df[col] = df[col].map({"true": 1, "false": 0, True: 1, False: 0})
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(np.int8)

    for col in ["prevalence_score", "file_size", "port", "stage_number",
                "confidence_level"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(np.float32)

    return df


# ── 3. FEATURE ENGINEERING ──────────────────────────────────────────────────────
def engineer_features(df: pd.DataFrame) -> tuple:
    """Returns (df, freq_maps, global_stats) needed for inference."""
    print("[3/7] Feature engineering ...")

    # Temporal
    df["hour"] = df["timestamp"].dt.hour.astype(np.int8)
    df["minute"] = df["timestamp"].dt.minute.astype(np.int8)
    df["day_of_week"] = df["timestamp"].dt.dayofweek.astype(np.int8)
    df["is_business_hours"] = ((df["hour"] >= 8) & (df["hour"] <= 18)).astype(np.int8)
    df["is_weekend"] = (df["day_of_week"] >= 5).astype(np.int8)

    # Frequency encoding — save maps for inference
    freq_maps = {}
    for col in FREQ_COLS:
        if col not in df.columns:
            continue
        df[col] = df[col].fillna("UNKNOWN")
        freq_map = df[col].value_counts(normalize=True).to_dict()
        freq_maps[col] = freq_map
        df[f"{col}_freq"] = df[col].map(freq_map).astype(np.float32)
    gc.collect()

    # Per-user aggregates — save for inference
    print("   Computing per-user aggregates ...")
    user_event_count = df.groupby("user")["hour"].transform("count")
    df["user_event_count"] = user_event_count.fillna(0).astype(np.int32)

    global_stats = {}

    # User event counts
    global_stats["user_cnt"] = df.groupby("user")["hour"].count().to_dict()

    if "destination_ip" in df.columns:
        df["user_unique_dst_ips"] = df.groupby("user")["destination_ip"].transform("nunique").fillna(0).astype(np.int16)
        global_stats["user_unique_dst"] = df.groupby("user")["destination_ip"].nunique().to_dict()
    else:
        df["user_unique_dst_ips"] = np.int16(0)
        global_stats["user_unique_dst"] = {}

    if "process_name" in df.columns:
        df["user_unique_processes"] = df.groupby("user")["process_name"].transform("nunique").fillna(0).astype(np.int16)
        global_stats["user_unique_proc"] = df.groupby("user")["process_name"].nunique().to_dict()
    else:
        df["user_unique_processes"] = np.int16(0)
        global_stats["user_unique_proc"] = {}

    if "success" in df.columns:
        df["user_success_rate"] = df.groupby("user")["success"].transform("mean").fillna(0).astype(np.float32)
        global_stats["user_suc_rate"] = df.groupby("user")["success"].mean().to_dict()
    else:
        df["user_success_rate"] = np.float32(1.0)
        global_stats["user_suc_rate"] = {}

    df["hostname_event_count"] = df.groupby("hostname")["hour"].transform("count").fillna(0).astype(np.int32)
    global_stats["host_cnt"] = df.groupby("hostname")["hour"].count().to_dict()
    gc.collect()

    # Sliding-window features
    print("   Computing sliding-window features ...")
    df["hour_bucket"] = df["timestamp"].dt.floor("h")
    df["user_hourly_event_rate"] = df.groupby(["user", "hour_bucket"])["hour"].transform("count").fillna(0).astype(np.int16)

    # Store per (user, hour_bucket) counts
    uh_counts = df.groupby(["user", "hour_bucket"])["hour"].count()
    global_stats["uh_cnt"] = {f"{u}||{str(h)}": int(v) for (u, h), v in uh_counts.items()}

    if "destination_ip" in df.columns:
        df["user_hourly_unique_dst"] = df.groupby(["user", "hour_bucket"])["destination_ip"].transform("nunique").fillna(0).astype(np.int16)
        uh_dst = df.groupby(["user", "hour_bucket"])["destination_ip"].nunique()
        global_stats["uh_unique_dst"] = {f"{u}||{str(h)}": int(v) for (u, h), v in uh_dst.items()}
    else:
        df["user_hourly_unique_dst"] = np.int16(0)
        global_stats["uh_unique_dst"] = {}
    gc.collect()

    # Rare-event indicators
    if "process_name" in df.columns:
        proc_counts = df["process_name"].value_counts()
        rare_threshold = proc_counts.quantile(0.05)
        df["is_rare_process"] = (df["process_name"].map(proc_counts) <= rare_threshold).astype(np.int8)
        global_stats["rare_proc_thr"] = float(rare_threshold)
    else:
        df["is_rare_process"] = np.int8(0)
        global_stats["rare_proc_thr"] = 0

    if "event_type" in df.columns:
        et_counts = df["event_type"].value_counts()
        rare_threshold_et = et_counts.quantile(0.05)
        df["is_rare_event_type"] = (df["event_type"].map(et_counts) <= rare_threshold_et).astype(np.int8)
        global_stats["rare_et_thr"] = float(rare_threshold_et)
    else:
        df["is_rare_event_type"] = np.int8(0)
        global_stats["rare_et_thr"] = 0

    # Session-level
    if "session_id" in df.columns:
        df["session_event_count"] = df.groupby("session_id")["hour"].transform("count").fillna(0).astype(np.int32)
        global_stats["sess_cnt"] = df.groupby("session_id")["hour"].count().to_dict()
    else:
        df["session_event_count"] = np.int32(0)
        global_stats["sess_cnt"] = {}

    # Command-line length
    if "command_line" in df.columns:
        df["cmd_len"] = df["command_line"].fillna("").str.len().fillna(0).astype(np.int16)
    else:
        df["cmd_len"] = np.int16(0)

    gc.collect()
    return df, freq_maps, global_stats


# ── 4. FEATURE SELECTION & SPLIT ────────────────────────────────────────────────
def prepare_model_data(df: pd.DataFrame):
    print("[4/7] Selecting features and splitting data ...")

    cols_to_drop = [
        "is_attack", "attack_id", "attack_type", "stage_number",
        "timestamp", "hour_bucket",
        "event_type", "user", "hostname", "process_name",
        "parent_process", "destination_ip", "source_ip",
        "department", "location", "device_type", "log_type",
        "event_id", "protocol", "command_line", "account",
        "session_id",
    ]

    y = df["is_attack"].values.astype(np.int8)
    X = df.drop(columns=[c for c in cols_to_drop if c in df.columns], errors="ignore")

    obj_cols = X.select_dtypes(include=["object"]).columns.tolist()
    if obj_cols:
        print(f"   Dropping non-numeric columns: {obj_cols}")
        X.drop(columns=obj_cols, inplace=True)

    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X.fillna(0, inplace=True)

    feature_names = list(X.columns)
    print(f"   Selected {len(feature_names)} features")

    # Chronological split
    split_idx = int(len(X) * (1 - TEST_SIZE))
    X_train, X_test = X.iloc[:split_idx].values, X.iloc[split_idx:].values
    y_train, y_test = y[:split_idx], y[split_idx:]

    print(f"   Train: {len(X_train):,}  |  Test: {len(X_test):,}")
    print(f"   Train attacks: {y_train.sum():,}  |  Test attacks: {y_test.sum():,}")

    del X
    gc.collect()

    print("   Scaling features ...")
    scaler = RobustScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    return X_train, X_test, y_train, y_test, feature_names, scaler


# ── 5. ISOLATION FOREST ─────────────────────────────────────────────────────────
def add_isolation_forest_scores(X_train, X_test):
    print("[5/7] Adding Isolation Forest anomaly scores ...")
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.005,
        max_samples=min(100000, len(X_train)),
        random_state=RANDOM_STATE,
        n_jobs=-1
    )
    iso.fit(X_train)
    train_scores = iso.decision_function(X_train).reshape(-1, 1)
    test_scores = iso.decision_function(X_test).reshape(-1, 1)

    X_train_aug = np.hstack([X_train, train_scores])
    X_test_aug = np.hstack([X_test, test_scores])
    del train_scores, test_scores
    gc.collect()
    return X_train_aug, X_test_aug, iso


# ── 6. TRAIN ENSEMBLE ──────────────────────────────────────────────────────────
def train_ensemble(X_train, y_train, X_test, y_test, feature_names):
    print("[6/7] Training ensemble models ...")

    pos = int(y_train.sum())
    neg = len(y_train) - pos
    scale_pos = neg / max(pos, 1)
    print(f"   scale_pos_weight = {scale_pos:.1f}")

    aug_feature_names = feature_names + ["iso_forest_score"]

    # XGBoost (CPU mode for portability)
    print("   Training XGBoost ...")
    xgb_clf = xgb.XGBClassifier(
        n_estimators=500,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos,
        eval_metric="aucpr",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        tree_method="hist",
    )
    xgb_clf.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

    # LightGBM (fixed: is_unbalance=True, CPU mode)
    print("   Training LightGBM ...")
    lgb_clf = lgb.LGBMClassifier(
        n_estimators=500,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        is_unbalance=True,
        min_child_samples=50,
        metric="average_precision",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbose=-1,
    )
    lgb_clf.fit(X_train, y_train, eval_set=[(X_test, y_test)])

    # Predictions
    xgb_proba = xgb_clf.predict_proba(X_test)[:, 1]
    lgb_proba = lgb_clf.predict_proba(X_test)[:, 1]
    ensemble_proba = 0.5 * xgb_proba + 0.5 * lgb_proba

    return xgb_clf, lgb_clf, xgb_proba, lgb_proba, ensemble_proba, aug_feature_names


# ── 7. THRESHOLD OPTIMIZATION ──────────────────────────────────────────────────
def optimize_threshold(y_test, proba, name="Ensemble"):
    precision, recall, thresholds = precision_recall_curve(y_test, proba)
    f1_scores = 2 * precision * recall / (precision + recall + 1e-8)
    best_idx = np.argmax(f1_scores)
    best_threshold = thresholds[best_idx] if best_idx < len(thresholds) else 0.5
    best_f1 = f1_scores[best_idx]
    print(f"   [{name}] Best F1 = {best_f1:.4f} at threshold = {best_threshold:.4f}")
    return best_threshold, best_f1


# ── 8. EXTRACT SAMPLE EVENTS ──────────────────────────────────────────────────
def extract_sample_events(data_dir: str, max_normal=200, max_attack=50):
    """Extract real events from the dataset with geo-IP for frontend demo."""
    print("[7/7] Extracting sample events for frontend ...")
    json_files = sorted(glob.glob(os.path.join(data_dir, "*.json")))

    normal_events = []
    attack_events = []

    for fpath in json_files:
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Enrich with geo data
                src_ip = row.get("source_ip", "")
                dst_ip = row.get("destination_ip", "")
                src_geo = ip_to_geo(src_ip)
                dst_geo = ip_to_geo(dst_ip)

                event = {
                    "event_type": row.get("event_type", "unknown"),
                    "user": row.get("user", "unknown"),
                    "hostname": row.get("hostname", ""),
                    "process_name": row.get("process_name", ""),
                    "command_line": row.get("command_line", ""),
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "department": row.get("department", ""),
                    "location": row.get("location", ""),
                    "device_type": row.get("device_type", ""),
                    "protocol": row.get("protocol", ""),
                    "port": row.get("port", ""),
                    "timestamp": row.get("timestamp", ""),
                    "success": row.get("success", ""),
                    "log_type": row.get("log_type", ""),
                    "attack_id": row.get("attack_id"),
                    "attack_type": row.get("attack_type"),
                    "source_geo": src_geo,
                    "destination_geo": dst_geo,
                    "is_attack": row.get("attack_id") is not None,
                }

                if event["is_attack"] and len(attack_events) < max_attack:
                    attack_events.append(event)
                elif not event["is_attack"] and len(normal_events) < max_normal:
                    normal_events.append(event)

                if len(normal_events) >= max_normal and len(attack_events) >= max_attack:
                    break
        if len(normal_events) >= max_normal and len(attack_events) >= max_attack:
            break

    print(f"   Extracted {len(normal_events)} normal + {len(attack_events)} attack events")
    return {"normal": normal_events, "attack": attack_events, "server": SERVER_LOCATION}


# ── MAIN ────────────────────────────────────────────────────────────────────────
def main():
    t0 = time.time()

    # Load and process
    df = load_jsonl_files(DATA_DIR)
    df = preprocess(df)
    df, freq_maps, global_stats = engineer_features(df)

    X_train, X_test, y_train, y_test, feature_names, scaler = prepare_model_data(df)
    del df
    gc.collect()

    X_train, X_test, iso_forest = add_isolation_forest_scores(X_train, X_test)

    xgb_clf, lgb_clf, xgb_proba, lgb_proba, ens_proba, aug_feats = \
        train_ensemble(X_train, y_train, X_test, y_test, feature_names)

    # Optimize thresholds
    xgb_thr, xgb_f1 = optimize_threshold(y_test, xgb_proba, "XGBoost")
    lgb_thr, lgb_f1 = optimize_threshold(y_test, lgb_proba, "LightGBM")
    ens_thr, ens_f1 = optimize_threshold(y_test, ens_proba, "Ensemble")

    # Evaluate ensemble
    y_pred = (ens_proba >= ens_thr).astype(int)
    print(f"\n{'='*60}")
    print("   Ensemble Evaluation")
    print(f"{'='*60}")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"], zero_division=0))

    # ── Save artifacts ──
    print("\nSaving production artifacts ...")
    artifacts = {
        "xgb_model": xgb_clf,
        "lgb_model": lgb_clf,
        "iso_forest": iso_forest,
        "scaler": scaler,
        "feature_names": feature_names,
        "aug_feature_names": aug_feats,
        "freq_maps": freq_maps,
        "global_stats": global_stats,
        "thresholds": {
            "xgboost": float(xgb_thr),
            "lightgbm": float(lgb_thr),
            "ensemble": float(ens_thr),
        },
        "metrics": {
            "xgboost_f1": float(xgb_f1),
            "lightgbm_f1": float(lgb_f1),
            "ensemble_f1": float(ens_f1),
        },
        "freq_cols": FREQ_COLS,
        "keep_cols": KEEP_COLS,
    }

    artifacts_path = os.path.join(OUTPUT_DIR, "pipeline_artifacts.joblib")
    joblib.dump(artifacts, artifacts_path, compress=3)
    print(f"   Saved pipeline_artifacts.joblib ({os.path.getsize(artifacts_path) / 1024 / 1024:.1f} MB)")

    # Extract sample events
    sample_events = extract_sample_events(DATA_DIR)
    sample_path = os.path.join(OUTPUT_DIR, "sample_events.json")
    with open(sample_path, "w", encoding="utf-8") as f:
        json.dump(sample_events, f, indent=2, default=str)
    print(f"   Saved sample_events.json ({os.path.getsize(sample_path) / 1024:.1f} KB)")

    elapsed = time.time() - t0
    print(f"\n[OK] Export completed in {elapsed:.1f}s")
    print(f"   Artifacts: {artifacts_path}")
    print(f"   Samples:   {sample_path}")


if __name__ == "__main__":
    main()
