"""
model_builder.py — Anomaly Detection Pipeline for Cyber Simulator Logs
=======================================================================
SOTA ensemble approach using XGBoost, LightGBM, and Isolation Forest
with extensive behavioral feature engineering.
Memory-efficient: loads data file-by-file via chunked DataFrames.
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

from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score,
    precision_recall_curve, roc_auc_score, average_precision_score,
    roc_curve, precision_score, recall_score, accuracy_score,
    matthews_corrcoef
)
import xgboost as xgb
import lightgbm as lgb
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

warnings.filterwarnings("ignore")

# ── CONFIG ──────────────────────────────────────────────────────────────────────
DATA_DIR = os.path.join(os.path.dirname(__file__),
                        "cyber_simulator_json_format",
                        "full_json_20260301")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "model_output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

RANDOM_STATE = 42
TEST_SIZE = 0.25

# Only keep columns we actually need to minimise memory
KEEP_COLS = [
    "event_type", "user", "hostname", "process_name", "command_line",
    "source_ip", "destination_ip", "department", "location", "device_type",
    "success", "session_id", "service_account", "account", "event_id",
    "parent_process", "prevalence_score", "log_type", "timestamp",
    "protocol", "port", "file_size", "confidence_level", "signed",
    "attack_id", "attack_type", "stage_number"
]

# ── 1. DATA LOADING (memory-efficient) ─────────────────────────────────────────
def load_jsonl_files(data_dir: str) -> pd.DataFrame:
    """Load all .json (JSON-Lines) files, one file at a time into DataFrames."""
    print(f"[1/6] Loading data from {data_dir} ...")
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
                    # Only keep relevant columns
                    records.append({k: row.get(k) for k in KEEP_COLS})
                except json.JSONDecodeError:
                    continue
        chunk_df = pd.DataFrame(records)
        total += len(chunk_df)
        dfs.append(chunk_df)
        print(f"   Loaded {fname} — {len(chunk_df):,} events (total: {total:,})")
        del records
        gc.collect()

    print(f"   Concatenating {len(dfs)} DataFrames ...")
    df = pd.concat(dfs, ignore_index=True)
    del dfs
    gc.collect()
    print(f"   Total events loaded: {len(df):,}")
    return df

# ── 2. PREPROCESSING ───────────────────────────────────────────────────────────
def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    """Clean data and create the binary label."""
    print("[2/6] Preprocessing ...")

    # Label: is_attack
    df["is_attack"] = df["attack_id"].notna().astype(np.int8)
    attack_n = df["is_attack"].sum()
    normal_n = len(df) - attack_n
    print(f"   Normal events : {normal_n:>10,}")
    print(f"   Attack events : {attack_n:>10,}")
    print(f"   Attack ratio  : {attack_n / len(df) * 100:.4f}%")

    # Timestamp parsing
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df.dropna(subset=["timestamp"], inplace=True)
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    # Boolean fields
    for col in ["success", "service_account", "signed"]:
        if col in df.columns:
            df[col] = df[col].map({"true": 1, "false": 0, True: 1, False: 0})
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(np.int8)

    # Numeric fields
    for col in ["prevalence_score", "file_size", "port", "stage_number",
                "confidence_level"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(np.float32)

    return df

# ── 3. FEATURE ENGINEERING ──────────────────────────────────────────────────────
def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Create behavioural features that capture entity-level anomalies."""
    print("[3/6] Feature engineering ...")

    # 3a. Temporal features
    df["hour"] = df["timestamp"].dt.hour.astype(np.int8)
    df["minute"] = df["timestamp"].dt.minute.astype(np.int8)
    df["day_of_week"] = df["timestamp"].dt.dayofweek.astype(np.int8)
    df["is_business_hours"] = ((df["hour"] >= 8) & (df["hour"] <= 18)).astype(np.int8)
    df["is_weekend"] = (df["day_of_week"] >= 5).astype(np.int8)

    # 3b. Frequency encoding for high-cardinality categoricals
    freq_encode_cols = [
        "event_type", "user", "hostname", "process_name",
        "parent_process", "destination_ip", "source_ip",
        "department", "location", "device_type", "log_type",
        "event_id", "protocol", "command_line", "account"
    ]
    for col in freq_encode_cols:
        if col not in df.columns:
            continue
        df[col] = df[col].fillna("UNKNOWN")
        freq_map = df[col].value_counts(normalize=True).to_dict()
        df[f"{col}_freq"] = df[col].map(freq_map).astype(np.float32)
    gc.collect()

    # 3c. Behavioural / Aggregation features
    print("   Computing per-user aggregates ...")
    user_event_count = df.groupby("user")["hour"].transform("count")
    df["user_event_count"] = user_event_count.fillna(0).astype(np.int32)

    if "destination_ip" in df.columns:
        df["user_unique_dst_ips"] = df.groupby("user")["destination_ip"].transform("nunique").fillna(0).astype(np.int16)
    else:
        df["user_unique_dst_ips"] = np.int16(0)

    if "process_name" in df.columns:
        df["user_unique_processes"] = df.groupby("user")["process_name"].transform("nunique").fillna(0).astype(np.int16)
    else:
        df["user_unique_processes"] = np.int16(0)

    if "success" in df.columns:
        df["user_success_rate"] = df.groupby("user")["success"].transform("mean").fillna(0).astype(np.float32)
    else:
        df["user_success_rate"] = np.float32(1.0)

    df["hostname_event_count"] = df.groupby("hostname")["hour"].transform("count").fillna(0).astype(np.int32)
    gc.collect()

    # 3d. Sliding-window features (per-user per-hour)
    print("   Computing sliding-window features ...")
    df["hour_bucket"] = df["timestamp"].dt.floor("h")
    df["user_hourly_event_rate"] = df.groupby(["user", "hour_bucket"])["hour"].transform("count").fillna(0).astype(np.int16)

    if "destination_ip" in df.columns:
        df["user_hourly_unique_dst"] = df.groupby(["user", "hour_bucket"])["destination_ip"].transform("nunique").fillna(0).astype(np.int16)
    else:
        df["user_hourly_unique_dst"] = np.int16(0)
    gc.collect()

    # 3e. Rare-event indicators
    if "process_name" in df.columns:
        proc_counts = df["process_name"].value_counts()
        rare_threshold = proc_counts.quantile(0.05)
        df["is_rare_process"] = (df["process_name"].map(proc_counts) <= rare_threshold).astype(np.int8)
    else:
        df["is_rare_process"] = np.int8(0)

    if "event_type" in df.columns:
        et_counts = df["event_type"].value_counts()
        rare_threshold_et = et_counts.quantile(0.05)
        df["is_rare_event_type"] = (df["event_type"].map(et_counts) <= rare_threshold_et).astype(np.int8)
    else:
        df["is_rare_event_type"] = np.int8(0)

    # 3f. Session-level features
    if "session_id" in df.columns:
        df["session_event_count"] = df.groupby("session_id")["hour"].transform("count").fillna(0).astype(np.int32)
    else:
        df["session_event_count"] = np.int32(0)

    # 3g. Command-line length
    if "command_line" in df.columns:
        df["cmd_len"] = df["command_line"].fillna("").str.len().fillna(0).astype(np.int16)
    else:
        df["cmd_len"] = np.int16(0)

    gc.collect()
    return df

# ── 4. FEATURE SELECTION & SPLIT ────────────────────────────────────────────────
def prepare_model_data(df: pd.DataFrame):
    """Select numeric features and split into train/test."""
    print("[4/6] Selecting features and splitting data ...")

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

    # Drop any remaining object columns
    obj_cols = X.select_dtypes(include=["object"]).columns.tolist()
    if obj_cols:
        print(f"   Dropping non-numeric columns: {obj_cols}")
        X.drop(columns=obj_cols, inplace=True)

    # Coerce and fill
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X.fillna(0, inplace=True)

    feature_names = list(X.columns)
    print(f"   Selected {len(feature_names)} features: {feature_names[:10]}{'...' if len(feature_names) > 10 else ''}")

    # Chronological split
    split_idx = int(len(X) * (1 - TEST_SIZE))
    X_train, X_test = X.iloc[:split_idx].values, X.iloc[split_idx:].values
    y_train, y_test = y[:split_idx], y[split_idx:]

    print(f"   Train: {len(X_train):,}  |  Test: {len(X_test):,}")
    print(f"   Train attacks: {y_train.sum():,}  |  Test attacks: {y_test.sum():,}")

    # Free the DataFrame
    del df, X
    gc.collect()

    # Scale features
    print("   Scaling features ...")
    scaler = RobustScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    return X_train, X_test, y_train, y_test, feature_names, scaler

# ── 5. ISOLATION FOREST SCORES ─────────────────────────────────────────────────
def add_isolation_forest_scores(X_train, X_test):
    """Fit an Isolation Forest and append its anomaly scores as an extra feature."""
    print("   Adding Isolation Forest anomaly scores ...")
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.005,
        max_samples=min(100000, len(X_train)),   # subsample for speed
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
    return X_train_aug, X_test_aug

# ── 6. MODEL TRAINING & ENSEMBLE ───────────────────────────────────────────────
def train_ensemble(X_train, y_train, X_test, y_test, feature_names):
    """Train XGBoost, LightGBM, and combine via Soft Voting."""
    print("[5/6] Training ensemble models ...")

    pos = int(y_train.sum())
    neg = len(y_train) - pos
    scale_pos = neg / max(pos, 1)
    print(f"   scale_pos_weight = {scale_pos:.1f}")

    aug_feature_names = feature_names + ["iso_forest_score"]

    # XGBoost
    print("   Training XGBoost ...")
    xgb_clf = xgb.XGBClassifier(
        n_estimators=500,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos,
        eval_metric="aucpr",
        use_label_encoder=False,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        tree_method="hist",
        device="cuda"
    )
    xgb_clf.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

    # LightGBM
    print("   Training LightGBM ...")
    lgb_clf = lgb.LGBMClassifier(
        n_estimators=500,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos,
        metric="average_precision",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbose=-1,
        device="gpu"
    )
    lgb_clf.fit(X_train, y_train, eval_set=[(X_test, y_test)])

    # Predictions
    xgb_proba = xgb_clf.predict_proba(X_test)[:, 1]
    lgb_proba = lgb_clf.predict_proba(X_test)[:, 1]

    # Soft-vote ensemble
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

# ── 8. EVALUATION ───────────────────────────────────────────────────────────────
def evaluate(y_test, proba, threshold, name="Ensemble"):
    y_pred = (proba >= threshold).astype(int)

    print(f"\n{'='*60}")
    print(f"   {name} — Evaluation Results")
    print(f"{'='*60}")

    acc   = accuracy_score(y_test, y_pred)
    prec  = precision_score(y_test, y_pred, zero_division=0)
    rec   = recall_score(y_test, y_pred, zero_division=0)
    f1    = f1_score(y_test, y_pred, zero_division=0)
    mcc   = matthews_corrcoef(y_test, y_pred)

    try:
        roc_auc = roc_auc_score(y_test, proba)
    except ValueError:
        roc_auc = 0.0
    try:
        pr_auc  = average_precision_score(y_test, proba)
    except ValueError:
        pr_auc = 0.0

    print(f"   Threshold      : {threshold:.4f}")
    print(f"   Accuracy       : {acc:.4f}")
    print(f"   Precision      : {prec:.4f}")
    print(f"   Recall         : {rec:.4f}")
    print(f"   F1-Score       : {f1:.4f}")
    print(f"   MCC            : {mcc:.4f}")
    print(f"   ROC-AUC        : {roc_auc:.4f}")
    print(f"   PR-AUC (AP)    : {pr_auc:.4f}")

    print("\n   Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"],
                                zero_division=0))

    cm = confusion_matrix(y_test, y_pred)
    return {
        "name": name, "threshold": threshold,
        "accuracy": acc, "precision": prec, "recall": rec,
        "f1": f1, "mcc": mcc, "roc_auc": roc_auc, "pr_auc": pr_auc,
        "confusion_matrix": cm, "y_pred": y_pred
    }

# ── 9. PLOTS ────────────────────────────────────────────────────────────────────
def plot_results(y_test, results_list, feature_names, xgb_clf, lgb_clf):
    print("[6/6] Generating plots ...")

    # Confusion Matrices
    fig, axes = plt.subplots(1, len(results_list), figsize=(6 * len(results_list), 5))
    if len(results_list) == 1:
        axes = [axes]
    for ax, res in zip(axes, results_list):
        sns.heatmap(res["confusion_matrix"], annot=True, fmt="d", cmap="Blues",
                    xticklabels=["Normal", "Attack"],
                    yticklabels=["Normal", "Attack"], ax=ax)
        ax.set_title(f"{res['name']}\nF1={res['f1']:.4f}  PR-AUC={res['pr_auc']:.4f}")
        ax.set_ylabel("True")
        ax.set_xlabel("Predicted")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "confusion_matrices.png"), dpi=150)
    plt.close()

    # ROC Curves
    plt.figure(figsize=(8, 6))
    for res in results_list:
        proba = res.get("proba")
        if proba is not None:
            fpr, tpr, _ = roc_curve(y_test, proba)
            plt.plot(fpr, tpr, label=f"{res['name']} (AUC={res['roc_auc']:.4f})")
    plt.plot([0, 1], [0, 1], "k--", alpha=0.5)
    plt.xlabel("False Positive Rate"); plt.ylabel("True Positive Rate")
    plt.title("ROC Curves"); plt.legend(); plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "roc_curves.png"), dpi=150)
    plt.close()

    # Precision-Recall Curves
    plt.figure(figsize=(8, 6))
    for res in results_list:
        proba = res.get("proba")
        if proba is not None:
            prec, rec, _ = precision_recall_curve(y_test, proba)
            plt.plot(rec, prec, label=f"{res['name']} (AP={res['pr_auc']:.4f})")
    plt.xlabel("Recall"); plt.ylabel("Precision")
    plt.title("Precision–Recall Curves"); plt.legend(); plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "precision_recall_curves.png"), dpi=150)
    plt.close()

    # Feature Importance (XGBoost)
    try:
        xgb_imp = xgb_clf.feature_importances_
        feat_imp_df = pd.DataFrame({
            "feature": feature_names, "importance": xgb_imp
        }).sort_values("importance", ascending=False).head(20)
        plt.figure(figsize=(10, 6))
        sns.barplot(data=feat_imp_df, x="importance", y="feature", palette="viridis")
        plt.title("Top 20 Feature Importances (XGBoost)")
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, "feature_importance.png"), dpi=150)
        plt.close()
    except Exception as e:
        print(f"   Could not plot feature importance: {e}")

    print(f"   All plots saved to {OUTPUT_DIR}")

# ── MAIN ────────────────────────────────────────────────────────────────────────
def main():
    t0 = time.time()

    df = load_jsonl_files(DATA_DIR)
    df = preprocess(df)
    df = engineer_features(df)

    X_train, X_test, y_train, y_test, feature_names, scaler = prepare_model_data(df)

    X_train, X_test = add_isolation_forest_scores(X_train, X_test)

    xgb_clf, lgb_clf, xgb_proba, lgb_proba, ens_proba, aug_feats = \
        train_ensemble(X_train, y_train, X_test, y_test, feature_names)

    xgb_thr, _ = optimize_threshold(y_test, xgb_proba, "XGBoost")
    lgb_thr, _ = optimize_threshold(y_test, lgb_proba, "LightGBM")
    ens_thr, _ = optimize_threshold(y_test, ens_proba, "Ensemble")

    results = []
    for proba, thr, name in [
        (xgb_proba, xgb_thr, "XGBoost"),
        (lgb_proba, lgb_thr, "LightGBM"),
        (ens_proba, ens_thr, "Ensemble")
    ]:
        res = evaluate(y_test, proba, thr, name)
        res["proba"] = proba
        results.append(res)

    plot_results(y_test, results, aug_feats, xgb_clf, lgb_clf)

    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    summary_df = pd.DataFrame([{
        "Model": r["name"],
        "Threshold": f"{r['threshold']:.4f}",
        "Accuracy": f"{r['accuracy']:.4f}",
        "Precision": f"{r['precision']:.4f}",
        "Recall": f"{r['recall']:.4f}",
        "F1": f"{r['f1']:.4f}",
        "MCC": f"{r['mcc']:.4f}",
        "ROC-AUC": f"{r['roc_auc']:.4f}",
        "PR-AUC": f"{r['pr_auc']:.4f}",
    } for r in results])
    print(summary_df.to_string(index=False))

    summary_path = os.path.join(OUTPUT_DIR, "summary.csv")
    summary_df.to_csv(summary_path, index=False)
    print(f"\nSaved summary → {summary_path}")

    elapsed = time.time() - t0
    print(f"\n✅ Pipeline completed in {elapsed:.1f}s")


if __name__ == "__main__":
    main()
