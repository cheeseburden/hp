# ============================================================================
# model_builder_colab.py  —  Memory-Efficient Colab Version (Two-Pass)
# ============================================================================
# USAGE:
#   1. Upload dataset to Drive:  My Drive/HPE/cyber_simulator_json_format/full_json_20260301/
#   2. Paste this entire file into ONE Colab cell and run.
#   3. Recommended: Runtime → Change runtime type → T4 GPU + High-RAM
# ============================================================================

# ── STEP 0: INSTALL & MOUNT ────────────────────────────────────────────────────
import subprocess, sys
def _install(p):
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", p])
_install("xgboost"); _install("lightgbm")

from google.colab import drive
drive.mount("/content/drive")

# ── IMPORTS ─────────────────────────────────────────────────────────────────────
import json, os, warnings, time, glob, gc, shutil
import numpy as np
import pandas as pd
import psutil
from collections import Counter, defaultdict
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
import matplotlib.pyplot as plt
import seaborn as sns
from IPython.display import display

plt.rcParams["figure.dpi"] = 120
warnings.filterwarnings("ignore")

# ── CONFIG ──────────────────────────────────────────────────────────────────────
DRIVE_DATA_DIR = "/content/drive/MyDrive/HPE/DATASET/cyber_simulator_json_format/full_json_20260301"
CHUNK_DIR      = "/content/feature_chunks"   # temp dir on local Colab disk
RANDOM_STATE   = 42
TEST_SIZE      = 0.25

KEEP_COLS = [
    "event_type","user","hostname","process_name","command_line",
    "source_ip","destination_ip","department","location","device_type",
    "success","session_id","service_account","account","event_id",
    "parent_process","prevalence_score","log_type","timestamp",
    "protocol","port","file_size","confidence_level","signed",
    "attack_id","attack_type","stage_number"
]

FREQ_COLS = [
    "event_type","user","hostname","process_name","parent_process",
    "destination_ip","source_ip","department","location","device_type",
    "log_type","event_id","protocol","command_line","account"
]

def mem_gb():
    return psutil.Process().memory_info().rss / 1024**3

# ── HELPER: load one file ───────────────────────────────────────────────────────
def load_one(fpath):
    records = []
    with open(fpath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                row = json.loads(line)
                records.append({k: row.get(k) for k in KEEP_COLS})
            except json.JSONDecodeError:
                continue
    return pd.DataFrame(records)

# ═══════════════════════════════════════════════════════════════════════════════
# PASS 1 — Stream through all files, gather global statistics (low memory)
# ═══════════════════════════════════════════════════════════════════════════════
def pass1(data_dir):
    print("=" * 65)
    print("PASS 1 / 3 — Gathering global statistics")
    print("=" * 65)
    files = sorted(glob.glob(os.path.join(data_dir, "*.json")))
    assert files, f"No .json files in {data_dir}"

    freq_ctr    = {c: Counter() for c in FREQ_COLS}
    user_cnt    = Counter()
    host_cnt    = Counter()
    sess_cnt    = Counter()
    user_dst    = defaultdict(set)
    user_proc   = defaultdict(set)
    user_suc_s  = defaultdict(float)
    user_suc_n  = Counter()
    uh_cnt      = Counter()          # (user, hour_bucket) → count
    uh_dst      = defaultdict(set)   # (user, hour_bucket) → set of dst ips
    total = 0

    for i, fp in enumerate(files, 1):
        df = load_one(fp)
        n = len(df)
        total += n
        print(f"  [{i}/{len(files)}] {os.path.basename(fp)}: {n:,}  (total {total:,})  💾{mem_gb():.1f}GB")

        # freq counts
        for c in FREQ_COLS:
            if c in df.columns:
                freq_ctr[c].update(df[c].fillna("UNKNOWN").values)

        # per-user
        for u, cnt in df["user"].fillna("UNKNOWN").value_counts().items():
            user_cnt[u] += cnt
        # per-hostname
        for h, cnt in df["hostname"].fillna("UNKNOWN").value_counts().items():
            host_cnt[h] += cnt
        # per-session
        if "session_id" in df.columns:
            for s, cnt in df["session_id"].dropna().value_counts().items():
                sess_cnt[s] += cnt

        # unique dst ips & processes per user  (groupby → unique sets)
        u_col = df["user"].fillna("UNKNOWN")
        if "destination_ip" in df.columns:
            dst_col = df["destination_ip"].fillna("UNKNOWN")
            for u, d in zip(u_col.values, dst_col.values):
                user_dst[u].add(d)
        if "process_name" in df.columns:
            proc_col = df["process_name"].fillna("UNKNOWN")
            for u, p in zip(u_col.values, proc_col.values):
                user_proc[u].add(p)

        # success rate per user
        if "success" in df.columns:
            suc = df["success"].map({"true":1,"false":0,True:1,False:0})
            suc = pd.to_numeric(suc, errors="coerce").fillna(0)
            for u, s in zip(u_col.values, suc.values):
                user_suc_s[u] += s
                user_suc_n[u] += 1

        # per (user, hour_bucket)
        ts = pd.to_datetime(df["timestamp"], errors="coerce")
        mask = ts.notna()
        if mask.any():
            hb = ts[mask].dt.floor("h").astype(str).values
            us = u_col[mask].values
            dst_vals = dst_col[mask].values if "destination_ip" in df.columns else None
            for j in range(len(hb)):
                key = (us[j], hb[j])
                uh_cnt[key] += 1
                if dst_vals is not None:
                    uh_dst[key].add(dst_vals[j])

        del df; gc.collect()

    # ── Derive final stats ──
    # normalised freq maps
    freq_maps = {}
    for c in FREQ_COLS:
        t = sum(freq_ctr[c].values())
        freq_maps[c] = {k: v/t for k,v in freq_ctr[c].items()} if t else {}
    del freq_ctr

    # rare thresholds
    pc = Counter({k: v for k, v in freq_maps.get("process_name", {}).items()})
    if pc:
        vals = sorted(pc.values())
        rare_proc_thr = np.percentile(vals, 5)
    else:
        rare_proc_thr = 0
    ec = Counter({k: v for k, v in freq_maps.get("event_type", {}).items()})
    if ec:
        vals = sorted(ec.values())
        rare_et_thr = np.percentile(vals, 5)
    else:
        rare_et_thr = 0

    stats = dict(
        freq_maps=freq_maps,
        user_cnt=dict(user_cnt),
        host_cnt=dict(host_cnt),
        sess_cnt=dict(sess_cnt),
        user_unique_dst={u: len(s) for u,s in user_dst.items()},
        user_unique_proc={u: len(s) for u,s in user_proc.items()},
        user_suc_rate={u: user_suc_s[u]/user_suc_n[u] for u in user_suc_n},
        uh_cnt=dict(uh_cnt),
        uh_unique_dst={k: len(s) for k,s in uh_dst.items()},
        rare_proc_thr=rare_proc_thr,
        rare_et_thr=rare_et_thr,
    )
    del user_dst, user_proc, uh_dst; gc.collect()
    print(f"✅ Pass 1 done. Total events: {total:,}  💾{mem_gb():.1f}GB\n")
    return stats

# ═══════════════════════════════════════════════════════════════════════════════
# PASS 2 — Build features file-by-file, save numeric chunks to disk
# ═══════════════════════════════════════════════════════════════════════════════
def pass2(data_dir, stats):
    print("=" * 65)
    print("PASS 2 / 3 — Building features (file by file → disk)")
    print("=" * 65)

    if os.path.exists(CHUNK_DIR):
        shutil.rmtree(CHUNK_DIR)
    os.makedirs(CHUNK_DIR)

    files = sorted(glob.glob(os.path.join(data_dir, "*.json")))
    fm = stats["freq_maps"]

    for i, fp in enumerate(files, 1):
        df = load_one(fp)
        fname = os.path.basename(fp)

        # — label
        df["is_attack"] = df["attack_id"].notna().astype(np.int8)

        # — timestamp
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df.dropna(subset=["timestamp"], inplace=True)
        df.sort_values("timestamp", inplace=True)
        df.reset_index(drop=True, inplace=True)

        # — booleans
        for c in ["success", "service_account", "signed"]:
            if c in df.columns:
                df[c] = df[c].map({"true":1,"false":0,True:1,False:0})
                df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(np.float32)
            else:
                df[c] = np.float32(0)

        # — numerics
        for c in ["prevalence_score","file_size","port","confidence_level"]:
            if c in df.columns:
                df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(np.float32)
            else:
                df[c] = np.float32(0)

        # — temporal
        df["hour"] = df["timestamp"].dt.hour.astype(np.float32)
        df["minute"] = df["timestamp"].dt.minute.astype(np.float32)
        df["day_of_week"] = df["timestamp"].dt.dayofweek.astype(np.float32)
        df["is_business_hours"] = ((df["hour"]>=8)&(df["hour"]<=18)).astype(np.float32)
        df["is_weekend"] = (df["day_of_week"]>=5).astype(np.float32)

        # — freq encoding
        for c in FREQ_COLS:
            fmap = fm.get(c, {})
            if c in df.columns:
                df[f"{c}_freq"] = df[c].fillna("UNKNOWN").map(fmap).fillna(0).astype(np.float32)
            else:
                df[f"{c}_freq"] = np.float32(0)

        # — aggregate lookups (dict.get, no groupby!)
        u = df["user"].fillna("UNKNOWN")
        df["user_event_count"]     = u.map(stats["user_cnt"]).fillna(0).astype(np.float32)
        df["user_unique_dst_ips"]  = u.map(stats["user_unique_dst"]).fillna(0).astype(np.float32)
        df["user_unique_processes"]= u.map(stats["user_unique_proc"]).fillna(0).astype(np.float32)
        df["user_success_rate"]    = u.map(stats["user_suc_rate"]).fillna(0).astype(np.float32)
        df["hostname_event_count"] = df["hostname"].fillna("UNKNOWN").map(stats["host_cnt"]).fillna(0).astype(np.float32)

        # — per (user, hour_bucket)
        hb = df["timestamp"].dt.floor("h").astype(str)
        keys = list(zip(u.values, hb.values))
        df["user_hourly_event_rate"] = pd.array([stats["uh_cnt"].get(k,0) for k in keys], dtype=np.float32)
        df["user_hourly_unique_dst"] = pd.array([stats["uh_unique_dst"].get(k,0) for k in keys], dtype=np.float32)

        # — rare indicators
        pn_freq = fm.get("process_name", {})
        if "process_name" in df.columns:
            df["is_rare_process"] = (df["process_name"].fillna("UNKNOWN").map(pn_freq).fillna(0) <= stats["rare_proc_thr"]).astype(np.float32)
        else:
            df["is_rare_process"] = np.float32(0)
        et_freq = fm.get("event_type", {})
        if "event_type" in df.columns:
            df["is_rare_event_type"] = (df["event_type"].fillna("UNKNOWN").map(et_freq).fillna(0) <= stats["rare_et_thr"]).astype(np.float32)
        else:
            df["is_rare_event_type"] = np.float32(0)

        # — session
        if "session_id" in df.columns:
            df["session_event_count"] = df["session_id"].map(stats["sess_cnt"]).fillna(0).astype(np.float32)
        else:
            df["session_event_count"] = np.float32(0)

        # — cmd len
        if "command_line" in df.columns:
            df["cmd_len"] = df["command_line"].fillna("").str.len().astype(np.float32)
        else:
            df["cmd_len"] = np.float32(0)

        # ── Extract numeric feature matrix ──
        feat_cols = (
            ["success","service_account","signed",
             "prevalence_score","file_size","port","confidence_level",
             "hour","minute","day_of_week","is_business_hours","is_weekend"]
            + [f"{c}_freq" for c in FREQ_COLS]
            + ["user_event_count","user_unique_dst_ips","user_unique_processes",
               "user_success_rate","hostname_event_count",
               "user_hourly_event_rate","user_hourly_unique_dst",
               "is_rare_process","is_rare_event_type",
               "session_event_count","cmd_len"]
        )

        X = df[feat_cols].values.astype(np.float32)
        y = df["is_attack"].values.astype(np.int8)

        chunk_path = os.path.join(CHUNK_DIR, f"chunk_{i:03d}.npz")
        np.savez_compressed(chunk_path, X=X, y=y)
        print(f"  [{i}/{len(files)}] {fname}: {len(X):,} rows → {chunk_path}  💾{mem_gb():.1f}GB")

        del df, X, y; gc.collect()

    print(f"✅ Pass 2 done. Chunks saved to {CHUNK_DIR}\n")
    return feat_cols

# ═══════════════════════════════════════════════════════════════════════════════
# PASS 3 — Load chunks, train, evaluate, plot
# ═══════════════════════════════════════════════════════════════════════════════
def pass3(feat_names):
    print("=" * 65)
    print("PASS 3 / 3 — Training & Evaluation")
    print("=" * 65)

    # ── Load all chunks (files are already sorted chronologically) ──
    chunk_files = sorted(glob.glob(os.path.join(CHUNK_DIR, "*.npz")))
    Xs, ys = [], []
    for cf in chunk_files:
        d = np.load(cf)
        Xs.append(d["X"]); ys.append(d["y"])
    X = np.vstack(Xs); y = np.concatenate(ys)
    del Xs, ys; gc.collect()
    print(f"  Loaded {len(X):,} rows × {X.shape[1]} features  💾{mem_gb():.1f}GB")

    # ── Split ──
    split = int(len(X) * (1 - TEST_SIZE))
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]
    del X, y; gc.collect()
    print(f"  Train: {len(X_train):,}  Test: {len(X_test):,}")
    print(f"  Train attacks: {y_train.sum():,}  Test attacks: {y_test.sum():,}")

    # ── Scale ──
    scaler = RobustScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # ── Isolation Forest scores ──
    print("  Adding Isolation Forest scores ...")
    iso = IsolationForest(n_estimators=200, contamination=0.005,
                          max_samples=min(100_000, len(X_train)),
                          random_state=RANDOM_STATE, n_jobs=-1)
    iso.fit(X_train)
    X_train = np.hstack([X_train, iso.decision_function(X_train).reshape(-1,1)])
    X_test  = np.hstack([X_test,  iso.decision_function(X_test).reshape(-1,1)])
    del iso; gc.collect()
    aug_feats = feat_names + ["iso_forest_score"]

    # ── Detect GPU ──
    has_gpu = False
    try:
        r = subprocess.run(["nvidia-smi"], capture_output=True, text=True)
        has_gpu = r.returncode == 0
    except FileNotFoundError:
        pass
    print(f"  {'🟢 GPU' if has_gpu else '⚪ CPU'} training")

    # ── Train ──
    pos = int(y_train.sum()); neg = len(y_train) - pos
    spw = neg / max(pos, 1)
    print(f"  scale_pos_weight = {spw:.1f}")

    print("  Training XGBoost ...")
    xp = dict(n_estimators=500, max_depth=8, learning_rate=0.05,
              subsample=0.8, colsample_bytree=0.8, scale_pos_weight=spw,
              eval_metric="aucpr", random_state=RANDOM_STATE,
              n_jobs=-1, tree_method="hist")
    if has_gpu: xp["device"] = "cuda"
    xgb_clf = xgb.XGBClassifier(**xp)
    xgb_clf.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

    print("  Training LightGBM ...")
    # NOTE: LightGBM GPU tree learner crashes with extreme scale_pos_weight,
    # so we use is_unbalance=True + CPU instead. LightGBM CPU is very fast.
    lp = dict(n_estimators=500, max_depth=8, learning_rate=0.05,
              subsample=0.8, colsample_bytree=0.8,
              is_unbalance=True,          # handles imbalance internally
              min_child_samples=50,       # prevents empty leaf splits
              metric="average_precision", random_state=RANDOM_STATE,
              n_jobs=-1, verbose=-1)
    lgb_clf = lgb.LGBMClassifier(**lp)
    lgb_clf.fit(X_train, y_train, eval_set=[(X_test, y_test)])

    xgb_p = xgb_clf.predict_proba(X_test)[:,1]
    lgb_p = lgb_clf.predict_proba(X_test)[:,1]
    ens_p = 0.5 * xgb_p + 0.5 * lgb_p

    # ── Threshold optimisation ──
    def best_thr(yt, p, name):
        pr, rc, th = precision_recall_curve(yt, p)
        f = 2*pr*rc/(pr+rc+1e-8)
        bi = np.argmax(f)
        t = th[bi] if bi < len(th) else 0.5
        print(f"  [{name}] Best F1={f[bi]:.4f} @ threshold={t:.4f}")
        return t

    xt = best_thr(y_test, xgb_p, "XGBoost")
    lt = best_thr(y_test, lgb_p, "LightGBM")
    et = best_thr(y_test, ens_p, "Ensemble")

    # ── Evaluate ──
    def evaluate(yt, p, thr, name):
        yp = (p >= thr).astype(int)
        acc = accuracy_score(yt, yp)
        pr  = precision_score(yt, yp, zero_division=0)
        rc  = recall_score(yt, yp, zero_division=0)
        f1  = f1_score(yt, yp, zero_division=0)
        mcc = matthews_corrcoef(yt, yp)
        try: ra = roc_auc_score(yt, p)
        except: ra = 0
        try: pa = average_precision_score(yt, p)
        except: pa = 0
        cm = confusion_matrix(yt, yp)
        print(f"\n{'='*55}\n  {name}\n{'='*55}")
        for k,v in [("Threshold",thr),("Accuracy",acc),("Precision",pr),
                     ("Recall",rc),("F1",f1),("MCC",mcc),("ROC-AUC",ra),("PR-AUC",pa)]:
            print(f"  {k:15s}: {v:.4f}")
        print(classification_report(yt, yp, target_names=["Normal","Attack"], zero_division=0))
        return dict(name=name, thr=thr, acc=acc, prec=pr, rec=rc, f1=f1,
                    mcc=mcc, roc_auc=ra, pr_auc=pa, cm=cm, proba=p)

    results = [evaluate(y_test, xgb_p, xt, "XGBoost"),
               evaluate(y_test, lgb_p, lt, "LightGBM"),
               evaluate(y_test, ens_p, et, "Ensemble")]

    # ── Plots ──
    print("\nGenerating plots ...")

    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    for ax, r in zip(axes, results):
        sns.heatmap(r["cm"], annot=True, fmt="d", cmap="Blues",
                    xticklabels=["Normal","Attack"], yticklabels=["Normal","Attack"], ax=ax)
        ax.set_title(f"{r['name']}\nF1={r['f1']:.4f}")
        ax.set_ylabel("True"); ax.set_xlabel("Predicted")
    plt.tight_layout(); plt.show()

    plt.figure(figsize=(8,6))
    for r in results:
        fpr, tpr, _ = roc_curve(y_test, r["proba"])
        plt.plot(fpr, tpr, label=f"{r['name']} (AUC={r['roc_auc']:.4f})")
    plt.plot([0,1],[0,1],"k--",alpha=.5)
    plt.xlabel("FPR"); plt.ylabel("TPR"); plt.title("ROC Curves")
    plt.legend(); plt.tight_layout(); plt.show()

    plt.figure(figsize=(8,6))
    for r in results:
        pr, rc, _ = precision_recall_curve(y_test, r["proba"])
        plt.plot(rc, pr, label=f"{r['name']} (AP={r['pr_auc']:.4f})")
    plt.xlabel("Recall"); plt.ylabel("Precision"); plt.title("PR Curves")
    plt.legend(); plt.tight_layout(); plt.show()

    try:
        imp = xgb_clf.feature_importances_
        fi = pd.DataFrame({"feature": aug_feats, "importance": imp})\
               .sort_values("importance", ascending=False).head(20)
        plt.figure(figsize=(10,6))
        sns.barplot(data=fi, x="importance", y="feature", palette="viridis")
        plt.title("Top 20 Features (XGBoost)"); plt.tight_layout(); plt.show()
    except: pass

    # ── Summary table ──
    sdf = pd.DataFrame([{
        "Model": r["name"], "Threshold": f"{r['thr']:.4f}",
        "Accuracy": f"{r['acc']:.4f}", "Precision": f"{r['prec']:.4f}",
        "Recall": f"{r['rec']:.4f}", "F1": f"{r['f1']:.4f}",
        "MCC": f"{r['mcc']:.4f}", "ROC-AUC": f"{r['roc_auc']:.4f}",
        "PR-AUC": f"{r['pr_auc']:.4f}",
    } for r in results])
    display(sdf)

    # cleanup temp chunks
    shutil.rmtree(CHUNK_DIR, ignore_errors=True)

# ── MAIN ────────────────────────────────────────────────────────────────────────
def main():
    t0 = time.time()
    stats = pass1(DRIVE_DATA_DIR)
    feat_names = pass2(DRIVE_DATA_DIR, stats)
    del stats; gc.collect()
    pass3(feat_names)
    print(f"\n✅ Pipeline completed in {time.time()-t0:.1f}s")

main()
