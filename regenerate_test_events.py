"""
regenerate_test_events.py — Regenerate test_events.json with a proper mix of
normal and anomalous events from the full dataset.
"""
import pandas as pd
import json
import os
import random

DATA_DIR = r"C:\Users\Lenovo\projects\hpe\realistic_logs_v2"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model_output")

LOGS_FILE = os.path.join(DATA_DIR, "realistic_network_logs.csv")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "test_events.json")

def main():
    print("=" * 60)
    print("  REGENERATING test_events.json WITH ANOMALIES")
    print("=" * 60)

    # Load full dataset
    df = pd.read_csv(LOGS_FILE)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp').reset_index(drop=True)

    print(f"  Total events in dataset: {len(df):,}")

    # Separate normal and anomaly events
    anomalies = df[df['is_injected_anomaly'] == True].copy()
    normals = df[df['is_injected_anomaly'] == False].copy()

    print(f"  Normal events: {len(normals):,}")
    print(f"  Anomaly events: {len(anomalies):,}")
    print(f"  Anomaly types: {anomalies['anomaly_type'].value_counts().to_dict()}")

    # Strategy: take ALL anomaly events + sample normal events to create
    # a ~5000 event test set with ~5-8% anomaly rate (realistic)
    # This ensures every attack type is represented
    
    total_target = 5000
    num_anomalies = len(anomalies)  # Keep all anomalies
    num_normals = total_target - num_anomalies
    
    if num_normals < 0:
        # More anomalies than target, sample anomalies too
        num_normals = int(total_target * 0.92)
        num_anomalies = total_target - num_normals
        anomalies = anomalies.sample(n=num_anomalies, random_state=42)
    
    # Sample normals spread across the full time range
    normal_sample = normals.sample(n=min(num_normals, len(normals)), random_state=42)
    
    # Combine and sort chronologically
    test_df = pd.concat([normal_sample, anomalies]).sort_values('timestamp').reset_index(drop=True)
    
    print(f"\n  Final test set: {len(test_df):,} events")
    print(f"  Anomalies included: {test_df['is_injected_anomaly'].sum():,}")
    print(f"  Anomaly breakdown:")
    for atype, count in test_df[test_df['is_injected_anomaly'] == True]['anomaly_type'].value_counts().items():
        print(f"    {atype}: {count}")

    # Format for JSON export
    test_df['timestamp'] = test_df['timestamp'].dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    test_df['anomaly_type'] = test_df['anomaly_type'].fillna('None')
    
    # Convert boolean columns properly
    bool_cols = ['geo_mismatch', 'impossible_travel', 'success', 'is_injected_anomaly']
    for col in bool_cols:
        if col in test_df.columns:
            test_df[col] = test_df[col].astype(bool)
    
    test_df = test_df.fillna('')

    # Export
    test_events = test_df.to_dict('records')
    
    # Clean up any numpy types for JSON serialization
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(test_events, f, indent=2, default=str)

    print(f"\n  [OK] Saved {len(test_events)} test events to:")
    print(f"       {OUTPUT_FILE}")
    print(f"\n  Restart Docker to use the new data:")
    print(f"       docker-compose restart backend")

if __name__ == "__main__":
    main()
