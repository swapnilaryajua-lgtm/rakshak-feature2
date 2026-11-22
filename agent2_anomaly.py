"""Agent 2: Anomaly Detection Agent

Isolation Forest trained ONLY on BENIGN training flows.
- Scores mapped to 0-1 percentile against BENIGN baseline
- Anomaly threshold calibrated on calib partition
- Feature evidence generated via robust z-scores with variance floor
- Strictly adheres to BRIEF.md Section 10 JSON contract
"""

import argparse
from typing import Dict, Any
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
import joblib

import config
from data import load_processed_data
from agent_classes import AnomalyDetectionAgent


def evaluate_agent2(agent: AnomalyDetectionAgent, df: pd.DataFrame, dataset_name: str) -> Dict[str, Any]:
    preds_df = agent.predict_batch(df)
    scores = preds_df["anomaly_score"].values
    is_ano = preds_df["is_anomalous"].values
    y_true_binary = (df[config.LABEL_COL] != "BENIGN").astype(int).values

    auroc = roc_auc_score(y_true_binary, scores)

    print("-" * 65)
    print(f"Agent 2 Evaluation on {dataset_name} ({len(df)} rows):")
    print(f"  Binary AUROC (BENIGN vs Attack): {auroc:.4f}")
    print(f"  Calibrated Anomaly Threshold   : {agent.calibrated_threshold:.4f}")

    det_rates = {}
    for cls in config.CLASSES:
        mask = (df[config.LABEL_COL] == cls).values
        if np.sum(mask) > 0:
            rate = np.mean(is_ano[mask])
            det_rates[cls] = float(rate)
            label_tag = "False Alarm Rate" if cls == "BENIGN" else "Detection Rate  "
            print(f"    - {cls:12s} ({label_tag}): {rate*100:.2f}% ({np.sum(is_ano[mask])}/{np.sum(mask)})")

    print("-" * 65)
    return {
        "dataset": dataset_name,
        "auroc": float(auroc),
        "threshold": float(agent.calibrated_threshold),
        "rates": det_rates
    }


def run_stage3(sample_size: int = None, save_model: bool = True):
    print("=" * 70)
    print(f"STAGE 3: Training Agent 2 Anomaly Detection (sample_size={sample_size})...")

    train_df, calib_df, eval_df, preprocessor = load_processed_data(sample_size=sample_size)
    feature_names = preprocessor.selected_feature_cols

    agent2 = AnomalyDetectionAgent()
    agent2.fit(train_df, feature_names)
    agent2.calibrate_threshold(calib_df)

    calib_metrics = evaluate_agent2(agent2, calib_df, "CALIB")
    eval_metrics = evaluate_agent2(agent2, eval_df, "EVAL")

    sample_preds = agent2.predict_batch(calib_df.head(2))
    sample_json = agent2.to_json_records(sample_preds)
    print("\nSample Agent 2 JSON Schema output:")
    import json
    print(json.dumps(sample_json[0], indent=2))

    if save_model:
        prefix = f"sample_{sample_size}_" if sample_size else ""
        model_path = config.ARTIFACTS_DIR / f"{prefix}agent2_anomaly.joblib"
        joblib.dump(agent2, model_path)
        print(f"Agent 2 model saved to {model_path}")

    print("=" * 70)
    return agent2, calib_metrics, eval_metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stage 3 Agent 2 Anomaly Detection")
    parser.add_argument("--sample", type=int, default=None, help="Sample size for testing (e.g. 50000)")
    args = parser.parse_args()

    run_stage3(sample_size=args.sample, save_model=True)
