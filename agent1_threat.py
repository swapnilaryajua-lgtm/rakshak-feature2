"""Agent 1: Threat Detection Agent

Multi-class classifier predicting one of the five classes:
[BENIGN, BRUTE_FORCE, DOS, DDOS, PORT_SCAN].
Uses LightGBM (with RandomForest fallback) with balanced class weights.
Outputs strict JSON schema defined in BRIEF.md Section 10.
"""

import argparse
from typing import Dict, Any
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix
import joblib

import config
from data import load_processed_data
from agent_classes import ThreatDetectionAgent


def evaluate_agent1(agent: ThreatDetectionAgent, df: pd.DataFrame, dataset_name: str) -> Dict[str, Any]:
    preds_df = agent.predict_batch(df)
    y_true = df[config.LABEL_COL]
    y_pred = preds_df["agent1_pred_class"]

    acc = accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, average="macro")
    per_class_f1 = f1_score(y_true, y_pred, average=None, labels=config.CLASSES)

    print("-" * 65)
    print(f"Agent 1 Evaluation on {dataset_name} ({len(df)} rows):")
    print(f"  Accuracy: {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Macro-F1: {macro_f1:.4f}")
    print("  Per-class F1:")
    for cls_name, f1 in zip(config.CLASSES, per_class_f1):
        print(f"    - {cls_name:12s}: {f1:.4f}")

    cm = confusion_matrix(y_true, y_pred, labels=config.CLASSES)
    cm_df = pd.DataFrame(cm, index=[f"True_{c}" for c in config.CLASSES], columns=[f"Pred_{c}" for c in config.CLASSES])
    print("\n  Confusion Matrix:")
    print(cm_df.to_string())
    print("-" * 65)

    return {
        "dataset": dataset_name,
        "accuracy": float(acc),
        "macro_f1": float(macro_f1),
        "per_class_f1": {c: float(f1) for c, f1 in zip(config.CLASSES, per_class_f1)},
        "confusion_matrix": cm.tolist()
    }


def run_stage2(sample_size: int = None, save_model: bool = True):
    print("=" * 70)
    print(f"STAGE 2: Training Agent 1 Threat Detection (sample_size={sample_size})...")

    train_df, calib_df, eval_df, preprocessor = load_processed_data(sample_size=sample_size)
    feature_names = preprocessor.selected_feature_cols

    agent1 = ThreatDetectionAgent()
    agent1.fit(train_df, feature_names)

    calib_metrics = evaluate_agent1(agent1, calib_df, "CALIB")
    eval_metrics = evaluate_agent1(agent1, eval_df, "EVAL")

    sample_preds = agent1.predict_batch(calib_df.head(2))
    sample_json = agent1.to_json_records(sample_preds)
    print("\nSample Agent 1 JSON Schema output:")
    import json
    print(json.dumps(sample_json[0], indent=2))

    if save_model:
        prefix = f"sample_{sample_size}_" if sample_size else ""
        model_path = config.ARTIFACTS_DIR / f"{prefix}agent1_threat.joblib"
        joblib.dump(agent1, model_path)
        print(f"Agent 1 model saved to {model_path}")

    print("=" * 70)
    return agent1, calib_metrics, eval_metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stage 2 Agent 1 Threat Detection")
    parser.add_argument("--sample", type=int, default=None, help="Sample size for testing (e.g. 50000)")
    args = parser.parse_args()

    run_stage2(sample_size=args.sample, save_model=True)
