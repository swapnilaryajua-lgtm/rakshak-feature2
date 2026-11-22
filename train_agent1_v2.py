"""Trains Agent 1 (v2) WITHOUT the Destination Port feature.

Saves:
- artifacts/agent1_threat_v2.joblib
- artifacts/v2_feature_names.joblib
- artifacts/v2_preprocessor.joblib
"""

import time
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score
import joblib

import config
from data import load_processed_data
from agent_classes import ThreatDetectionAgent
from preprocessor import FlowPreprocessor


def train_agent1_v2():
    print("=" * 75)
    print("TRAINING PRODUCTION AGENT 1 (v2) - WITHOUT 'Destination Port'...")

    train_df, calib_df, eval_df, preprocessor = load_processed_data()
    all_features = list(preprocessor.selected_feature_cols)
    
    # Exclude Destination Port
    v2_features = [f for f in all_features if f != "Destination Port"]
    assert len(v2_features) == 74, f"Expected 74 features, got {len(v2_features)}"
    print(f"Selected {len(v2_features)} active features (Destination Port excluded).")

    # Fit Agent 1 (v2)
    agent1_v2 = ThreatDetectionAgent(n_estimators=config.AGENT1_N_ESTIMATORS)
    agent1_v2.fit(train_df, v2_features)

    # Save artifacts
    model_path = config.ARTIFACTS_DIR / "agent1_threat_v2.joblib"
    feat_path = config.ARTIFACTS_DIR / "v2_feature_names.joblib"
    prep_path = config.ARTIFACTS_DIR / "v2_preprocessor.joblib"

    joblib.dump(agent1_v2, model_path)
    joblib.dump(v2_features, feat_path)
    joblib.dump(preprocessor, prep_path)
    print(f"Saved Agent 1 (v2) model to {model_path}")
    print(f"Saved v2 features to {feat_path}")
    print(f"Saved v2 preprocessor to {prep_path}")

    # Evaluate on eval
    preds_eval = agent1_v2.predict_batch(eval_df)
    y_true = eval_df[config.LABEL_COL]
    y_pred = preds_eval["agent1_pred_class"]

    acc = accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, average="macro")
    per_class_f1 = f1_score(y_true, y_pred, average=None, labels=config.CLASSES)

    print("-" * 65)
    print(f"Agent 1 (v2) Evaluation on EVAL ({len(eval_df)} rows):")
    print(f"  Accuracy: {acc*100:.2f}%")
    print(f"  Macro-F1: {macro_f1:.4f}")
    for cls, f1 in zip(config.CLASSES, per_class_f1):
        print(f"    - {cls:12s}: {f1:.4f}")
    print("-" * 65)
    print("=" * 75)
    return agent1_v2


if __name__ == "__main__":
    train_agent1_v2()
