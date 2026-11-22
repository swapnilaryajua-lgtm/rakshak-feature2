"""Verification script for v2 production models and zero-day fixed conflict rule.

Runs:
1. Standard eval on Cyber/eval/flows.parquet (114,185 flows)
   - Checks accuracy and macro-F1
   - Reports count of benign flows marked suspicious
2. Zero-day PORT_SCAN and DDOS tests with the fixed rule
   - Reports safe catch rate (blocked or escalated)
"""

import sys
from pathlib import Path
import json
import time
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix
import lightgbm as lgb
import joblib

sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from pipeline import CyberSentinelPipeline
from agent_classes import ThreatDetectionAgent, AnomalyDetectionAgentV2
from agent3_fusion import EvidenceFusionAgent
from data import load_processed_data


def test_standard_eval():
    print("=" * 80)
    print("TEST 1: Standard Evaluation with Production Models (v2) & Fixed Fusion Rule")
    print("=" * 80)

    pipeline = CyberSentinelPipeline.load_from_artifacts(version="v2")
    eval_df = pd.read_parquet(config.EVAL_PATH)
    eval_df.columns = eval_df.columns.str.strip()

    t0 = time.time()
    results_df, _ = pipeline.run(eval_df)
    elapsed = time.time() - t0
    print(f"Processed {len(eval_df)} flows in {elapsed:.2f}s ({len(eval_df)/elapsed:.1f} flows/sec)")

    y_true = eval_df[config.LABEL_COL]
    y_pred = results_df["final_class"]

    acc = accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, average="macro")
    per_class_f1 = f1_score(y_true, y_pred, average=None, labels=config.CLASSES)

    print("-" * 65)
    print(f"Full-Coverage Accuracy: {acc*100:.2f}%")
    print(f"Full-Coverage Macro-F1: {macro_f1:.4f}")
    print("Per-Class F1:")
    for cls, f1 in zip(config.CLASSES, per_class_f1):
        print(f"  - {cls:12s}: {f1:.4f}")

    # Suspicious flows analysis on BENIGN
    benign_mask = (y_true == "BENIGN")
    n_benign = benign_mask.sum()
    benign_suspicious = results_df.loc[benign_mask, "suspicious"].sum()
    benign_suspicious_pct = (benign_suspicious / n_benign) * 100

    print("-" * 65)
    print(f"BENIGN Flows Analysis ({n_benign} flows):")
    print(f"  Benign flows marked SUSPICIOUS (weak anomaly signals): {benign_suspicious} ({benign_suspicious_pct:.2f}%)")
    print(f"  Benign flows marked NORMAL                            : {n_benign - benign_suspicious} ({100 - benign_suspicious_pct:.2f}%)")

    # Overall Action & Status distribution
    action_counts = results_df["action"].value_counts().to_dict()
    status_counts = results_df["evidence_status"].value_counts().to_dict()
    print("-" * 65)
    print("Action Distribution:", action_counts)
    print("Evidence Status Distribution:", status_counts)

    return {
        "accuracy": acc,
        "macro_f1": macro_f1,
        "per_class_f1": {cls: float(f1) for cls, f1 in zip(config.CLASSES, per_class_f1)},
        "benign_total": int(n_benign),
        "benign_suspicious": int(benign_suspicious),
        "benign_suspicious_pct": round(benign_suspicious_pct, 2),
        "actions": action_counts,
        "statuses": status_counts
    }


def test_zero_day_fixed(held_out_class: str, train_df, eval_df, v2_features, agent2_v2):
    print(f"\n" + "-" * 75)
    print(f"TEST 2: Zero-Day '{held_out_class}' with Fixed Fusion Rule")
    print("-" * 75)

    train_zero = train_df[train_df[config.LABEL_COL] != held_out_class].reset_index(drop=True)
    known_classes = [c for c in config.CLASSES if c != held_out_class]
    class_to_idx = {c: i for i, c in enumerate(known_classes)}
    idx_to_class = {i: c for i, c in enumerate(known_classes)}

    X_train = train_zero[v2_features].values
    y_train = train_zero[config.LABEL_COL].map(class_to_idx).values

    model = lgb.LGBMClassifier(
        n_estimators=config.AGENT1_N_ESTIMATORS,
        learning_rate=config.AGENT1_LEARNING_RATE,
        num_leaves=config.AGENT1_NUM_LEAVES,
        class_weight="balanced",
        random_state=config.RANDOM_STATE,
        n_jobs=-1,
        verbose=-1
    )
    model.fit(X_train, y_train)

    held_out_eval = eval_df[eval_df[config.LABEL_COL] == held_out_class].reset_index(drop=True)
    n_flows = len(held_out_eval)

    X_eval = held_out_eval[v2_features].values
    probs = model.predict_proba(X_eval)
    pred_indices = np.argmax(probs, axis=1)
    confidences = np.max(probs, axis=1)
    a1_preds = [idx_to_class[i] for i in pred_indices]

    a1_pred_df = pd.DataFrame({
        config.ID_COL: held_out_eval[config.ID_COL],
        "agent1_pred_class": a1_preds,
        "agent1_confidence": np.round(confidences, 4)
    })
    prob_dicts = []
    for row in probs:
        p_dict = {c: float(np.round(p, 4)) for c, p in zip(known_classes, row)}
        prob_dicts.append(p_dict)
    a1_pred_df["agent1_probabilities"] = prob_dicts

    a2_pred_df = agent2_v2.predict_batch(held_out_eval)

    agent3 = EvidenceFusionAgent()
    fusion_df = agent3.fuse(a1_pred_df, a2_pred_df)

    # Metrics
    miss_rate = (a1_pred_df["agent1_pred_class"] == "BENIGN").mean()
    anom_catch = a2_pred_df["is_anomalous"].mean()
    safe_catch = (fusion_df["action"] != "ALLOW").mean()
    unknown_threat = (fusion_df["evidence_status"] == "UNKNOWN_THREAT").mean()
    escalate = (fusion_df["action"] == "ESCALATE").mean()
    suspicious = fusion_df["suspicious"].mean()

    print(f"Results for '{held_out_class}' ({n_flows} flows):")
    print(f"  Agent 1 Miss Rate (Called BENIGN) : {miss_rate*100:.2f}%")
    print(f"  Agent 2 Anomaly Catch Rate        : {anom_catch*100:.2f}%")
    print(f"  Fusion UNKNOWN_THREAT Rate        : {unknown_threat*100:.2f}%")
    print(f"  Fusion Escalation Rate            : {escalate*100:.2f}%")
    print(f"  Fusion SAFE CATCH Rate (Non-Allow): {safe_catch*100:.2f}% (Previously {0.08 if held_out_class=='PORT_SCAN' else 67.40}%)")
    print(f"  Fusion Flagged Suspicious for A4  : {suspicious*100:.2f}%")

    return {
        "held_out_class": held_out_class,
        "n_flows": n_flows,
        "agent1_miss_rate": miss_rate,
        "agent2_catch_rate": anom_catch,
        "fusion_safe_catch_rate": safe_catch,
        "fusion_unknown_threat_rate": unknown_threat,
        "fusion_escalate_rate": escalate,
        "fusion_suspicious_rate": suspicious
    }


def main():
    eval_metrics = test_standard_eval()

    train_df, calib_df, eval_df, _ = load_processed_data()
    v2_features = joblib.load(config.ARTIFACTS_DIR / "v2_feature_names.joblib")
    agent2_v2 = joblib.load(config.ARTIFACTS_DIR / "agent2_anomaly_v2.joblib")

    zd_port = test_zero_day_fixed("PORT_SCAN", train_df, eval_df, v2_features, agent2_v2)
    zd_ddos = test_zero_day_fixed("DDOS", train_df, eval_df, v2_features, agent2_v2)

    summary = {
        "standard_eval": eval_metrics,
        "zero_day_fixed": {
            "PORT_SCAN": zd_port,
            "DDOS": zd_ddos
        }
    }
    out_file = config.OUTPUTS_DIR / "experiments" / "v2_and_fixed_rule_verification.json"
    with open(out_file, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved verification summary to {out_file}")


if __name__ == "__main__":
    main()
