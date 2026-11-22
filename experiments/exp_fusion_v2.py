"""Runs Fusion with Agent 1 (baseline) and Agent 2 (v2 - Mahalanobis on PCA).
Computes ablation table, disagreement counts, and saves to outputs/experiments/fusion_v2_metrics.json
"""

import sys
from pathlib import Path
import json
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, roc_auc_score
import joblib

sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from agent_classes import ThreatDetectionAgent, AnomalyDetectionAgentV2
from agent3_fusion import EvidenceFusionAgent
from preprocessor import FlowPreprocessor


def run_fusion_v2():
    print("=" * 75)
    print("RE-RUNNING FUSION WITH AGENT 2 (v2)...")

    preprocessor = joblib.load(config.ARTIFACTS_DIR / "preprocessor.joblib")
    agent1 = joblib.load(config.ARTIFACTS_DIR / "agent1_threat.joblib")
    agent2_v2 = joblib.load(config.ARTIFACTS_DIR / "agent2_anomaly_v2.joblib")
    agent3 = EvidenceFusionAgent()

    eval_raw = pd.read_parquet(config.EVAL_PATH)
    eval_raw.columns = eval_raw.columns.str.strip()
    n_eval = len(eval_raw)

    cleaned_df = preprocessor.transform(eval_raw)
    a1_preds = agent1.predict_batch(cleaned_df)
    a2_preds = agent2_v2.predict_batch(cleaned_df)
    fusion_preds = agent3.fuse(a1_preds, a2_preds)

    y_true = eval_raw[config.LABEL_COL]
    y_true_binary = (y_true != "BENIGN").astype(int)
    y_pred_fusion = fusion_preds["final_class"]

    # 1. Full-Coverage Metrics
    acc_full = float(accuracy_score(y_true, y_pred_fusion))
    macro_f1_full = float(f1_score(y_true, y_pred_fusion, average="macro"))

    # 2. Ablation Table
    # Agent 1 only
    y_pred_a1 = a1_preds["agent1_pred_class"]
    a1_acc = float(accuracy_score(y_true, y_pred_a1))
    a1_macro_f1 = float(f1_score(y_true, y_pred_a1, average="macro"))
    a1_false_allow = int(((y_true != "BENIGN") & (y_pred_a1 == "BENIGN")).sum())
    a1_false_block = int(((y_true == "BENIGN") & (y_pred_a1 != "BENIGN")).sum())

    # Agent 2 (v2) only as binary
    y_pred_a2 = a2_preds["is_anomalous"].astype(int)
    a2_acc = float(accuracy_score(y_true_binary, y_pred_a2))
    a2_macro_f1 = float(f1_score(y_true_binary, y_pred_a2, average="macro"))
    a2_auroc = float(roc_auc_score(y_true_binary, a2_preds["anomaly_score"]))
    a2_false_allow = int(((y_true_binary == 1) & (y_pred_a2 == 0)).sum())
    a2_false_block = int(((y_true_binary == 0) & (y_pred_a2 == 1)).sum())

    # Fusion v2
    fusion_false_allow = int(((y_true_binary == 1) & (fusion_preds["action"] == "ALLOW")).sum())
    fusion_false_block = int(((y_true_binary == 0) & (fusion_preds["action"] == "BLOCK")).sum())

    ablation_table = [
        {
            "system": "Agent 1 only (Threat)",
            "task": "5-Class Classifier",
            "accuracy": round(a1_acc, 4),
            "macro_f1": round(a1_macro_f1, 4),
            "false_allow_count": a1_false_allow,
            "false_block_count": a1_false_block
        },
        {
            "system": "Agent 2 (v2) only (Anomaly)",
            "task": "Binary (Attack vs Benign)",
            "accuracy": round(a2_acc, 4),
            "macro_f1": round(a2_macro_f1, 4),
            "auroc": round(a2_auroc, 4),
            "false_allow_count": a2_false_allow,
            "false_block_count": a2_false_block
        },
        {
            "system": "CyberSentinel Fusion (with v2)",
            "task": "Multi-Agent Defense",
            "accuracy": round(acc_full, 4),
            "macro_f1": round(macro_f1_full, 4),
            "false_allow_count": fusion_false_allow,
            "false_block_count": fusion_false_block
        }
    ]

    # 3. Disagreement Counts & Attribution
    agreements_mask = fusion_preds["agreement"]
    n_agreed = int(agreements_mask.sum())
    n_disagreed = n_eval - n_agreed

    type1_mask = (~agreements_mask) & (a1_preds["agent1_pred_class"] != "BENIGN") & (~a2_preds["is_anomalous"])
    n_type1 = int(type1_mask.sum())
    type1_a1_right = int((type1_mask & (y_true != "BENIGN")).sum())
    type1_a2_right = int((type1_mask & (y_true == "BENIGN")).sum())

    type2_mask = (~agreements_mask) & (a1_preds["agent1_pred_class"] == "BENIGN") & (a2_preds["is_anomalous"])
    n_type2 = int(type2_mask.sum())
    type2_a1_right = int((type2_mask & (y_true == "BENIGN")).sum())
    type2_a2_right = int((type2_mask & (y_true != "BENIGN")).sum())

    action_counts = fusion_preds["action"].value_counts().to_dict()
    status_counts = fusion_preds["evidence_status"].value_counts().to_dict()

    print("\nAblation Table (Fusion with v2):")
    print(pd.DataFrame(ablation_table).to_string(index=False))

    print("\nDisagreement Analysis (Fusion with v2):")
    print(f"  Agreements   : {n_agreed} ({n_agreed/n_eval*100:.2f}%)")
    print(f"  Disagreements: {n_disagreed} ({n_disagreed/n_eval*100:.2f}%)")
    print(f"  - Classifier Attack, Anomaly Normal: {n_type1} (Agent 1 right: {type1_a1_right}, Agent 2 right: {type1_a2_right})")
    print(f"  - Classifier Benign, Anomaly Alert : {n_type2} (Agent 1 right: {type2_a1_right}, Agent 2 right: {type2_a2_right})")

    print("\nAction Distribution:")
    for act, cnt in action_counts.items():
        print(f"  - {act:10s}: {cnt} ({cnt/n_eval*100:.2f}%)")

    print("\nEvidence Status Distribution:")
    for st, cnt in status_counts.items():
        print(f"  - {st:17s}: {cnt} ({cnt/n_eval*100:.2f}%)")

    payload = {
        "ablation_table": ablation_table,
        "disagreement_analysis": {
            "agreements_count": n_agreed,
            "agreements_pct": round(n_agreed / n_eval * 100, 2),
            "disagreements_count": n_disagreed,
            "disagreements_pct": round(n_disagreed / n_eval * 100, 2),
            "type1_classifier_attack_anomaly_normal": {
                "total": n_type1,
                "agent1_right": type1_a1_right,
                "agent2_right": type1_a2_right
            },
            "type2_classifier_benign_anomaly_alert": {
                "total": n_type2,
                "agent1_right": type2_a1_right,
                "agent2_right": type2_a2_right
            }
        },
        "action_distribution": action_counts,
        "evidence_status_distribution": status_counts
    }

    out_path = config.OUTPUTS_DIR / "experiments" / "fusion_v2_metrics.json"
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\nSaved updated Fusion metrics to {out_path}")
    print("=" * 75)
    return payload


if __name__ == "__main__":
    run_fusion_v2()
