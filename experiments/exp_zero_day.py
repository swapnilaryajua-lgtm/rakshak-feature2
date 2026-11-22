"""Zero-Day Evaluation Experiment for CyberSentinel.

Simulates novel attacks by holding out one attack class at a time from Agent 1 training:
1. Hold out PORT_SCAN
2. Hold out DDOS
3. Hold out BRUTE_FORCE
Evaluates on the held-out class flows in the validation set:
- % Agent 1 misclassifies as BENIGN (Miss Rate)
- % Agent 2 flags as Anomalous (Catch Rate)
- % Fusion marks as UNKNOWN_THREAT and % Fusion ESCALATES
Saves results to outputs/experiments/zero_day.json
"""

import sys
from pathlib import Path
import json
import time
from typing import Dict, Any, List
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score
import lightgbm as lgb
import joblib

sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from data import load_processed_data
from agent_classes import ThreatDetectionAgent, AnomalyDetectionAgent, AnomalyDetectionAgentV2
from agent3_fusion import EvidenceFusionAgent


def run_single_zero_day(held_out_class: str,
                        train_df: pd.DataFrame,
                        calib_df: pd.DataFrame,
                        eval_df: pd.DataFrame,
                        feature_names: List[str],
                        agent2) -> Dict[str, Any]:
    print(f"\n" + "=" * 75)
    print(f"ZERO-DAY EXPERIMENT: Holding out '{held_out_class}' from Agent 1 Training")
    print("=" * 75)

    # 1. Filter training data: remove the held-out attack class completely
    train_zero = train_df[train_df[config.LABEL_COL] != held_out_class].reset_index(drop=True)
    known_classes = [c for c in config.CLASSES if c != held_out_class]
    class_to_idx = {c: i for i, c in enumerate(known_classes)}
    idx_to_class = {i: c for i, c in enumerate(known_classes)}

    print(f"Training Agent 1 on {len(train_zero)} flows across {len(known_classes)} known classes: {known_classes}...")
    t0 = time.time()
    
    X_train = train_zero[feature_names].values
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
    print(f"Model trained in {time.time() - t0:.2f}s")

    # 2. Extract held-out class flows from EVAL partition
    held_out_eval = eval_df[eval_df[config.LABEL_COL] == held_out_class].reset_index(drop=True)
    n_flows = len(held_out_eval)
    print(f"Evaluating on {n_flows} held-out '{held_out_class}' flows from EVAL...")

    # Predict with Zero-Day Agent 1
    X_eval = held_out_eval[feature_names].values
    probs = model.predict_proba(X_eval)
    pred_indices = np.argmax(probs, axis=1)
    confidences = np.max(probs, axis=1)
    a1_preds = [idx_to_class[i] for i in pred_indices]

    a1_pred_df = pd.DataFrame({
        config.ID_COL: held_out_eval[config.ID_COL],
        "agent1_pred_class": a1_preds,
        "agent1_confidence": np.round(confidences, 4)
    })
    
    # Format probabilities mapping
    prob_dicts = []
    for row in probs:
        p_dict = {c: float(np.round(p, 4)) for c, p in zip(known_classes, row)}
        prob_dicts.append(p_dict)
    a1_pred_df["agent1_probabilities"] = prob_dicts

    # Predict with Agent 2 (Anomaly Detector)
    a2_pred_df = agent2.predict_batch(held_out_eval)

    # Fuse predictions with Agent 3
    agent3 = EvidenceFusionAgent()
    fusion_df = agent3.fuse(a1_pred_df, a2_pred_df)

    # 3. Compute Metrics
    # (a) Agent 1 Miss Rate: % called BENIGN
    n_called_benign = int((a1_pred_df["agent1_pred_class"] == "BENIGN").sum())
    miss_rate = float(n_called_benign / n_flows)

    # Breakdown of Agent 1 predictions on this unknown class
    a1_pred_distribution = a1_pred_df["agent1_pred_class"].value_counts().to_dict()

    # (b) Agent 2 Anomaly Detection Rate: % flagged as anomalous
    n_flagged_anom = int(a2_pred_df["is_anomalous"].sum())
    anom_catch_rate = float(n_flagged_anom / n_flows)
    mean_anom_score = float(a2_pred_df["anomaly_score"].mean())

    # (c) Fusion Defense Rate
    # UNKNOWN_THREAT count and rate
    n_unknown_threat = int((fusion_df["evidence_status"] == "UNKNOWN_THREAT").sum())
    unknown_threat_rate = float(n_unknown_threat / n_flows)

    # ESCALATE count and rate
    n_escalate = int((fusion_df["action"] == "ESCALATE").sum())
    escalate_rate = float(n_escalate / n_flows)

    # Action counts
    action_counts = fusion_df["action"].value_counts().to_dict()
    status_counts = fusion_df["evidence_status"].value_counts().to_dict()

    # Safe catch: % of flows that were NOT falsely allowed as benign
    # (either blocked or escalated)
    safe_catch_count = int((fusion_df["action"] != "ALLOW").sum())
    safe_catch_rate = float(safe_catch_count / n_flows)

    print("-" * 65)
    print(f"Results for Zero-Day '{held_out_class}' ({n_flows} flows):")
    print(f"  Agent 1 Miss Rate (Called BENIGN): {miss_rate*100:.2f}% ({n_called_benign}/{n_flows})")
    print(f"  Agent 1 Predictions Distribution : {a1_pred_distribution}")
    print(f"  Agent 2 Anomaly Catch Rate       : {anom_catch_rate*100:.2f}% ({n_flagged_anom}/{n_flows}) [Mean Score: {mean_anom_score:.4f}]")
    print(f"  Fusion UNKNOWN_THREAT Rate       : {unknown_threat_rate*100:.2f}% ({n_unknown_threat}/{n_flows})")
    print(f"  Fusion Escalation Rate           : {escalate_rate*100:.2f}% ({n_escalate}/{n_flows})")
    print(f"  Fusion Safe Catch (Non-Allow)    : {safe_catch_rate*100:.2f}% ({safe_catch_count}/{n_flows})")
    print(f"  Fusion Action Distribution       : {action_counts}")
    print("-" * 65)

    return {
        "held_out_class": held_out_class,
        "n_flows": n_flows,
        "agent1_miss_rate_benign": miss_rate,
        "agent1_pred_distribution": a1_pred_distribution,
        "agent2_anomaly_catch_rate": anom_catch_rate,
        "agent2_mean_anomaly_score": mean_anom_score,
        "fusion_unknown_threat_rate": unknown_threat_rate,
        "fusion_escalation_rate": escalate_rate,
        "fusion_safe_catch_rate": safe_catch_rate,
        "fusion_action_distribution": action_counts,
        "fusion_status_distribution": status_counts
    }


def run_all_zero_day_experiments():
    print("=" * 80)
    print("EXPERIMENT C: Multi-Class Zero-Day Defense Testing")
    print("=" * 80)

    train_df, calib_df, eval_df, preprocessor = load_processed_data()
    feature_names = preprocessor.selected_feature_cols

    # Load Agent 2 v2 (upgraded anomaly detector)
    agent2_v2 = joblib.load(config.ARTIFACTS_DIR / "agent2_anomaly_v2.joblib")

    classes_to_test = ["PORT_SCAN", "DDOS", "BRUTE_FORCE"]
    all_zero_day_results = {}

    for cls in classes_to_test:
        res = run_single_zero_day(cls, train_df, calib_df, eval_df, feature_names, agent2_v2)
        all_zero_day_results[cls] = res

    # Summary Table
    print("\n" + "=" * 80)
    print("ZERO-DAY EXPERIMENT SUMMARY TABLE:")
    rows = []
    for cls, r in all_zero_day_results.items():
        rows.append({
            "Held-Out Attack": cls,
            "Eval Flows": r["n_flows"],
            "Agent 1 Miss (Called BENIGN)": f"{r['agent1_miss_rate_benign']*100:.2f}%",
            "Agent 2 Catch Rate": f"{r['agent2_anomaly_catch_rate']*100:.2f}%",
            "Fusion UNKNOWN_THREAT": f"{r['fusion_unknown_threat_rate']*100:.2f}%",
            "Fusion Escalated": f"{r['fusion_escalation_rate']*100:.2f}%",
            "Fusion Safe Catch (Blocked+Esc)": f"{r['fusion_safe_catch_rate']*100:.2f}%",
        })
    df_summary = pd.DataFrame(rows)
    print(df_summary.to_string(index=False))

    out_path = config.OUTPUTS_DIR / "experiments" / "zero_day.json"
    with open(out_path, "w") as f:
        json.dump(all_zero_day_results, f, indent=2)
    print(f"\nSaved Zero-Day results to {out_path}")
    print("=" * 80)


if __name__ == "__main__":
    run_all_zero_day_experiments()
