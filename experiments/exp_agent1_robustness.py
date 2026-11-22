"""Agent 1 Feature Robustness Check.

Retrains copies of Agent 1:
1. Baseline (Full 75 features)
2. Without Destination Port
3. Without Init_Win_bytes_forward and Init_Win_bytes_backward
4. Without all three (Destination Port + TCP initial windows)
Evaluates accuracy, macro-F1, and per-class F1 on calib and eval.
Saves results to outputs/experiments/agent1_robustness.json.
"""

import sys
from pathlib import Path
import json
import time
from typing import List, Dict, Any
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix
import lightgbm as lgb
import joblib

sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from data import load_processed_data


def train_and_eval_lgb(train_df: pd.DataFrame,
                       calib_df: pd.DataFrame,
                       eval_df: pd.DataFrame,
                       feature_cols: List[str],
                       experiment_name: str) -> Dict[str, Any]:
    print(f"\n--- Training {experiment_name} ({len(feature_cols)} features) ---")
    t0 = time.time()
    
    class_to_idx = {c: i for i, c in enumerate(config.CLASSES)}
    idx_to_class = {i: c for i, c in enumerate(config.CLASSES)}

    X_train = train_df[feature_cols].values
    y_train = train_df[config.LABEL_COL].map(class_to_idx).values

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
    train_time = time.time() - t0
    print(f"Trained in {train_time:.2f}s")

    def eval_subset(df: pd.DataFrame, name: str) -> Dict[str, Any]:
        X = df[feature_cols].values
        y_true = df[config.LABEL_COL].values
        preds_idx = model.predict(X)
        y_pred = [idx_to_class[i] for i in preds_idx]

        acc = float(accuracy_score(y_true, y_pred))
        macro_f1 = float(f1_score(y_true, y_pred, average="macro"))
        per_class_f1 = f1_score(y_true, y_pred, average=None, labels=config.CLASSES)

        print(f"  {name:5s} -> Acc: {acc*100:.2f}%, Macro-F1: {macro_f1:.4f}")
        for cls, f1 in zip(config.CLASSES, per_class_f1):
            print(f"    - {cls:12s}: {f1:.4f}")

        return {
            "accuracy": acc,
            "macro_f1": macro_f1,
            "per_class_f1": {cls: float(f1) for cls, f1 in zip(config.CLASSES, per_class_f1)}
        }

    calib_res = eval_subset(calib_df, "CALIB")
    eval_res = eval_subset(eval_df, "EVAL")

    return {
        "experiment_name": experiment_name,
        "n_features": len(feature_cols),
        "train_time_seconds": round(train_time, 2),
        "calib": calib_res,
        "eval": eval_res
    }


def run_robustness_experiments():
    print("=" * 80)
    print("EXPERIMENT B: Agent 1 Feature Robustness & Ablation")
    print("=" * 80)

    train_df, calib_df, eval_df, preprocessor = load_processed_data()
    all_features = list(preprocessor.selected_feature_cols)

    # 1. Baseline
    feat_baseline = all_features

    # 2. Without Destination Port
    feat_no_port = [f for f in all_features if f != "Destination Port"]

    # 3. Without TCP window sizes
    feat_no_win = [f for f in all_features if f not in ("Init_Win_bytes_forward", "Init_Win_bytes_backward")]

    # 4. Without Destination Port AND TCP window sizes
    feat_no_port_no_win = [f for f in all_features if f not in ("Destination Port", "Init_Win_bytes_forward", "Init_Win_bytes_backward")]

    experiments = [
        ("Baseline (All 75 features)", feat_baseline),
        ("Without Destination Port", feat_no_port),
        ("Without TCP Window Bytes (fwd & bwd)", feat_no_win),
        ("Without Dest Port & TCP Window Bytes", feat_no_port_no_win),
    ]

    all_results = {}
    for exp_name, feat_cols in experiments:
        res = train_and_eval_lgb(train_df, calib_df, eval_df, feat_cols, exp_name)
        all_results[exp_name] = res

    # Comparison Table
    print("\n" + "=" * 80)
    print("SUMMARY COMPARISON TABLE (EVAL DATASET):")
    summary_rows = []
    for name, res in all_results.items():
        ev = res["eval"]
        row = {
            "Model Variant": name,
            "Features": res["n_features"],
            "Eval Acc": f"{ev['accuracy']*100:.2f}%",
            "Macro-F1": f"{ev['macro_f1']:.4f}",
            "BENIGN": f"{ev['per_class_f1']['BENIGN']:.4f}",
            "BRUTE_FORCE": f"{ev['per_class_f1']['BRUTE_FORCE']:.4f}",
            "DOS": f"{ev['per_class_f1']['DOS']:.4f}",
            "DDOS": f"{ev['per_class_f1']['DDOS']:.4f}",
            "PORT_SCAN": f"{ev['per_class_f1']['PORT_SCAN']:.4f}",
        }
        summary_rows.append(row)

    summary_df = pd.DataFrame(summary_rows)
    print(summary_df.to_string(index=False))

    out_path = config.OUTPUTS_DIR / "experiments" / "agent1_robustness.json"
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nSaved robustness results to {out_path}")
    print("=" * 80)


if __name__ == "__main__":
    run_robustness_experiments()
