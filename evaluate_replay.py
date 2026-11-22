"""Replay Evaluation & Threshold Sweep Suite (Level 2).

Evaluates replay defense against ground truth on simulated replay:
1. Classification Accuracy and Macro-F1
2. Attack Containment (attacks blocked after first policy trigger)
3. Collateral Damage (legitimate benign flows blocked by policy)
4. Policy efficiency (number of policies, average policy lifetime)
5. Parameter sweep over min_suspicious_flows (2, 3, 5) and TTL (100, 250, 500)
   to quantify the containment vs collateral trade-off.
Saves results to outputs/experiments/replay_evaluation.json
"""

import argparse
from pathlib import Path
import json
import time
from typing import Dict, Any, List
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, f1_score

import config
from replay_engine import ReplayEngine
from agent4_temporal import TemporalCorrelationAgent
from agent5_defense import AdaptiveDefenseAgent


def evaluate_replay_run(ground_truth_parquet: str,
                        outputs_dir: str = str(config.OUTPUTS_DIR)) -> Dict[str, Any]:
    out_dir = Path(outputs_dir)
    gt_df = pd.read_parquet(ground_truth_parquet)
    class_df = pd.read_csv(out_dir / "classification.csv", dtype={"record_id": str})
    replay_df = pd.read_csv(out_dir / "replay.csv", dtype={"record_id": str, "applied_policy_id": str})
    policy_df = pd.read_csv(out_dir / "policy.csv", dtype=str)

    y_true = gt_df["label"]
    y_pred = class_df["predicted_class"]

    # 1. Classification Metrics
    acc = float(accuracy_score(y_true, y_pred))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro"))
    per_class_f1 = f1_score(y_true, y_pred, average=None, labels=config.CLASSES)

    # 2. Defense Replay Metrics
    is_attack_true = (y_true != "BENIGN")
    is_benign_true = (y_true == "BENIGN")
    is_blocked_action = (replay_df["action"] == "BLOCK")
    is_allowed_action = (replay_df["action"] == "ALLOW")

    total_attacks = int(is_attack_true.sum())
    total_benign = int(is_benign_true.sum())

    # Attack containment
    attacks_blocked = int((is_attack_true & is_blocked_action).sum())
    attacks_allowed = int((is_attack_true & is_allowed_action).sum())
    containment_rate = float(attacks_blocked / total_attacks) if total_attacks > 0 else 0.0

    # Benign collateral damage
    benign_blocked = int((is_benign_true & is_blocked_action).sum())
    benign_allowed = int((is_benign_true & is_allowed_action).sum())
    collateral_rate = float(benign_blocked / total_benign) if total_benign > 0 else 0.0

    # Collateral breakdown: pure benign IPs vs mixed IPs
    is_mixed = gt_df.get("is_mixed_ip", pd.Series([False] * len(gt_df)))
    pure_benign_blocked = int((is_benign_true & (~is_mixed) & is_blocked_action).sum())
    mixed_benign_blocked = int((is_benign_true & is_mixed & is_blocked_action).sum())

    # Policy statistics
    n_policies = len(policy_df)
    if n_policies > 0:
        # Calculate policy lifetimes
        id_to_idx = {rid: i for i, rid in enumerate(gt_df["record_id"].astype(str))}
        lifetimes = []
        for _, row in policy_df.iterrows():
            act_i = id_to_idx[row["activated_after_record_id"]]
            exp_i = id_to_idx[row["expires_after_record_id"]]
            lifetimes.append(exp_i - act_i)
        avg_lifetime = float(np.mean(lifetimes))
    else:
        avg_lifetime = 0.0

    metrics = {
        "classification": {
            "accuracy": acc,
            "macro_f1": macro_f1,
            "per_class_f1": {cls: float(f1) for cls, f1 in zip(config.CLASSES, per_class_f1)}
        },
        "defense": {
            "total_attacks": total_attacks,
            "attacks_blocked": attacks_blocked,
            "attacks_allowed_trigger": attacks_allowed,
            "containment_rate": containment_rate,
            "total_benign": total_benign,
            "benign_blocked_collateral": benign_blocked,
            "benign_allowed": benign_allowed,
            "collateral_rate": collateral_rate,
            "pure_benign_blocked": pure_benign_blocked,
            "mixed_benign_blocked": mixed_benign_blocked,
            "total_policies_created": n_policies,
            "average_policy_lifetime_records": round(avg_lifetime, 1)
        }
    }

    print("-" * 75)
    print("REPLAY EVALUATION SUMMARY:")
    print(f"  Classification Accuracy : {acc*100:.2f}% | Macro-F1: {macro_f1:.4f}")
    print(f"  Attack Containment Rate : {containment_rate*100:.2f}% ({attacks_blocked:,} / {total_attacks:,} attacks blocked)")
    print(f"  Collateral Damage Rate  : {collateral_rate*100:.2f}% ({benign_blocked:,} / {total_benign:,} benign flows blocked)")
    print(f"    - Pure benign IPs blocked : {pure_benign_blocked:,}")
    print(f"    - Mixed / NAT IPs blocked : {mixed_benign_blocked:,} (from legitimate users on attacked gateway)")
    print(f"  Total Policies Created  : {n_policies:,} (Average lifetime: {avg_lifetime:.1f} records)")
    print("-" * 75)
    return metrics


def run_threshold_sweep(input_parquet: str, ground_truth_parquet: str) -> List[Dict[str, Any]]:
    print("\n" + "=" * 80)
    print("RUNNING PARAMETER SWEEP: A5 Thresholds & TTL (Trade-off Analysis)")
    print("=" * 80)

    sweep_results = []
    min_flows_options = [2, 3, 5]
    ttl_options = [100, 250, 500]

    temp_out_dir = Path("outputs/temp_sweep")
    temp_out_dir.mkdir(parents=True, exist_ok=True)

    for min_f in min_flows_options:
        for ttl in ttl_options:
            print(f"\nEvaluating: min_suspicious_flows={min_f}, ttl_records={ttl}...")
            a4 = TemporalCorrelationAgent(window_records=200)
            a5 = AdaptiveDefenseAgent(min_suspicious_flows=min_f, ttl_records=ttl)
            engine = ReplayEngine(a4_agent=a4, a5_agent=a5)

            engine.run_replay(
                input_parquet=input_parquet,
                output_dir=str(temp_out_dir),
                save_trace=False
            )

            res = evaluate_replay_run(ground_truth_parquet, str(temp_out_dir))
            def_res = res["defense"]

            sweep_results.append({
                "min_suspicious_flows": min_f,
                "ttl_records": ttl,
                "containment_rate": round(def_res["containment_rate"] * 100, 2),
                "collateral_rate": round(def_res["collateral_rate"] * 100, 2),
                "pure_benign_blocked": def_res["pure_benign_blocked"],
                "mixed_benign_blocked": def_res["mixed_benign_blocked"],
                "policies_created": def_res["total_policies_created"]
            })

    # Display comparison table
    sweep_df = pd.DataFrame(sweep_results)
    print("\n" + "=" * 80)
    print("TRADE-OFF SWEEP TABLE (CONTAINMENT VS COLLATERAL):")
    print(sweep_df.to_string(index=False))
    print("=" * 80)

    # Save to JSON
    out_file = config.OUTPUTS_DIR / "experiments" / "replay_evaluation.json"
    with open(out_file, "w") as f:
        json.dump(sweep_results, f, indent=2)
    print(f"Saved sweep metrics to {out_file}")

    # Clean up temp sweep directory
    import shutil
    shutil.rmtree(temp_out_dir, ignore_errors=True)
    return sweep_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberSentinel Replay Evaluator")
    parser.add_argument("--input", type=str, default="dev_replay/replay_input.parquet")
    parser.add_argument("--ground_truth", type=str, default="dev_replay/replay_ground_truth.parquet")
    parser.add_argument("--sweep", action="store_true", help="Run parameter trade-off sweep")
    args = parser.parse_args()

    # Re-run default evaluation
    evaluate_replay_run(args.ground_truth, str(config.OUTPUTS_DIR))

    if args.sweep:
        run_threshold_sweep(args.input, args.ground_truth)
