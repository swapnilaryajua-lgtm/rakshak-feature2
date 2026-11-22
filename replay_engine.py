"""CyberSentinel Replay Engine (Level 2).

Executes sequential, strictly causal traffic replay:
1. Pre-computes batch classification & anomaly detection (A1-A3)
2. For each flow in chronological sequence:
   a. Check if active policy matches source_ip -> if so, action=BLOCK, active_policy_id=policy_id (lexicographically smallest)
   b. Otherwise, action=ALLOW, active_policy_id=NONE
   c. Feed flow to A4 (Temporal Correlation) to update sliding window state
   d. A5 evaluates correlation group and may create a temporary SOURCE_IP BLOCK policy
      (affects LATER records only; triggering record remains ALLOW)
   e. Expire policies that reached their TTL
3. Writes the official submission CSVs (BRIEF.md Section 15.2):
   - classification.csv (record_id,predicted_class,anomaly_score,evidence_status)
   - replay.csv (record_id,action,active_policy_id)
   - policies.csv (policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id)
   - replay_trace.jsonl (audit trail)
"""

import argparse
from pathlib import Path
import json
import time
from typing import Dict, List, Any, Optional
import pandas as pd
import numpy as np

import config
from pipeline import CyberSentinelPipeline
from agent4_temporal import TemporalCorrelationAgent
from agent5_defense import AdaptiveDefenseAgent

STATUS_MAP = {
    "CONFIRMED": "AGREE",
    "CONFLICT_RESOLVED": "CONFLICT",
    "UNKNOWN_THREAT": "CONFLICT",
    "LOW_CONFIDENCE": "UNCERTAIN"
}


def load_replay_input(input_path: Path) -> pd.DataFrame:
    """Loads CSV or Parquet input, strips whitespace, and ensures sequence ordering."""
    if input_path.suffix.lower() == ".csv":
        df = pd.read_csv(input_path)
    else:
        df = pd.read_parquet(input_path)
    df.columns = df.columns.str.strip()
    if "seq" in df.columns:
        df["seq"] = pd.to_numeric(df["seq"], errors="coerce")
        df = df.sort_values(by="seq").reset_index(drop=True)
    return df


class ReplayEngine:
    """Orchestrates causal offline flow replay and adaptive policy actuation."""

    def __init__(self,
                 pipeline: Optional[CyberSentinelPipeline] = None,
                 a4_agent: Optional[TemporalCorrelationAgent] = None,
                 a5_agent: Optional[AdaptiveDefenseAgent] = None):
        self.pipeline = pipeline or CyberSentinelPipeline.load_from_artifacts(version=config.MODEL_VERSION)
        self.a4_agent = a4_agent or TemporalCorrelationAgent()
        self.a5_agent = a5_agent or AdaptiveDefenseAgent()

    def run_replay(self,
                   input_path: str,
                   output_dir: str = str(config.OUTPUTS_DIR / "final"),
                   save_trace: bool = True) -> Dict[str, Any]:
        inp_file = Path(input_path)
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        print("=" * 80)
        print(f"STARTING REPLAY ENGINE ON: {inp_file}")
        print("=" * 80)

        df = load_replay_input(inp_file)
        n_records = len(df)
        print(f"Loaded {n_records} replay records in chronological order.")

        # Ensure required endpoint columns exist
        if "source_ip" not in df.columns:
            raise KeyError("Replay input must contain 'source_ip' for policy matching.")

        record_ids = df[config.ID_COL].astype(str).tolist()
        source_ips = df["source_ip"].astype(str).tolist()
        dest_ips = df["destination_ip"].astype(str).tolist() if "destination_ip" in df.columns else ["172.16.0.1"] * n_records
        dest_ports = df["destination_port"].astype(int).tolist() if "destination_port" in df.columns else [80] * n_records

        # -------------------------------------------------------------
        # Step 1: Pre-compute Batch Predictions (A1-A3)
        # -------------------------------------------------------------
        print("\n[Phase 1] Pre-computing flow predictions (Agents 1-3)...")
        t0 = time.time()
        results_df, json_payloads = self.pipeline.run(df)
        t_batch = time.time() - t0
        print(f"Batch inference complete in {t_batch:.2f}s ({n_records / max(t_batch, 0.001):.1f} flows/sec).")

        # Extract per-flow outputs from results_df for causal iteration
        pred_classes = results_df["final_class"].tolist()
        confidences = results_df["agent1_confidence"].tolist()
        anom_scores = results_df["anomaly_score"].tolist()
        statuses = results_df["evidence_status"].tolist()
        suspicious_flags = results_df["suspicious"].tolist()
        suspicious_strengths = results_df["suspicious_strength"].tolist()

        # -------------------------------------------------------------
        # Step 2: Sequential Causal Replay Loop (A4-A5)
        # -------------------------------------------------------------
        print("\n[Phase 2] Executing sequential replay loop with Adaptive Defense...")
        self.a4_agent.reset()
        self.a5_agent.reset()

        actions = [None] * n_records
        active_policy_ids = ["NONE"] * n_records
        trace_logs = []

        n_blocked = 0
        n_allowed = 0
        t_loop_start = time.time()

        for idx in range(n_records):
            rid = record_ids[idx]
            src_ip = source_ips[idx]
            dst_ip = dest_ips[idx]
            dst_port = dest_ports[idx]

            # 1. Expire outdated policies at current step
            self.a5_agent.expire_policies(rid, idx)

            # 2. Policy enforcement: check if source_ip matches active BLOCK policy
            active_pol = self.a5_agent.get_active_policy(src_ip, current_record_idx=idx)
            
            if active_pol is not None:
                # Flow is BLOCKED by active policy
                action = "BLOCK"
                applied_pid = active_pol["policy_id"]
                n_blocked += 1
            else:
                # No active policy -> Flow is ALLOWED
                action = "ALLOW"
                applied_pid = "NONE"
                n_allowed += 1

            actions[idx] = action
            active_policy_ids[idx] = applied_pid

            # 3. Form flow observation for A4
            flow_obs = {
                "final_class": pred_classes[idx],
                "confidence": confidences[idx],
                "anomaly_score": anom_scores[idx],
                "evidence_status": statuses[idx],
                "suspicious": suspicious_flags[idx],
                "suspicious_strength": suspicious_strengths[idx]
            }

            # 4. A4 Temporal Correlation updates sliding window state
            group = self.a4_agent.process_flow(
                record_idx=idx,
                record_id=rid,
                source_ip=src_ip,
                destination_ip=dst_ip,
                destination_port=dst_port,
                a3_result=flow_obs
            )

            # 5. A5 Adaptive Defense evaluates group (creates policy for LATER records)
            new_policy = None
            if group is not None:
                new_policy = self.a5_agent.evaluate_group(
                    group=group,
                    trigger_record_id=rid,
                    trigger_record_idx=idx,
                    total_records=n_records,
                    record_id_lookup=record_ids
                )

            # 6. Audit trace logging (optional for debugging & demo)
            if save_trace and (idx < 500 or new_policy is not None or applied_pid != "NONE"):
                trace_entry = {
                    "seq": idx + 1,
                    "record_id": rid,
                    "source_ip": src_ip,
                    "action": action,
                    "active_policy_id": applied_pid,
                    "predicted_class": pred_classes[idx],
                    "evidence_status": statuses[idx],
                    "suspicious": suspicious_flags[idx],
                    "new_policy_activated": new_policy["policy_id"] if new_policy else None
                }
                trace_logs.append(trace_entry)

        t_loop = time.time() - t_loop_start
        print(f"Replay loop finished in {t_loop:.2f}s ({n_records / max(t_loop, 0.001):.1f} flows/sec).")
        print(f"Replay Actions: ALLOW = {n_allowed:,} ({n_allowed/n_records*100:.2f}%), BLOCK = {n_blocked:,} ({n_blocked/n_records*100:.2f}%)")
        print(f"Total Policies Created: {len(self.a5_agent.created_policies):,}")

        # -------------------------------------------------------------
        # Step 3: Write Three Official Submission CSVs (BRIEF.md Section 15.2)
        # -------------------------------------------------------------
        print("\n[Phase 3] Exporting official submission files...")

        # 1. classification.csv (record_id, predicted_class, anomaly_score, evidence_status)
        official_statuses = [STATUS_MAP.get(s, "UNCERTAIN") for s in statuses]
        class_df = pd.DataFrame({
            "record_id": record_ids,
            "predicted_class": pred_classes,
            "anomaly_score": np.round(anom_scores, 4),
            "evidence_status": official_statuses
        })
        class_path = out_dir / "classification.csv"
        class_df.to_csv(class_path, index=False)
        print(f"  -> Saved {class_path} ({len(class_df):,} rows)")

        # 2. policies.csv (policy_id, activated_after_record_id, scope_type, scope_value, expires_after_record_id)
        # Exactly matching BRIEF.md Section 15.2 & check_official.py
        policy_records = []
        for pol in self.a5_agent.created_policies:
            policy_records.append({
                "policy_id": pol["policy_id"],
                "activated_after_record_id": pol["activated_after_record_id"],
                "scope_type": pol["scope_type"],
                "scope_value": pol["scope_value"],
                "expires_after_record_id": pol["expires_after_record_id"]
            })
        
        if policy_records:
            policy_df = pd.DataFrame(policy_records)
        else:
            policy_df = pd.DataFrame(columns=[
                "policy_id", "activated_after_record_id", "scope_type",
                "scope_value", "expires_after_record_id"
            ])
        policy_path = out_dir / "policies.csv"
        policy_df.to_csv(policy_path, index=False)
        print(f"  -> Saved {policy_path} ({len(policy_df):,} rows)")

        # 3. replay.csv (record_id, action, active_policy_id)
        # Exactly matching BRIEF.md Section 15.2 & check_official.py
        replay_df = pd.DataFrame({
            "record_id": record_ids,
            "action": actions,
            "active_policy_id": active_policy_ids
        })
        replay_path = out_dir / "replay.csv"
        replay_df.to_csv(replay_path, index=False)
        print(f"  -> Saved {replay_path} ({len(replay_df):,} rows)")

        # 4. replay_trace.jsonl
        if save_trace:
            trace_path = out_dir / "replay_trace.jsonl"
            with open(trace_path, "w") as f:
                for entry in trace_logs:
                    f.write(json.dumps(entry) + "\n")
            print(f"  -> Saved {trace_path} ({len(trace_logs):,} trace logs)")

        print("=" * 80)
        return {
            "n_records": n_records,
            "n_allowed": n_allowed,
            "n_blocked": n_blocked,
            "n_policies": len(self.a5_agent.created_policies),
            "classification_csv": class_path,
            "policies_csv": policy_path,
            "replay_csv": replay_path
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberSentinel Replay Engine")
    parser.add_argument("--input", type=str, default="records.csv", help="Path to input replay CSV/Parquet")
    parser.add_argument("--output_dir", type=str, default=str(config.OUTPUTS_DIR / "final"), help="Output directory for CSVs")
    args = parser.parse_args()

    engine = ReplayEngine()
    engine.run_replay(input_path=args.input, output_dir=args.output_dir)
