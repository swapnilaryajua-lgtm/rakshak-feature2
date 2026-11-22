"""Submission Validator for CyberSentinel (Level 2).

Implements all 7 verification checks from BRIEF.md Section 14.7:
1. File existence & row counts match input records exactly
2. Classification schema & valid classes (no empty or NaN fields)
3. Policy validity (unique IDs, scope_type==SOURCE_IP, policy_action==BLOCK)
4. ALLOW action integrity (empty applied_policy_id)
5. BLOCK action integrity (valid policy ID reference)
6. Strict causality & scope matching (no self-blocking, IP matches, within active window)
7. Replay ordering matches input sequence
Outputs PASS/FAIL for each check.
"""

import argparse
from pathlib import Path
from typing import Dict, Any, List
import pandas as pd
import numpy as np

import config


def validate_submission(input_parquet: str, outputs_dir: str = str(config.OUTPUTS_DIR)) -> bool:
    print("=" * 80)
    print("RUNNING SUBMISSION VALIDATION (BRIEF.md Section 14.7)...")
    print("=" * 80)

    input_file = Path(input_parquet)
    out_dir = Path(outputs_dir)

    class_path = out_dir / "classification.csv"
    policy_path = out_dir / "policy.csv"
    replay_path = out_dir / "replay.csv"

    checks_passed = 0
    total_checks = 7

    # -------------------------------------------------------------
    # Check 1: File existence & Exact Row Counts
    # -------------------------------------------------------------
    print("[Check 1/7] File existence & record count matching...")
    if not (class_path.exists() and policy_path.exists() and replay_path.exists()):
        print(f"  FAIL: Missing one or more required output CSVs in {out_dir}")
        return False

    raw_input = pd.read_parquet(input_file)
    class_df = pd.read_csv(class_path, dtype={"record_id": str})
    policy_df = pd.read_csv(policy_path, dtype=str)
    replay_df = pd.read_csv(replay_path, dtype={"record_id": str, "applied_policy_id": str})
    replay_df["applied_policy_id"] = replay_df["applied_policy_id"].fillna("")

    n_input = len(raw_input)
    n_class = len(class_df)
    n_replay = len(replay_df)

    if n_class != n_input or n_replay != n_input:
        print(f"  FAIL: Count mismatch! Input={n_input}, classification.csv={n_class}, replay.csv={n_replay}")
        return False

    # Check identical record ID sets and order
    input_ids = raw_input[config.ID_COL].astype(str).tolist()
    class_ids = class_df["record_id"].tolist()
    replay_ids = replay_df["record_id"].tolist()

    if input_ids != class_ids or input_ids != replay_ids:
        print("  FAIL: Record IDs do not match input file or are not in identical order!")
        return False

    print(f"  PASS: Exactly {n_input:,} records match across all files in identical order.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 2: Classification Schema & Value Validity
    # -------------------------------------------------------------
    print("\n[Check 2/7] Classification schema & value integrity...")
    expected_class_cols = {"record_id", "predicted_class", "anomaly_score", "evidence_status"}
    if not expected_class_cols.issubset(class_df.columns):
        print(f"  FAIL: Missing expected columns in classification.csv: {expected_class_cols - set(class_df.columns)}")
        return False

    # Check nulls
    if class_df.isna().sum().sum() > 0:
        print(f"  FAIL: Null values detected in classification.csv:\n{class_df.isna().sum()}")
        return False

    # Check valid classes
    invalid_classes = set(class_df["predicted_class"]) - set(config.CLASSES)
    if invalid_classes:
        print(f"  FAIL: Invalid predicted classes detected: {invalid_classes}")
        return False

    # Check anomaly scores range [0, 1]
    if (class_df["anomaly_score"] < 0.0).any() or (class_df["anomaly_score"] > 1.0).any():
        print("  FAIL: Anomaly scores outside valid [0, 1] range!")
        return False

    # Check valid evidence statuses
    valid_statuses = {"CONFIRMED", "CONFLICT_RESOLVED", "LOW_CONFIDENCE", "UNKNOWN_THREAT"}
    invalid_statuses = set(class_df["evidence_status"]) - valid_statuses
    if invalid_statuses:
        print(f"  FAIL: Invalid evidence statuses detected: {invalid_statuses}")
        return False

    print(f"  PASS: All {n_class:,} rows have valid classes, non-null values, and compliant schemas.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 3: Policy Table Schema & Integrity
    # -------------------------------------------------------------
    print("\n[Check 3/7] Policy schema & deduplication...")
    expected_policy_cols = {"policy_id", "activated_after_record_id", "scope_type",
                            "scope_value", "expires_after_record_id", "policy_action"}
    if not expected_policy_cols.issubset(policy_df.columns):
        print(f"  FAIL: Missing expected columns in policy.csv: {expected_policy_cols - set(policy_df.columns)}")
        return False

    n_policies = len(policy_df)
    if n_policies > 0:
        if policy_df["policy_id"].nunique() != n_policies:
            print("  FAIL: Duplicate policy IDs found in policy.csv!")
            return False

        if not (policy_df["scope_type"] == "SOURCE_IP").all():
            print("  FAIL: scope_type must be strictly 'SOURCE_IP'!")
            return False

        if not (policy_df["policy_action"] == "BLOCK").all():
            print("  FAIL: policy_action must be strictly 'BLOCK'!")
            return False

        # Build position lookup for causality check
        id_to_idx = {rid: i for i, rid in enumerate(input_ids)}
        
        # Verify activated_after and expires_after are valid IDs
        for _, row in policy_df.iterrows():
            act_id = row["activated_after_record_id"]
            exp_id = row["expires_after_record_id"]
            if act_id not in id_to_idx or exp_id not in id_to_idx:
                print(f"  FAIL: Policy {row['policy_id']} references non-existent record ID: act={act_id}, exp={exp_id}")
                return False
            if id_to_idx[act_id] >= id_to_idx[exp_id]:
                print(f"  FAIL: Policy {row['policy_id']} activation index >= expiration index!")
                return False

    print(f"  PASS: {n_policies:,} unique policies with compliant scope and valid activation/expiry windows.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 4: ALLOW Action Integrity
    # -------------------------------------------------------------
    print("\n[Check 4/7] ALLOW action integrity...")
    allow_mask = (replay_df["action"] == "ALLOW")
    invalid_allow_refs = (replay_df.loc[allow_mask, "applied_policy_id"] != "").sum()
    if invalid_allow_refs > 0:
        print(f"  FAIL: Found {invalid_allow_refs} ALLOW records with non-empty applied_policy_id!")
        return False
    print(f"  PASS: All {allow_mask.sum():,} ALLOW records have empty applied_policy_id.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 5: BLOCK Action Integrity
    # -------------------------------------------------------------
    print("\n[Check 5/7] BLOCK action integrity...")
    block_mask = (replay_df["action"] == "BLOCK")
    n_blocks = block_mask.sum()
    empty_block_refs = (replay_df.loc[block_mask, "applied_policy_id"] == "").sum()
    if empty_block_refs > 0:
        print(f"  FAIL: Found {empty_block_refs} BLOCK records with empty applied_policy_id!")
        return False

    valid_policy_ids = set(policy_df["policy_id"])
    block_pids = set(replay_df.loc[block_mask, "applied_policy_id"])
    dangling_pids = block_pids - valid_policy_ids
    if dangling_pids:
        print(f"  FAIL: BLOCK records reference non-existent policy IDs: {dangling_pids}")
        return False
    print(f"  PASS: All {n_blocks:,} BLOCK records reference valid existing policies.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 6: Causality & Scope Match
    # -------------------------------------------------------------
    print("\n[Check 6/7] Strict causality & policy scope verification...")
    # Build policy window mapping: policy_id -> (scope_value, act_idx, exp_idx)
    id_to_idx = {rid: i for i, rid in enumerate(input_ids)}
    policy_lookup = {}
    for _, row in policy_df.iterrows():
        policy_lookup[row["policy_id"]] = {
            "scope_value": row["scope_value"],
            "act_idx": id_to_idx[row["activated_after_record_id"]],
            "exp_idx": id_to_idx[row["expires_after_record_id"]]
        }

    source_ips = raw_input["source_ip"].astype(str).tolist()
    causality_violations = 0
    scope_mismatches = 0

    for idx in np.where(block_mask)[0]:
        pid = replay_df.at[idx, "applied_policy_id"]
        pol = policy_lookup[pid]
        src_ip = source_ips[idx]

        # Scope check: source_ip must match scope_value
        if src_ip != pol["scope_value"]:
            scope_mismatches += 1

        # Causality check: record must be AFTER activation and ON/BEFORE expiration
        if not (pol["act_idx"] < idx <= pol["exp_idx"]):
            causality_violations += 1

    if scope_mismatches > 0:
        print(f"  FAIL: {scope_mismatches} records blocked by policy with mismatched source IP!")
        return False

    if causality_violations > 0:
        print(f"  FAIL: {causality_violations} records violated temporal causality (blocked outside policy active window)!")
        return False

    print("  PASS: Zero causality violations. No policy applies to its trigger or outside its window.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 7: Replay Sequence Compliance
    # -------------------------------------------------------------
    print("\n[Check 7/7] Chronological replay order compliance...")
    if "seq" in raw_input.columns:
        input_seq = raw_input["seq"].tolist()
        if not np.all(np.diff(input_seq) >= 0):
            print("  FAIL: Input sequence not monotonic!")
            return False
    print("  PASS: Replay order strictly matches input parquet order.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------
    print("=" * 80)
    print(f"ALL {checks_passed}/{total_checks} VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("Files are 100% compliant with Level 2 submission specifications.")
    print("=" * 80)
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberSentinel Submission Validator")
    parser.add_argument("--input", type=str, default="dev_replay/replay_input.parquet")
    parser.add_argument("--outputs_dir", type=str, default=str(config.OUTPUTS_DIR))
    args = parser.parse_args()

    validate_submission(args.input, args.outputs_dir)
