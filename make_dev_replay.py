"""Simulated Replay Generator for CyberSentinel (Level 2).

Generates a realistic chronological replay stream from Cyber/eval/flows.parquet:
- Pure attacker IPs (attacks arrive in bursts)
- Pure benign client IPs (continuous legitimate traffic)
- Mixed IPs (NAT gateways / shared subnets with both benign and attack flows to test collateral damage)
- Synthetic timestamps and sequence numbers
- Saves an UNLABELED replay_input.parquet and a separate replay_ground_truth.parquet
"""

import argparse
from pathlib import Path
import time
import numpy as np
import pandas as pd

import config


def create_simulated_replay(sample_size: int = None, output_dir: str = "dev_replay"):
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(config.RANDOM_STATE)

    print("=" * 75)
    print("GENERATING SIMULATED REPLAY (SYNTHETIC ENDPOINTS)...")
    raw_eval = pd.read_parquet(config.EVAL_PATH)
    raw_eval.columns = raw_eval.columns.str.strip()

    if sample_size and sample_size < len(raw_eval):
        print(f"Sampling {sample_size} records stratified by label...")
        from sklearn.model_selection import train_test_split
        raw_eval, _ = train_test_split(
            raw_eval, train_size=sample_size,
            stratify=raw_eval[config.LABEL_COL],
            random_state=config.RANDOM_STATE
        )
        raw_eval = raw_eval.reset_index(drop=True)

    n_flows = len(raw_eval)
    print(f"Total flows in replay scenario: {n_flows}")

    # Separate benign and attacks
    benign_indices = raw_eval[raw_eval[config.LABEL_COL] == "BENIGN"].index.tolist()
    attack_indices = raw_eval[raw_eval[config.LABEL_COL] != "BENIGN"].index.tolist()

    # Define synthetic endpoints
    attacker_ips = [f"198.51.100.{i}" for i in range(1, 11)]  # 10 dedicated attacker IPs
    benign_ips = [f"192.168.1.{i}" for i in range(1, 255)] + [f"192.168.2.{i}" for i in range(1, 101)]  # 354 client IPs
    mixed_ips = [f"10.0.0.{i}" for i in range(101, 106)]      # 5 mixed NAT / gateway IPs

    dest_servers = [
        "172.16.0.10",  # Web Server 1
        "172.16.0.20",  # Web Server 2
        "172.16.0.30",  # Database
        "172.16.0.40",  # Bastion / SSH
        "172.16.0.50"   # Internal DNS
    ]

    # Assign source IPs
    source_ips = [None] * n_flows
    is_mixed = [False] * n_flows

    # 1. Distribute attacks: 85% to pure attacker IPs (in bursts), 15% to mixed IPs
    rng.shuffle(attack_indices)
    n_attacks = len(attack_indices)
    n_mixed_attacks = int(0.15 * n_attacks)
    
    mixed_attack_idx = attack_indices[:n_mixed_attacks]
    pure_attack_idx = attack_indices[n_mixed_attacks:]

    # Pure attackers get attack bursts
    for idx in pure_attack_idx:
        source_ips[idx] = rng.choice(attacker_ips)

    for idx in mixed_attack_idx:
        source_ips[idx] = rng.choice(mixed_ips)
        is_mixed[idx] = True

    # 2. Distribute benign flows: 90% to pure benign clients, 10% to mixed IPs
    rng.shuffle(benign_indices)
    n_benign = len(benign_indices)
    n_mixed_benign = int(0.08 * n_benign)

    mixed_benign_idx = benign_indices[:n_mixed_benign]
    pure_benign_idx = benign_indices[n_mixed_benign:]

    for idx in pure_benign_idx:
        source_ips[idx] = rng.choice(benign_ips)

    for idx in mixed_benign_idx:
        source_ips[idx] = rng.choice(mixed_ips)
        is_mixed[idx] = True

    # 3. Create chronological stream with temporal burst dynamics
    # Shuffle into semi-bursty ordering
    order = list(range(n_flows))
    rng.shuffle(order)

    ordered_df = raw_eval.iloc[order].reset_index(drop=True)
    ordered_source_ips = [source_ips[i] for i in order]
    ordered_is_mixed = [is_mixed[i] for i in order]

    # Assign synthetic sequence and timestamp
    base_time = pd.Timestamp("2026-10-31 10:00:00")
    # Time delta between flows ~10ms to 50ms
    time_deltas = rng.integers(5, 45, size=n_flows)
    cum_deltas = np.cumsum(time_deltas)
    timestamps = [base_time + pd.Timedelta(milliseconds=int(d)) for d in cum_deltas]

    # Assign destination IPs & ports
    dest_ips = rng.choice(dest_servers, size=n_flows)
    
    # Destination port: if Destination Port column exists in features, use it; else synthetic
    if "Destination Port" in ordered_df.columns:
        dest_ports = ordered_df["Destination Port"].astype(int).values
    else:
        dest_ports = rng.choice([80, 443, 8080, 22, 53, 3306], size=n_flows)

    protocols = rng.choice([6, 17], size=n_flows, p=[0.85, 0.15])  # TCP / UDP

    # 4. Construct Output DataFrames
    # Separate Ground Truth file
    ground_truth_df = pd.DataFrame({
        "record_id": ordered_df[config.ID_COL],
        "seq": np.arange(1, n_flows + 1),
        "timestamp": timestamps,
        "source_ip": ordered_source_ips,
        "destination_ip": dest_ips,
        "destination_port": dest_ports,
        "label": ordered_df[config.LABEL_COL],
        "is_mixed_ip": ordered_is_mixed
    })

    # Unlabeled Replay Input file (Endpoint columns + flow features; strictly NO label)
    replay_input_df = ordered_df.drop(columns=[config.LABEL_COL]).copy()
    
    # Insert endpoint columns at front
    replay_input_df.insert(1, "seq", np.arange(1, n_flows + 1))
    replay_input_df.insert(2, "timestamp", timestamps)
    replay_input_df.insert(3, "source_ip", ordered_source_ips)
    replay_input_df.insert(4, "destination_ip", dest_ips)
    replay_input_df.insert(5, "destination_port", dest_ports)
    replay_input_df.insert(6, "protocol", protocols)

    # Save to disk
    input_path = out_dir / "replay_input.parquet"
    truth_path = out_dir / "replay_ground_truth.parquet"

    replay_input_df.to_parquet(input_path, index=False)
    ground_truth_df.to_parquet(truth_path, index=False)

    print(f"Saved unlabeled replay input ({len(replay_input_df)} rows) to {input_path}")
    print(f"Saved replay ground truth ({len(ground_truth_df)} rows) to {truth_path}")
    print(f"Simulated attack flows: {(ground_truth_df['label'] != 'BENIGN').sum()}")
    print(f"Simulated benign flows: {(ground_truth_df['label'] == 'BENIGN').sum()}")
    print(f"Simulated mixed-IP flows: {sum(ordered_is_mixed)} (across {len(mixed_ips)} IPs)")
    print("=" * 75)
    return input_path, truth_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberSentinel Replay Generator")
    parser.add_argument("--sample", type=int, default=30000, help="Number of flows to simulate (default: 30000 for rapid dev)")
    parser.add_argument("--output_dir", type=str, default="dev_replay")
    args = parser.parse_args()

    create_simulated_replay(sample_size=args.sample, output_dir=args.output_dir)
