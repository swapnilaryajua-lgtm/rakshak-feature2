"""Agent 4: Temporal Correlation Agent (Level 2).

Maintains a strictly causal sliding window per source IP.
Groups related suspicious flows (A3 says attack or suspicious==True).
Identifies attack patterns:
- port_sweep (many distinct destination ports)
- flood_attack (high-volume DoS / DDoS)
- brute_force_burst (repeated authentication attempts)
- novel_anomaly_cluster (repeated unknown threat anomalies)
Outputs JSON schema defined in BRIEF.md Section 14.5.
"""

from collections import deque, Counter
from typing import Dict, List, Any, Optional
import numpy as np

import config


class TemporalCorrelationAgent:
    """Agent 4: Causal sliding-window tracker and correlation group generator."""

    def __init__(self, window_records: int = config.A4_WINDOW_RECORDS):
        self.window_records = window_records
        # Mapping from source_ip -> deque of flow dicts within sliding window
        self.ip_windows: Dict[str, deque] = {}
        self.group_counter: int = 1
        # Track group IDs assigned per IP
        self.ip_group_ids: Dict[str, str] = {}

    def reset(self):
        """Resets agent state for a fresh replay run."""
        self.ip_windows.clear()
        self.group_counter = 1
        self.ip_group_ids.clear()

    def process_flow(self,
                     record_idx: int,
                     record_id: str,
                     source_ip: str,
                     destination_ip: str,
                     destination_port: int,
                     a3_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Processes a single flow arriving at replay position record_idx.
        
        Strictly causal: only uses flows seen up to this point.
        Returns a group correlation dictionary if suspicious flows exist in the window.
        """
        if not source_ip:
            return None

        # Extract classification & suspicion signals from A3
        final_class = a3_result.get("final_class", "BENIGN")
        confidence = float(a3_result.get("agent1_confidence", a3_result.get("confidence", 1.0)))
        anom_score = float(a3_result.get("anomaly_score", 0.0))
        is_suspicious = bool(a3_result.get("suspicious", False) or (final_class != "BENIGN"))
        suspicious_strength = float(a3_result.get("suspicious_strength", anom_score if final_class == "BENIGN" else confidence))
        evidence_status = a3_result.get("evidence_status", "CONFIRMED")

        if source_ip not in self.ip_windows:
            self.ip_windows[source_ip] = deque()

        # Evict records older than window_records from this source_ip's queue
        ip_queue = self.ip_windows[source_ip]
        while ip_queue and (record_idx - ip_queue[0]["record_idx"] >= self.window_records):
            ip_queue.popleft()

        # Append current flow record
        current_flow = {
            "record_idx": record_idx,
            "record_id": record_id,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "final_class": final_class,
            "confidence": confidence,
            "anom_score": anom_score,
            "is_suspicious": is_suspicious,
            "suspicious_strength": suspicious_strength,
            "evidence_status": evidence_status
        }
        ip_queue.append(current_flow)

        # Collect suspicious flows within the window
        suspicious_flows = [f for f in ip_queue if f["is_suspicious"]]
        n_suspicious = len(suspicious_flows)

        # Only generate a group if there is suspicious activity
        if n_suspicious == 0:
            return None

        # Reuse or assign stable group_id for this active correlation cluster
        if source_ip not in self.ip_group_ids:
            self.ip_group_ids[source_ip] = f"G{self.group_counter:04d}"
            self.group_counter += 1
        group_id = self.ip_group_ids[source_ip]

        # Compute summary stats over suspicious flows
        member_record_ids = [f["record_id"] for f in suspicious_flows]
        dst_ports = [f["destination_port"] for f in suspicious_flows]
        distinct_dst_ports = len(set(dst_ports))
        mean_conf = float(np.mean([f["suspicious_strength"] for f in suspicious_flows]))
        
        # Majority class among suspicious flows
        class_counts = Counter(f["final_class"] for f in suspicious_flows)
        majority_class = class_counts.most_common(1)[0][0]

        # Total flows from this IP in the window (for benign share calculation)
        total_window_flows = len(ip_queue)
        benign_flows_count = total_window_flows - n_suspicious
        benign_share = float(benign_flows_count / total_window_flows)

        # Check if any suspicious flow has Agent 1 predicting non-BENIGN with confidence >= 0.9
        has_high_conf_attack = any(
            f["final_class"] != "BENIGN" and f["confidence"] >= 0.9 
            for f in suspicious_flows
        )

        # Pattern identification
        if distinct_dst_ports >= 4 or (distinct_dst_ports >= 3 and distinct_dst_ports / n_suspicious >= 0.4):
            pattern = "port_sweep"
            evidence = f"{n_suspicious} suspicious flows from {source_ip} within {self.window_records} records, {distinct_dst_ports} distinct destination ports"
        elif majority_class in ("DOS", "DDOS"):
            pattern = "flood_attack"
            evidence = f"{n_suspicious} high-rate flood flows ({majority_class}) from {source_ip} within {self.window_records} records"
        elif majority_class == "BRUTE_FORCE":
            pattern = "brute_force_burst"
            evidence = f"{n_suspicious} repeated authentication attempts ({majority_class}) from {source_ip} targeting service port {dst_ports[0]}"
        elif majority_class == "BENIGN" or any(f["evidence_status"] == "UNKNOWN_THREAT" for f in suspicious_flows):
            pattern = "novel_anomaly_cluster"
            evidence = f"{n_suspicious} anomalous flows (unknown threat cluster) from {source_ip} within {self.window_records} records (mean anomaly: {mean_conf:.2f})"
        else:
            pattern = "suspicious_burst"
            evidence = f"{n_suspicious} suspicious flows ({majority_class}) from {source_ip} within {self.window_records} records"

        group_record = {
            "agent": "temporal_correlation",
            "group_id": group_id,
            "source_ip": source_ip,
            "member_record_ids": member_record_ids,
            "window_records": self.window_records,
            "stats": {
                "n_flows": n_suspicious,
                "total_flows": total_window_flows,
                "benign_share": round(benign_share, 4),
                "distinct_dst_ports": distinct_dst_ports,
                "mean_confidence": round(mean_conf, 4),
                "majority_class": majority_class,
                "has_high_conf_attack": has_high_conf_attack
            },
            "pattern": pattern,
            "evidence": evidence
        }

        return group_record
