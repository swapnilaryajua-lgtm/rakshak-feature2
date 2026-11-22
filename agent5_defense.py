"""Agent 5: Adaptive Defense Agent (Level 2).

Generates temporary simulated BLOCK policies per SOURCE_IP from Agent 4 correlation groups.
Safeguards:
- Requires group-level evidence (min_suspicious_flows >= 3) to prevent false blocking from single 5% benign anomaly noise.
- Checks confidence and benign share within the temporal window.
- No duplicate active policies for an already blocked IP.
- Enforces strict causality: policy is activated AFTER the triggering record and expires after TTL records.
Outputs JSON schema defined in BRIEF.md Section 14.5.
"""

from typing import Dict, List, Any, Optional
import config


class AdaptiveDefenseAgent:
    """Agent 5: Generates and tracks active simulated firewall defense policies."""

    def __init__(self,
                 min_suspicious_flows: int = config.A5_MIN_SUSPICIOUS_FLOWS,
                 min_confidence: float = config.A5_MIN_CONFIDENCE,
                 max_benign_share: float = config.A5_MAX_BENIGN_SHARE,
                 ttl_records: int = config.A5_POLICY_TTL_RECORDS):
        self.min_suspicious_flows = min_suspicious_flows
        self.min_confidence = min_confidence
        self.max_benign_share = max_benign_share
        self.ttl_records = ttl_records
        
        self.policy_counter: int = 1
        # Track active policies: source_ip -> policy_dict
        self.active_policies_by_ip: Dict[str, Dict[str, Any]] = {}
        # History of all policies created
        self.created_policies: List[Dict[str, Any]] = []

    def reset(self):
        """Resets state for a fresh replay run."""
        self.policy_counter = 1
        self.active_policies_by_ip.clear()
        self.created_policies.clear()

    def get_active_policy(self, source_ip: str, current_record_idx: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Returns the lexicographically smallest matching active policy for this IP if one exists."""
        if current_record_idx is not None:
            matching = [p for p in self.created_policies 
                        if p["activated_idx"] < current_record_idx <= p["expires_idx"] 
                        and p["scope_value"] == source_ip]
            if matching:
                return min(matching, key=lambda p: p["policy_id"])
            return None
        return self.active_policies_by_ip.get(source_ip, None)

    def expire_policies(self, current_record_id: str, current_record_idx: int):
        """Removes policies that have expired at or before the current record."""
        expired_ips = []
        for ip, policy in self.active_policies_by_ip.items():
            if current_record_idx > policy["expires_idx"]:
                expired_ips.append(ip)

        for ip in expired_ips:
            del self.active_policies_by_ip[ip]

    def evaluate_group(self,
                       group: Dict[str, Any],
                       trigger_record_id: str,
                       trigger_record_idx: int,
                       total_records: int,
                       record_id_lookup: List[str]) -> Optional[Dict[str, Any]]:
        """Evaluates an Agent 4 correlation group.
        
        If criteria are met and IP is not already blocked, creates a new BLOCK policy.
        """
        source_ip = group["source_ip"]
        stats = group["stats"]
        n_flows = stats["n_flows"]
        mean_conf = stats["mean_confidence"]
        benign_share = stats["benign_share"]
        pattern = group["pattern"]
        has_high_conf_attack = stats.get("has_high_conf_attack", False)

        # Check 1: Deduplication - IP must not already have an active policy on the next record
        if any(p["activated_idx"] < (trigger_record_idx + 1) <= p["expires_idx"] and p["scope_value"] == source_ip 
               for p in self.created_policies):
            return None

        # Check 1b: End of dataset safeguard - cannot activate on or after the last record
        if trigger_record_idx >= total_records - 1:
            return None

        # Check 2: Minimum suspicious volume safeguard
        # Single suspicious flow is weak evidence (5% benign noise); require group evidence (min_suspicious_flows >= 2)
        if n_flows < self.min_suspicious_flows:
            return None

        # Check 3: Confidence threshold
        if mean_conf < self.min_confidence:
            return None

        # Check 4: Benign share safeguard (skip IPs whose recent traffic is predominantly benign)
        # Exception: high attack volume (e.g. >= 6 attacks) overrides higher benign share
        if benign_share > self.max_benign_share and n_flows < 6:
            return None

        # Calculate expiration index and verify strict ordering
        expires_idx = min(trigger_record_idx + self.ttl_records, total_records - 1)
        if expires_idx <= trigger_record_idx:
            return None

        # Criteria passed -> Create Policy
        policy_id = f"P{self.policy_counter:04d}"
        self.policy_counter += 1
        expires_after_record_id = record_id_lookup[expires_idx]

        reason = f"{group['group_id']}: {pattern}, {n_flows} suspicious flows"

        policy_record = {
            "agent": "adaptive_defense",
            "policy_id": policy_id,
            "activated_after_record_id": trigger_record_id,
            "scope_type": config.A5_SCOPE_TYPE,
            "scope_value": source_ip,
            "expires_after_record_id": expires_after_record_id,
            "policy_action": config.A5_POLICY_ACTION,
            "reason": reason,
            # Internal tracking fields
            "activated_idx": trigger_record_idx,
            "expires_idx": expires_idx
        }

        # Activate policy for future records
        self.active_policies_by_ip[source_ip] = policy_record
        self.created_policies.append(policy_record)
        return policy_record
