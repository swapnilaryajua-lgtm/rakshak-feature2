"""Agent 3: Evidence Fusion Agent

Combines Agent 1 (Threat Detection) and Agent 2 (Anomaly Detection) evidence:
- Cost-aware BLOCK threshold (missed attack cost 5, false block cost 1 -> threshold = 1/6)
- High classifier confidence resolution preserves near-perfect multi-class classification
- Zero-day hardened conflict rule: If Agent 1 says BENIGN but Agent 2 is anomalous,
  set evidence_status = UNKNOWN_THREAT, action = ESCALATE, suspicious = True,
  preserving final_class as Agent 1's best guess (BENIGN).
- Exposes suspicious (bool) and suspicious_strength (float) for Agent 4 Temporal Correlation.
- Generates concrete, numeric one-line rationales for each decision.
"""

from typing import Dict, List, Any
import numpy as np
import pandas as pd

import config


class EvidenceFusionAgent:
    """Agent 3: Fuses multi-class classification and one-class anomaly detection."""
    __module__ = "agent3_fusion"

    def __init__(self,
                 cost_block_threshold: float = config.COST_BLOCK_THRESHOLD,
                 abstain_threshold: float = config.ABSTAIN_CONFIDENCE_THRESHOLD,
                 high_conf_threshold: float = config.HIGH_CONFIDENCE_THRESHOLD):
        self.cost_block_threshold = cost_block_threshold
        self.abstain_threshold = abstain_threshold
        self.high_conf_threshold = high_conf_threshold

    def fuse(self, agent1_preds: pd.DataFrame, agent2_preds: pd.DataFrame) -> pd.DataFrame:
        """Fuses Agent 1 and Agent 2 predictions.
        
        Outputs columns:
        - record_id
        - final_class (best-guess class)
        - action (ALLOW, BLOCK, ESCALATE)
        - evidence_status (CONFIRMED, CONFLICT_RESOLVED, LOW_CONFIDENCE, UNKNOWN_THREAT)
        - agreement (bool)
        - suspicious (bool)
        - suspicious_strength (float)
        - is_escalated (bool)
        - rationale (str)
        """
        assert len(agent1_preds) == len(agent2_preds), "Length mismatch between agents!"

        # Extract numpy arrays / python lists for high-speed row processing
        rids = agent1_preds[config.ID_COL].tolist()
        pred_classes = agent1_preds["agent1_pred_class"].tolist()
        confidences = agent1_preds["agent1_confidence"].values
        probabilities = agent1_preds["agent1_probabilities"].tolist()

        anom_scores = agent2_preds["anomaly_score"].values
        is_anoms = agent2_preds["is_anomalous"].values
        top_features_list = agent2_preds["top_features"].tolist()

        n_rows = len(rids)
        final_classes = [None] * n_rows
        actions = [None] * n_rows
        evidence_statuses = [None] * n_rows
        agreements = [False] * n_rows
        suspicious_list = [False] * n_rows
        suspicious_strengths = [0.0] * n_rows
        rationales = [None] * n_rows
        is_escalated_list = [False] * n_rows

        for i in range(n_rows):
            cls1 = pred_classes[i]
            conf1 = float(confidences[i])
            probs1 = probabilities[i]
            p_benign = probs1.get("BENIGN", 0.0)
            p_attack = 1.0 - p_benign

            anom_score = float(anom_scores[i])
            is_anom = bool(is_anoms[i])
            top_feats = top_features_list[i]

            if top_feats and len(top_feats) > 0:
                top_str = f"driven by {top_feats[0]['name']} ({top_feats[0]['direction']}, z={top_feats[0]['z']})"
            else:
                top_str = "no feature deviation"

            # Classification output always preserves Agent 1's best guess
            final_class = cls1
            is_attack1 = (cls1 != "BENIGN")

            # 1. Agreement: Both Attack or Both Benign
            if is_attack1 and is_anom:
                agreement = True
                status = "CONFIRMED"
                action = "BLOCK"
                suspicious = True
                suspicious_strength = max(anom_score, conf1)
                rationale = f"Classifier: {cls1} ({conf1:.2f}). Anomaly {anom_score:.2f} {top_str}. Agents agree -> BLOCK."

            elif (not is_attack1) and (not is_anom):
                agreement = True
                status = "CONFIRMED"
                action = "ALLOW"
                suspicious = False
                suspicious_strength = anom_score
                rationale = f"Classifier: BENIGN ({conf1:.2f}). Anomaly {anom_score:.2f} (normal). Agents agree -> ALLOW."

            # 2. Disagreement A: Classifier Attack, Anomaly Normal
            elif is_attack1 and (not is_anom):
                agreement = False
                suspicious = True
                suspicious_strength = conf1
                if conf1 >= self.high_conf_threshold:
                    status = "CONFLICT_RESOLVED"
                    action = "BLOCK" if p_attack >= self.cost_block_threshold else "ALLOW"
                    rationale = f"Classifier: {cls1} ({conf1:.2f}). Anomaly {anom_score:.2f} (normal). High classifier confidence overrides -> BLOCK."
                else:
                    status = "LOW_CONFIDENCE"
                    action = "ESCALATE"
                    rationale = f"Classifier: {cls1} ({conf1:.2f}) contradicts normal anomaly score {anom_score:.2f}. Confidence < {self.high_conf_threshold:.2f} -> ESCALATE."

            # 3. Disagreement B: Classifier Benign, Anomaly Alert (Zero-Day Hardened Rule)
            else:  # not is_attack1 and is_anom
                agreement = False
                status = "UNKNOWN_THREAT"
                action = "ESCALATE"
                suspicious = True
                suspicious_strength = anom_score
                rationale = f"Classifier: BENIGN ({conf1:.2f}). Anomaly {anom_score:.2f} {top_str}. Potential novel threat -> UNKNOWN_THREAT, ESCALATE."

            # Global low confidence check
            if conf1 < self.abstain_threshold and action != "ESCALATE":
                status = "LOW_CONFIDENCE"
                action = "ESCALATE"
                rationale = f"Classifier confidence {conf1:.2f} below abstain threshold {self.abstain_threshold:.2f} -> ESCALATE."

            final_classes[i] = final_class
            actions[i] = action
            evidence_statuses[i] = status
            agreements[i] = agreement
            suspicious_list[i] = suspicious
            suspicious_strengths[i] = round(suspicious_strength, 4)
            rationales[i] = rationale
            is_escalated_list[i] = (action == "ESCALATE")

        out = pd.DataFrame(index=agent1_preds.index)
        out[config.ID_COL] = rids
        out["final_class"] = final_classes
        out["action"] = actions
        out["evidence_status"] = evidence_statuses
        out["agreement"] = agreements
        out["suspicious"] = suspicious_list
        out["suspicious_strength"] = suspicious_strengths
        out["is_escalated"] = is_escalated_list
        out["rationale"] = rationales

        # Pass through extra columns
        extra_cols = [c for c in agent1_preds.columns if c not in (config.ID_COL, "agent1_pred_class", "agent1_confidence", "agent1_probabilities")]
        for col in extra_cols:
            out[col] = agent1_preds[col]

        return out

    def to_json_records(self, fusion_df: pd.DataFrame) -> List[Dict[str, Any]]:
        records = []
        for _, row in fusion_df.iterrows():
            record = {
                "record_id": str(row[config.ID_COL]),
                "agent": "evidence_fusion",
                "final_class": row["final_class"],
                "action": row["action"],
                "evidence_status": row["evidence_status"],
                "agreement": bool(row["agreement"]),
                "suspicious": bool(row["suspicious"]),
                "suspicious_strength": float(row["suspicious_strength"]),
                "rationale": row["rationale"]
            }
            records.append(record)
        return records
