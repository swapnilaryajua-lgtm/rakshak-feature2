"""CyberSentinel End-to-End Pipeline

Coordinates preprocessing, Agent 1 Threat Detection, Agent 2 Anomaly Detection,
and Agent 3 Evidence Fusion. Accepts any raw flow dataframe with arbitrary extra metadata.
Supports versioning via config.MODEL_VERSION ('v1' for Day 1 baseline, 'v2' for Level 2 production).
"""

from typing import Dict, List, Any, Optional, Tuple
import pandas as pd
import joblib

import config
from preprocessor import FlowPreprocessor
from agent_classes import ThreatDetectionAgent, AnomalyDetectionAgent, AnomalyDetectionAgentV2
from agent3_fusion import EvidenceFusionAgent


class CyberSentinelPipeline:
    """Full offline multi-agent intrusion detection pipeline."""

    def __init__(self,
                 preprocessor: Optional[FlowPreprocessor] = None,
                 agent1: Optional[ThreatDetectionAgent] = None,
                 agent2: Optional[Any] = None,
                 agent3: Optional[EvidenceFusionAgent] = None,
                 version: str = config.MODEL_VERSION):
        self.preprocessor = preprocessor
        self.agent1 = agent1
        self.agent2 = agent2
        self.agent3 = agent3 or EvidenceFusionAgent()
        self.version = version

    @classmethod
    def load_from_artifacts(cls, prefix: str = "", version: str = config.MODEL_VERSION) -> "CyberSentinelPipeline":
        """Loads fitted pipeline components from artifacts based on version."""
        if version == "v2":
            prep_path = config.ARTIFACTS_DIR / f"{prefix}v2_preprocessor.joblib"
            if not prep_path.exists():
                prep_path = config.ARTIFACTS_DIR / f"{prefix}preprocessor.joblib"
            a1_path = config.ARTIFACTS_DIR / f"{prefix}agent1_threat_v2.joblib"
            a2_path = config.ARTIFACTS_DIR / f"{prefix}agent2_anomaly_v2.joblib"
        else:
            prep_path = config.ARTIFACTS_DIR / f"{prefix}preprocessor.joblib"
            a1_path = config.ARTIFACTS_DIR / f"{prefix}agent1_threat.joblib"
            a2_path = config.ARTIFACTS_DIR / f"{prefix}agent2_anomaly.joblib"

        print(f"Loading pipeline (version='{version}') components from {config.ARTIFACTS_DIR} (prefix='{prefix}')...")
        preprocessor = joblib.load(prep_path)
        agent1 = joblib.load(a1_path)
        agent2 = joblib.load(a2_path)
        agent3 = EvidenceFusionAgent()

        return cls(preprocessor, agent1, agent2, agent3, version=version)

    def run(self, raw_df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, List[Dict[str, Any]]]]:
        """Processes raw flows through the complete multi-agent pipeline.
        
        Returns:
            - Enriched master DataFrame containing all inputs, agent outputs, and decisions
            - Dictionary of JSON contract records for all three agents
        """
        assert config.ID_COL in raw_df.columns, f"Input must contain {config.ID_COL}"

        # 1. Preprocess features, preserving metadata & extras
        cleaned_df = self.preprocessor.transform(raw_df)

        # 2. Agent 1 Threat Detection
        a1_preds = self.agent1.predict_batch(cleaned_df)
        a1_json = self.agent1.to_json_records(a1_preds)

        # 3. Agent 2 Anomaly Detection
        a2_preds = self.agent2.predict_batch(cleaned_df)
        a2_json = self.agent2.to_json_records(a2_preds)

        # 4. Agent 3 Evidence Fusion
        fusion_preds = self.agent3.fuse(a1_preds, a2_preds)
        a3_json = self.agent3.to_json_records(fusion_preds)

        # 5. Assemble unified result DataFrame
        master_df = pd.DataFrame(index=raw_df.index)
        master_df[config.ID_COL] = raw_df[config.ID_COL]
        
        # If ground truth label is present in raw_df, preserve it
        if config.LABEL_COL in raw_df.columns:
            master_df[config.LABEL_COL] = raw_df[config.LABEL_COL]

        master_df["final_class"] = fusion_preds["final_class"]
        master_df["action"] = fusion_preds["action"]
        master_df["evidence_status"] = fusion_preds["evidence_status"]
        master_df["agreement"] = fusion_preds["agreement"]
        master_df["suspicious"] = fusion_preds["suspicious"]
        master_df["suspicious_strength"] = fusion_preds["suspicious_strength"]
        master_df["is_escalated"] = fusion_preds["is_escalated"]
        master_df["agent1_pred_class"] = a1_preds["agent1_pred_class"]
        master_df["agent1_confidence"] = a1_preds["agent1_confidence"]
        master_df["anomaly_score"] = a2_preds["anomaly_score"]
        master_df["is_anomalous"] = a2_preds["is_anomalous"]
        master_df["rationale"] = fusion_preds["rationale"]

        # Pass through any additional metadata columns (e.g. IPs, ports, sequence)
        extra_cols = [c for c in raw_df.columns if c not in self.preprocessor.raw_feature_cols 
                      and c not in (config.ID_COL, config.LABEL_COL)]
        for col in extra_cols:
            master_df[col] = raw_df[col]

        json_payloads = {
            "threat_detection": a1_json,
            "anomaly": a2_json,
            "evidence_fusion": a3_json
        }

        return master_df, json_payloads


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CyberSentinel Pipeline Runner")
    parser.add_argument("--input", type=str, default=str(config.EVAL_PATH))
    parser.add_argument("--sample", type=int, default=None)
    parser.add_argument("--version", type=str, default=config.MODEL_VERSION)
    args = parser.parse_args()

    pipeline = CyberSentinelPipeline.load_from_artifacts(version=args.version)
    df = pd.read_parquet(args.input)
    if args.sample:
        df = df.head(args.sample)

    results_df, _ = pipeline.run(df)
    print("Pipeline execution completed successfully!")
    print(results_df[["record_id", "final_class", "action", "evidence_status", "suspicious", "suspicious_strength"]].head(5))
