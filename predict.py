"""Batch prediction script for CyberSentinel (Level 2).

Runs Agents 1-3 on any CSV or Parquet file containing record_id and flow features.
Ignores extra endpoint columns (source_ip, destination_ip, ports, seq) for modeling.
Outputs classification.csv with columns:
record_id, predicted_class, anomaly_score, evidence_status
"""

import argparse
import time
from pathlib import Path
import pandas as pd

import config
from pipeline import CyberSentinelPipeline

STATUS_MAP = {
    "CONFIRMED": "AGREE",
    "CONFLICT_RESOLVED": "CONFLICT",
    "UNKNOWN_THREAT": "CONFLICT",
    "LOW_CONFIDENCE": "UNCERTAIN"
}


def load_input_data(input_path: Path) -> pd.DataFrame:
    """Loads CSV or Parquet input, strips column whitespace, and sorts by seq if present."""
    if input_path.suffix.lower() == ".csv":
        df = pd.read_csv(input_path)
    else:
        df = pd.read_parquet(input_path)
    df.columns = df.columns.str.strip()
    if "seq" in df.columns:
        df["seq"] = pd.to_numeric(df["seq"], errors="coerce")
        df = df.sort_values(by="seq").reset_index(drop=True)
    return df


def run_predict(input_path: str, output_path: str = None, version: str = config.MODEL_VERSION):
    input_file = Path(input_path)
    if output_path is None:
        output_file = config.OUTPUTS_DIR / "final" / "classification.csv"
    else:
        output_file = Path(output_path)

    print(f"Loading input flows from {input_file}...")
    df = load_input_data(input_file)
    n_flows = len(df)
    print(f"Loaded {n_flows} records.")

    # Load production pipeline
    pipeline = CyberSentinelPipeline.load_from_artifacts(version=version)

    t0 = time.time()
    results_df, _ = pipeline.run(df)
    elapsed = time.time() - t0
    print(f"Processed {n_flows} flows in {elapsed:.2f}s ({n_flows / max(elapsed, 0.001):.1f} flows/sec)")

    # Map internal status to official Level 2 specification (BRIEF.md Section 15.2)
    official_status = results_df["evidence_status"].map(STATUS_MAP).fillna("UNCERTAIN")

    # Prepare official classification.csv format:
    # record_id,predicted_class,anomaly_score,evidence_status
    classification_df = pd.DataFrame({
        "record_id": results_df[config.ID_COL],
        "predicted_class": results_df["final_class"],
        "anomaly_score": results_df["anomaly_score"].round(4),
        "evidence_status": official_status
    })

    output_file.parent.mkdir(parents=True, exist_ok=True)
    classification_df.to_csv(output_file, index=False)
    print(f"Saved classification results ({len(classification_df)} rows) to {output_file}")
    return classification_df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberSentinel Batch Predictor")
    parser.add_argument("--input", type=str, default=str(config.EVAL_PATH), help="Path to input parquet file")
    parser.add_argument("--output", type=str, default=None, help="Path to output classification.csv")
    parser.add_argument("--version", type=str, default=config.MODEL_VERSION, help="Model version ('v1' or 'v2')")
    args = parser.parse_args()

    run_predict(args.input, args.output, args.version)
