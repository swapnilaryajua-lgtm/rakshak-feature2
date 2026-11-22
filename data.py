"""Data pipeline for CyberSentinel.

Handles:
- Column whitespace stripping
- Replacement of inf/-inf with NaN
- Identification and dropping of constant columns on train partition only
- Median imputation fit strictly on train partition only
- Deduplication of feature rows in training
- Stratified 80/20 split into train and calib (random_state=42)
- Saving preprocessors and datasets via joblib/parquet for fast reproducible execution
"""

import argparse
import time
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
import joblib

import config
from preprocessor import FlowPreprocessor


def prepare_datasets(sample_size: int = None, save_artifacts: bool = True):
    """Loads raw data, performs deduplication, train/calib split, fits preprocessor,
    and returns (train_df, calib_df, eval_df, preprocessor).
    """
    t0 = time.time()
    print("=" * 70)
    print(f"STAGE 1: Preparing datasets (sample_size={sample_size})...")

    # 1. Load Parquet files
    raw_train = pd.read_parquet(config.TRAIN_PATH)
    raw_eval = pd.read_parquet(config.EVAL_PATH)

    raw_train.columns = raw_train.columns.str.strip()
    raw_eval.columns = raw_eval.columns.str.strip()

    # If sampling requested (e.g. 50k rows for test)
    if sample_size and sample_size < len(raw_train):
        print(f"Sampling {sample_size} rows stratified by label from training data...")
        raw_train, _ = train_test_split(
            raw_train,
            train_size=sample_size,
            stratify=raw_train[config.LABEL_COL],
            random_state=config.RANDOM_STATE
        )
        # Sample eval proportionally
        eval_sample_size = int(sample_size * (len(raw_eval) / 456737))
        raw_eval, _ = train_test_split(
            raw_eval,
            train_size=min(eval_sample_size, len(raw_eval)),
            stratify=raw_eval[config.LABEL_COL],
            random_state=config.RANDOM_STATE
        )

    # 2. Check and drop duplicate feature rows in training (ignoring record_id)
    feature_candidates = [c for c in raw_train.columns if c not in (config.ID_COL, config.LABEL_COL)]
    n_before_dedup = len(raw_train)
    raw_train = raw_train.drop_duplicates(subset=feature_candidates, keep="first").reset_index(drop=True)
    n_dropped_dup = n_before_dedup - len(raw_train)
    print(f"Dropped {n_dropped_dup} duplicate rows in training set (remaining: {len(raw_train)}).")

    # 3. Stratified 80/20 train/calib split
    train_split, calib_split = train_test_split(
        raw_train,
        test_size=config.CALIB_SIZE,
        stratify=raw_train[config.LABEL_COL],
        random_state=config.RANDOM_STATE
    )
    train_split = train_split.reset_index(drop=True)
    calib_split = calib_split.reset_index(drop=True)
    eval_df = raw_eval.reset_index(drop=True)

    print(f"Splits created: Train={len(train_split)} rows, Calib={len(calib_split)} rows, Eval={len(eval_df)} rows")

    # 4. Fit preprocessor on train_split ONLY
    preprocessor = FlowPreprocessor()
    preprocessor.fit(train_split)
    print(f"Identified {len(preprocessor.constant_cols)} constant columns: {preprocessor.constant_cols}")
    print(f"Selected {len(preprocessor.selected_feature_cols)} active features.")

    # 5. Transform all splits
    train_clean = preprocessor.transform(train_split)
    calib_clean = preprocessor.transform(calib_split)
    eval_clean = preprocessor.transform(eval_df)

    # 6. Integrity and leak checks
    assert len(train_clean) == len(train_split)
    assert len(calib_clean) == len(calib_split)
    assert len(eval_clean) == len(eval_df)
    
    # Check for NaNs
    assert train_clean[preprocessor.selected_feature_cols].isna().sum().sum() == 0, "NaNs found in train!"
    assert calib_clean[preprocessor.selected_feature_cols].isna().sum().sum() == 0, "NaNs found in calib!"
    assert eval_clean[preprocessor.selected_feature_cols].isna().sum().sum() == 0, "NaNs found in eval!"

    # Check for disjoint record_ids
    train_ids = set(train_clean[config.ID_COL])
    calib_ids = set(calib_clean[config.ID_COL])
    eval_ids = set(eval_clean[config.ID_COL])
    assert len(train_ids & calib_ids) == 0, "Leakage: Overlap between train and calib IDs!"
    assert len(train_ids & eval_ids) == 0, "Leakage: Overlap between train and eval IDs!"
    assert len(calib_ids & eval_ids) == 0, "Leakage: Overlap between calib and eval IDs!"

    print("Integrity checks passed: Zero NaNs, zero ID overlap across all partitions.")

    # 7. Print Class Distributions
    print("\nClass distribution in Train:")
    print(train_clean[config.LABEL_COL].value_counts(normalize=True).round(4) * 100)
    print("\nClass distribution in Calib:")
    print(calib_clean[config.LABEL_COL].value_counts(normalize=True).round(4) * 100)
    print("\nClass distribution in Eval:")
    print(eval_clean[config.LABEL_COL].value_counts(normalize=True).round(4) * 100)

    # 8. Save artifacts if requested
    if save_artifacts:
        prefix = f"sample_{sample_size}_" if sample_size else ""
        joblib.dump(preprocessor, config.ARTIFACTS_DIR / f"{prefix}preprocessor.joblib")
        joblib.dump(preprocessor.selected_feature_cols, config.ARTIFACTS_DIR / f"{prefix}selected_features.joblib")
        
        train_clean.to_parquet(config.ARTIFACTS_DIR / f"{prefix}train_clean.parquet", index=False)
        calib_clean.to_parquet(config.ARTIFACTS_DIR / f"{prefix}calib_clean.parquet", index=False)
        eval_clean.to_parquet(config.ARTIFACTS_DIR / f"{prefix}eval_clean.parquet", index=False)
        print(f"Artifacts saved to {config.ARTIFACTS_DIR}")

    elapsed = time.time() - t0
    print(f"Stage 1 completed in {elapsed:.2f}s")
    print("=" * 70)
    return train_clean, calib_clean, eval_clean, preprocessor


def load_processed_data(sample_size: int = None):
    """Loads preprocessed datasets and preprocessor from artifacts if available,
    otherwise runs prepare_datasets.
    """
    prefix = f"sample_{sample_size}_" if sample_size else ""
    train_path = config.ARTIFACTS_DIR / f"{prefix}train_clean.parquet"
    calib_path = config.ARTIFACTS_DIR / f"{prefix}calib_clean.parquet"
    eval_path = config.ARTIFACTS_DIR / f"{prefix}eval_clean.parquet"
    prep_path = config.ARTIFACTS_DIR / f"{prefix}preprocessor.joblib"

    if train_path.exists() and calib_path.exists() and eval_path.exists() and prep_path.exists():
        print(f"Loading cached preprocessed data from {config.ARTIFACTS_DIR} (prefix='{prefix}')...")
        train_clean = pd.read_parquet(train_path)
        calib_clean = pd.read_parquet(calib_path)
        eval_clean = pd.read_parquet(eval_path)
        preprocessor = joblib.load(prep_path)
        return train_clean, calib_clean, eval_clean, preprocessor

    return prepare_datasets(sample_size=sample_size, save_artifacts=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stage 1 Data Pipeline")
    parser.add_argument("--sample", type=int, default=None, help="Sample size for testing (e.g. 50000)")
    args = parser.parse_args()

    prepare_datasets(sample_size=args.sample, save_artifacts=True)
