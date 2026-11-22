"""Diagnostic script for Agent 1 feature importances and train-eval duplicate analysis."""

import sys
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score
import joblib

import config
import agent1_threat
sys.modules['__main__'].ThreatDetectionAgent = agent1_threat.ThreatDetectionAgent

# 1. Load Agent 1 and features
agent1 = joblib.load(config.ARTIFACTS_DIR / "agent1_threat.joblib")
feature_names = agent1.feature_names
importances = agent1.model.feature_importances_

# Re-save agent1 with clean module reference
agent1.__class__.__module__ = "agent1_threat"
joblib.dump(agent1, config.ARTIFACTS_DIR / "agent1_threat.joblib")

imp_df = pd.DataFrame({
    "feature": feature_names,
    "importance": importances
}).sort_values(by="importance", ascending=False).reset_index(drop=True)

print("=" * 70)
print("DIAGNOSTIC (A): Top 10 LightGBM Feature Importances:")
print(imp_df.head(10).to_string(index=True))
print("=" * 70)

# Check if any top feature looks ID-like
suspicious = [f for f in imp_df.head(10)["feature"] if any(k in f.lower() for k in ["id", "index", "row", "key", "time", "date"])]
print("Suspicious / ID-like features in top 10:", suspicious if suspicious else "None (all are valid network flow statistics)")
print("=" * 70)

# 2. Train-Eval Feature Duplication Analysis
print("DIAGNOSTIC (B): Analyzing cross-split feature duplication...")
train_df = pd.read_parquet(config.ARTIFACTS_DIR / "train_clean.parquet")
eval_df = pd.read_parquet(config.ARTIFACTS_DIR / "eval_clean.parquet")

# Hash feature rows for fast exact matching
print("Hashing feature vectors for exact duplicate lookup...")
train_hashes = pd.util.hash_pandas_object(train_df[feature_names], index=False)
eval_hashes = pd.util.hash_pandas_object(eval_df[feature_names], index=False)

train_hash_set = set(train_hashes)
is_eval_in_train = eval_hashes.isin(train_hash_set)

n_eval = len(eval_df)
n_eval_dups = int(is_eval_in_train.sum())
n_eval_novel = n_eval - n_eval_dups

print(f"Total Eval flows: {n_eval}")
print(f"Eval flows with exact duplicate feature vector in Train: {n_eval_dups} ({n_eval_dups/n_eval*100:.2f}%)")
print(f"Eval flows with NO duplicate in Train (novel flows): {n_eval_novel} ({n_eval_novel/n_eval*100:.2f}%)")

# Predict on full eval and eval novel subset
preds_full = agent1.predict_batch(eval_df)
y_true_full = eval_df[config.LABEL_COL]
y_pred_full = preds_full["agent1_pred_class"]

acc_full = accuracy_score(y_true_full, y_pred_full)
macro_f1_full = f1_score(y_true_full, y_pred_full, average="macro")

eval_novel_df = eval_df[~is_eval_in_train].reset_index(drop=True)
preds_novel = preds_full[~is_eval_in_train].reset_index(drop=True)
y_true_novel = eval_novel_df[config.LABEL_COL]
y_pred_novel = preds_novel["agent1_pred_class"]

acc_novel = accuracy_score(y_true_novel, y_pred_novel)
macro_f1_novel = f1_score(y_true_novel, y_pred_novel, average="macro")

print("-" * 70)
print(f"Full Eval ({n_eval} rows)           : Accuracy = {acc_full*100:.2f}%, Macro-F1 = {macro_f1_full:.4f}")
print(f"Novel Eval ({n_eval_novel} rows, no train dups): Accuracy = {acc_novel*100:.2f}%, Macro-F1 = {macro_f1_novel:.4f}")
print("-" * 70)
print("Per-class F1 on Novel Eval subset:")
per_class_f1_novel = f1_score(y_true_novel, y_pred_novel, average=None, labels=config.CLASSES)
for cls_name, f1 in zip(config.CLASSES, per_class_f1_novel):
    print(f"  - {cls_name:12s}: {f1:.4f}")
print("=" * 70)
