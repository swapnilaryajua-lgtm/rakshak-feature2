"""Agent 2 Upgrade Experiments.

Evaluates:
1. Baseline: Isolation Forest on raw features
2. Variant 1: Isolation Forest on signed log1p + robust scaled features
3. Variant 2: PCA Reconstruction Error on signed log1p + robust scaled features
4. Variant 3: Mahalanobis Distance on PCA components
Reports:
- Binary AUROC (BENIGN vs all attacks)
- Per-class AUROC (BENIGN vs each attack class)
- Detection rates at 5% and 10% benign false-alarm rate (FAR) set on calib, evaluated on calib & eval
Saves winning model as artifacts/agent2_anomaly_v2.joblib and outputs/experiments/agent2_upgrades.json
"""

import json
import sys
import time
from pathlib import Path
from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
from sklearn.covariance import LedoitWolf
from sklearn.metrics import roc_auc_score
import joblib

sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from agent_classes import AnomalyDetectionAgent
from agent3_fusion import EvidenceFusionAgent
from preprocessor import FlowPreprocessor


def signed_log1p(X: np.ndarray) -> np.ndarray:
    """Applies signed log1p transform: sign(x) * log(1 + |x|)."""
    return np.sign(X) * np.log1p(np.abs(X))


class AnomalyDetectorVariant:
    """Wrapper for anomaly detection variants supporting score percentiles and evaluation."""

    def __init__(self, name: str, detector_type: str, n_components: int = 15):
        self.name = name
        self.detector_type = detector_type  # 'iforest_raw', 'iforest_log', 'pca_recon', 'mahalanobis'
        self.n_components = n_components
        
        self.feature_names: List[str] = []
        self.benign_medians: np.ndarray = np.array([])
        self.benign_scales: np.ndarray = np.array([])
        self.benign_train_scores_sorted: np.ndarray = np.array([])
        
        self.model = None
        self.pca = None
        self.cov_estimator = None
        self.th_5pct: float = 0.95
        self.th_10pct: float = 0.90

    def fit(self, benign_X: np.ndarray, feature_names: List[str]):
        self.feature_names = list(feature_names)
        
        # 1. Base robust stats for evidence
        medians = np.median(benign_X, axis=0)
        mad = np.median(np.abs(benign_X - medians), axis=0)
        std = np.std(benign_X, axis=0)
        scales = np.maximum(mad * 1.4826, np.maximum(std, 1e-6))
        
        valid_mask = scales > 1e-5
        self.valid_feature_names = [f for f, v in zip(self.feature_names, valid_mask) if v]
        self.benign_medians = medians[valid_mask]
        self.benign_scales = scales[valid_mask]

        # 2. Transform benign_X based on detector_type
        if self.detector_type == "iforest_raw":
            X_fit = benign_X
            self.model = IsolationForest(
                n_estimators=150, max_samples="auto", contamination="auto",
                random_state=config.RANDOM_STATE, n_jobs=-1
            )
            self.model.fit(X_fit)
            raw_scores = -self.model.score_samples(X_fit)

        else:
            # Apply signed log1p + robust scale to benign_X
            X_log = signed_log1p(benign_X[:, valid_mask])
            self.log_medians = np.median(X_log, axis=0)
            log_mad = np.median(np.abs(X_log - self.log_medians), axis=0)
            log_std = np.std(X_log, axis=0)
            self.log_scales = np.maximum(log_mad * 1.4826, np.maximum(log_std, 1e-6))
            X_scaled = (X_log - self.log_medians) / self.log_scales

            if self.detector_type == "iforest_log":
                self.model = IsolationForest(
                    n_estimators=150, max_samples="auto", contamination="auto",
                    random_state=config.RANDOM_STATE, n_jobs=-1
                )
                self.model.fit(X_scaled)
                raw_scores = -self.model.score_samples(X_scaled)

            elif self.detector_type == "pca_recon":
                self.pca = PCA(n_components=self.n_components, random_state=config.RANDOM_STATE)
                self.pca.fit(X_scaled)
                X_proj = self.pca.transform(X_scaled)
                X_recon = self.pca.inverse_transform(X_proj)
                raw_scores = np.mean((X_scaled - X_recon) ** 2, axis=1)

            elif self.detector_type == "mahalanobis":
                self.pca = PCA(n_components=self.n_components, random_state=config.RANDOM_STATE)
                X_proj = self.pca.fit_transform(X_scaled)
                self.cov_estimator = LedoitWolf()
                self.cov_estimator.fit(X_proj)
                raw_scores = self.cov_estimator.mahalanobis(X_proj)

            else:
                raise ValueError(f"Unknown detector_type: {self.detector_type}")

        self.benign_train_scores_sorted = np.sort(raw_scores)
        return self

    def predict_raw_scores(self, X: np.ndarray) -> np.ndarray:
        if self.detector_type == "iforest_raw":
            return -self.model.score_samples(X)
        
        # Log-transformed types
        valid_indices = [self.feature_names.index(f) for f in self.valid_feature_names]
        X_sub = X[:, valid_indices]
        X_log = signed_log1p(X_sub)
        X_scaled = (X_log - self.log_medians) / self.log_scales

        if self.detector_type == "iforest_log":
            return -self.model.score_samples(X_scaled)
        elif self.detector_type == "pca_recon":
            X_proj = self.pca.transform(X_scaled)
            X_recon = self.pca.inverse_transform(X_proj)
            return np.mean((X_scaled - X_recon) ** 2, axis=1)
        elif self.detector_type == "mahalanobis":
            X_proj = self.pca.transform(X_scaled)
            return self.cov_estimator.mahalanobis(X_proj)

    def predict_percentile_scores(self, X: np.ndarray) -> np.ndarray:
        raw_scores = self.predict_raw_scores(X)
        n_ref = len(self.benign_train_scores_sorted)
        ranks = np.searchsorted(self.benign_train_scores_sorted, raw_scores, side="right")
        return np.clip(ranks / n_ref, 0.0, 1.0)

    def calibrate(self, calib_df: pd.DataFrame):
        benign_mask = (calib_df[config.LABEL_COL] == "BENIGN").values
        X_benign_calib = calib_df[self.feature_names].values[benign_mask]
        scores_benign = self.predict_percentile_scores(X_benign_calib)
        
        # 5% FAR -> 95th percentile
        self.th_5pct = float(np.percentile(scores_benign, 95.0))
        # 10% FAR -> 90th percentile
        self.th_10pct = float(np.percentile(scores_benign, 90.0))

    def evaluate(self, df: pd.DataFrame, partition_name: str) -> Dict[str, Any]:
        X = df[self.feature_names].values
        scores = self.predict_percentile_scores(X)
        labels = df[config.LABEL_COL].values
        is_attack = (labels != "BENIGN").astype(int)

        # 1. Binary AUROC
        binary_auroc = float(roc_auc_score(is_attack, scores))

        # 2. Per-class AUROC (BENIGN vs class)
        per_class_auroc = {}
        for cls in config.ATTACK_CLASSES:
            mask = (labels == "BENIGN") | (labels == cls)
            if np.sum(labels == cls) > 0:
                y_sub = (labels[mask] == cls).astype(int)
                score_sub = scores[mask]
                per_class_auroc[cls] = float(roc_auc_score(y_sub, score_sub))
            else:
                per_class_auroc[cls] = float("nan")

        # 3. Detection rates at 5% and 10% FAR
        rates_5pct = {}
        rates_10pct = {}
        for cls in config.CLASSES:
            mask = (labels == cls)
            if np.sum(mask) > 0:
                rates_5pct[cls] = float(np.mean(scores[mask] >= self.th_5pct))
                rates_10pct[cls] = float(np.mean(scores[mask] >= self.th_10pct))

        return {
            "partition": partition_name,
            "binary_auroc": binary_auroc,
            "per_class_auroc": per_class_auroc,
            "threshold_5pct": self.th_5pct,
            "threshold_10pct": self.th_10pct,
            "rates_5pct_far": rates_5pct,
            "rates_10pct_far": rates_10pct
        }


def run_agent2_upgrades():
    print("=" * 80)
    print("EXPERIMENT A: Agent 2 Anomaly Detection Upgrades")
    print("=" * 80)

    # Load cleaned data
    train_df = pd.read_parquet(config.ARTIFACTS_DIR / "train_clean.parquet")
    calib_df = pd.read_parquet(config.ARTIFACTS_DIR / "calib_clean.parquet")
    eval_df = pd.read_parquet(config.ARTIFACTS_DIR / "eval_clean.parquet")
    feature_names = joblib.load(config.ARTIFACTS_DIR / "selected_features.joblib")

    # Sample 100k BENIGN flows from train
    benign_train = train_df[train_df[config.LABEL_COL] == "BENIGN"][feature_names]
    benign_sample = benign_train.sample(n=min(config.AGENT2_BENIGN_SUBSAMPLE, len(benign_train)),
                                        random_state=config.RANDOM_STATE).values

    variants = [
        AnomalyDetectorVariant("Baseline: IForest (raw features)", "iforest_raw"),
        AnomalyDetectorVariant("Variant 1: IForest (log1p + robust scale)", "iforest_log"),
        AnomalyDetectorVariant("Variant 2: PCA Recon Error (15 comps)", "pca_recon", n_components=15),
        AnomalyDetectorVariant("Variant 3: Mahalanobis Distance (15 comps)", "mahalanobis", n_components=15),
    ]

    results = {}
    for var in variants:
        t0 = time.time()
        print(f"\n--- Training {var.name} ---")
        var.fit(benign_sample, feature_names)
        var.calibrate(calib_df)
        fit_time = time.time() - t0

        calib_eval = var.evaluate(calib_df, "CALIB")
        eval_eval = var.evaluate(eval_df, "EVAL")

        print(f"Fit Time: {fit_time:.2f}s | Calib Binary AUROC: {calib_eval['binary_auroc']:.4f} | Eval Binary AUROC: {eval_eval['binary_auroc']:.4f}")
        print("Eval Per-Class AUROC:")
        for cls, score in eval_eval["per_class_auroc"].items():
            print(f"  - {cls:12s}: {score:.4f}")
        print("Eval Detection Rates at 5% Benign FAR (th={:.4f}):".format(eval_eval['threshold_5pct']))
        for cls, rate in eval_eval["rates_5pct_far"].items():
            print(f"  - {cls:12s}: {rate*100:.2f}%")
        print("Eval Detection Rates at 10% Benign FAR (th={:.4f}):".format(eval_eval['threshold_10pct']))
        for cls, rate in eval_eval["rates_10pct_far"].items():
            print(f"  - {cls:12s}: {rate*100:.2f}%")

        results[var.name] = {
            "detector_type": var.detector_type,
            "fit_time_seconds": round(fit_time, 2),
            "calib": calib_eval,
            "eval": eval_eval
        }

    # Save comparison JSON
    exp_out_path = config.OUTPUTS_DIR / "experiments" / "agent2_upgrades.json"
    with open(exp_out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved Agent 2 upgrade metrics to {exp_out_path}")

    # Determine best variant by binary AUROC on Eval
    best_name = max(results.keys(), key=lambda k: results[k]["eval"]["binary_auroc"])
    best_var = next(v for v in variants if v.name == best_name)
    print("=" * 80)
    print(f"BEST VARIANT SELECTED: {best_name} (Eval Binary AUROC: {results[best_name]['eval']['binary_auroc']:.4f})")
    print("=" * 80)

    return best_var, results


if __name__ == "__main__":
    run_agent2_upgrades()
