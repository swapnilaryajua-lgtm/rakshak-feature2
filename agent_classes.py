"""Agent model definitions for CyberSentinel.

Houses ThreatDetectionAgent and AnomalyDetectionAgent classes to ensure clean,
module-level pickling and unpickling across all stages and entry points.
"""

import time
from typing import Dict, List, Any, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest

try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False

import config


class ThreatDetectionAgent:
    """Agent 1: Classifies network flows into 5 classes with confidence and probabilities."""

    def __init__(self, n_estimators: int = config.AGENT1_N_ESTIMATORS):
        self.n_estimators = n_estimators
        self.classes = config.CLASSES
        self.class_to_idx = {c: i for i, c in enumerate(self.classes)}
        self.idx_to_class = {i: c for i, c in enumerate(self.classes)}
        self.feature_names: List[str] = []
        self.model = None
        self.model_type: Optional[str] = None
        self.training_time: float = 0.0

    def fit(self, train_df: pd.DataFrame, feature_names: List[str]):
        """Fits model strictly on train features and train labels."""
        self.feature_names = list(feature_names)
        X = train_df[self.feature_names]
        y = train_df[config.LABEL_COL].map(self.class_to_idx).values

        print(f"Training Threat Detection Agent ({len(X)} rows, {len(self.feature_names)} features)...")
        t0 = time.time()

        if HAS_LIGHTGBM:
            self.model_type = "LightGBM"
            self.model = lgb.LGBMClassifier(
                n_estimators=self.n_estimators,
                learning_rate=config.AGENT1_LEARNING_RATE,
                num_leaves=config.AGENT1_NUM_LEAVES,
                class_weight="balanced",
                random_state=config.RANDOM_STATE,
                n_jobs=-1,
                verbose=-1
            )
        else:
            self.model_type = "RandomForest"
            self.model = RandomForestClassifier(
                n_estimators=100,
                class_weight="balanced",
                random_state=config.RANDOM_STATE,
                n_jobs=-1
            )

        self.model.fit(X, y)
        self.training_time = time.time() - t0
        print(f"Agent 1 trained using {self.model_type} in {self.training_time:.2f}s")
        return self

    def predict_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """Takes a dataframe with record_id and features, returns predictions dataframe.
        Preserves record_id and any extra columns.
        """
        X = df[self.feature_names]
        probs = self.model.predict_proba(X)

        if probs.shape[1] < len(self.classes):
            full_probs = np.zeros((len(df), len(self.classes)))
            for local_idx, class_idx in enumerate(self.model.classes_):
                full_probs[:, class_idx] = probs[:, local_idx]
            probs = full_probs

        pred_indices = np.argmax(probs, axis=1)
        confidences = np.max(probs, axis=1)
        pred_classes = [self.idx_to_class[i] for i in pred_indices]

        out = pd.DataFrame(index=df.index)
        out[config.ID_COL] = df[config.ID_COL]
        out["agent1_pred_class"] = pred_classes
        out["agent1_confidence"] = np.round(confidences, 4)

        prob_dicts = []
        for row in probs:
            p_dict = {c: float(np.round(p, 4)) for c, p in zip(self.classes, row)}
            prob_dicts.append(p_dict)
        out["agent1_probabilities"] = prob_dicts

        extra_cols = [c for c in df.columns if c not in self.feature_names and c not in (config.ID_COL, config.LABEL_COL)]
        for col in extra_cols:
            out[col] = df[col]

        return out

    def to_json_records(self, pred_df: pd.DataFrame) -> List[Dict[str, Any]]:
        records = []
        for _, row in pred_df.iterrows():
            record = {
                "record_id": str(row[config.ID_COL]),
                "agent": "threat_detection",
                "predicted_class": row["agent1_pred_class"],
                "confidence": float(row["agent1_confidence"]),
                "probabilities": row["agent1_probabilities"]
            }
            records.append(record)
        return records


class AnomalyDetectionAgent:
    """Agent 2: One-class Isolation Forest on BENIGN traffic with robust z-score explanation."""

    def __init__(self,
                 n_estimators: int = config.AGENT2_N_ESTIMATORS,
                 benign_subsample: int = config.AGENT2_BENIGN_SUBSAMPLE,
                 percentile_threshold: float = config.ANOMALY_PERCENTILE_THRESHOLD):
        self.n_estimators = n_estimators
        self.benign_subsample = benign_subsample
        self.percentile_threshold = percentile_threshold
        self.feature_names: List[str] = []
        self.valid_feature_names: List[str] = []

        self.benign_medians: np.ndarray = np.array([])
        self.benign_scales: np.ndarray = np.array([])
        self.benign_train_scores_sorted: np.ndarray = np.array([])

        self.model: Optional[IsolationForest] = None
        self.calibrated_threshold: float = percentile_threshold
        self.training_time: float = 0.0

    def fit(self, train_df: pd.DataFrame, feature_names: List[str]):
        """Fits Isolation Forest ONLY on BENIGN training flows."""
        t0 = time.time()
        self.feature_names = list(feature_names)

        benign_train = train_df[train_df[config.LABEL_COL] == "BENIGN"][self.feature_names]
        if self.benign_subsample and len(benign_train) > self.benign_subsample:
            benign_sample = benign_train.sample(n=self.benign_subsample, random_state=config.RANDOM_STATE)
        else:
            benign_sample = benign_train

        print(f"Fitting Agent 2 Isolation Forest on {len(benign_sample)} BENIGN train flows...")

        X_benign = benign_sample.values
        medians = np.median(X_benign, axis=0)
        mad = np.median(np.abs(X_benign - medians), axis=0)
        std = np.std(X_benign, axis=0)

        # scale = max(MAD * 1.4826, std, 1e-6)
        scales = np.maximum(mad * 1.4826, np.maximum(std, 1e-6))

        valid_mask = scales > 1e-5
        self.valid_feature_names = [f for f, v in zip(self.feature_names, valid_mask) if v]
        self.benign_medians = medians[valid_mask]
        self.benign_scales = scales[valid_mask]

        print(f"Robust evidence scale initialized across {len(self.valid_feature_names)} active features.")

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples="auto",
            contamination="auto",
            random_state=config.RANDOM_STATE,
            n_jobs=-1
        )
        self.model.fit(X_benign)

        raw_benign_scores = -self.model.score_samples(X_benign)
        self.benign_train_scores_sorted = np.sort(raw_benign_scores)

        self.training_time = time.time() - t0
        print(f"Agent 2 trained in {self.training_time:.2f}s")
        return self

    def calibrate_threshold(self, calib_df: pd.DataFrame):
        benign_calib = calib_df[calib_df[config.LABEL_COL] == "BENIGN"]
        scores = self.predict_scores(benign_calib)
        self.calibrated_threshold = float(np.percentile(scores, self.percentile_threshold * 100))
        print(f"Calibrated is_anomalous threshold on calib: {self.calibrated_threshold:.4f} (target: {self.percentile_threshold})")
        return self.calibrated_threshold

    def predict_scores(self, df: pd.DataFrame) -> np.ndarray:
        X = df[self.feature_names].values
        raw_scores = -self.model.score_samples(X)
        n_ref = len(self.benign_train_scores_sorted)
        ranks = np.searchsorted(self.benign_train_scores_sorted, raw_scores, side="right")
        percentiles = ranks / n_ref
        return np.clip(percentiles, 0.0, 1.0)

    def extract_top_evidence(self, X_valid: np.ndarray) -> List[List[Dict[str, Any]]]:
        z_scores = (X_valid - self.benign_medians) / self.benign_scales
        abs_z = np.abs(z_scores)

        top3_indices = np.argsort(-abs_z, axis=1)[:, :3]
        all_evidence = []

        for row_idx, indices in enumerate(top3_indices):
            row_evidence = []
            for col_idx in indices:
                feat_name = self.valid_feature_names[col_idx]
                val = float(X_valid[row_idx, col_idx])
                z_val = float(z_scores[row_idx, col_idx])
                direction = "high" if z_val >= 0 else "low"
                row_evidence.append({
                    "name": feat_name,
                    "value": round(val, 2),
                    "z": round(z_val, 2),
                    "direction": direction
                })
            all_evidence.append(row_evidence)

        return all_evidence

    def predict_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        scores = self.predict_scores(df)
        is_anomalous = scores >= self.calibrated_threshold

        X_valid = df[self.valid_feature_names].values
        top_features = self.extract_top_evidence(X_valid)

        out = pd.DataFrame(index=df.index)
        out[config.ID_COL] = df[config.ID_COL]
        out["anomaly_score"] = np.round(scores, 4)
        out["is_anomalous"] = is_anomalous
        out["top_features"] = top_features

        extra_cols = [c for c in df.columns if c not in self.feature_names and c not in (config.ID_COL, config.LABEL_COL)]
        for col in extra_cols:
            out[col] = df[col]

        return out

    def to_json_records(self, pred_df: pd.DataFrame) -> List[Dict[str, Any]]:
        records = []
        for _, row in pred_df.iterrows():
            record = {
                "record_id": str(row[config.ID_COL]),
                "agent": "anomaly",
                "anomaly_score": float(row["anomaly_score"]),
                "is_anomalous": bool(row["is_anomalous"]),
                "top_features": row["top_features"]
            }
            records.append(record)
        return records


def signed_log1p(X: np.ndarray) -> np.ndarray:
    return np.sign(X) * np.log1p(np.abs(X))


class AnomalyDetectionAgentV2:
    """Agent 2 (v2): Ledoit-Wolf Mahalanobis distance on PCA components of signed log1p + robust scaled features."""

    def __init__(self,
                 n_components: int = 15,
                 benign_subsample: int = config.AGENT2_BENIGN_SUBSAMPLE,
                 percentile_threshold: float = config.ANOMALY_PERCENTILE_THRESHOLD):
        self.n_components = n_components
        self.benign_subsample = benign_subsample
        self.percentile_threshold = percentile_threshold
        self.feature_names: List[str] = []
        self.valid_feature_names: List[str] = []

        # Evidence engine parameters (top-3 robust z-scores with floor)
        self.benign_medians: np.ndarray = np.array([])
        self.benign_scales: np.ndarray = np.array([])

        # Log1p + robust scale parameters for model inference
        self.log_medians: np.ndarray = np.array([])
        self.log_scales: np.ndarray = np.array([])

        self.pca = None
        self.cov_estimator = None
        self.benign_train_scores_sorted: np.ndarray = np.array([])
        self.calibrated_threshold: float = percentile_threshold
        self.training_time: float = 0.0

    def fit(self, train_df: pd.DataFrame, feature_names: List[str]):
        from sklearn.decomposition import PCA
        from sklearn.covariance import LedoitWolf
        t0 = time.time()
        self.feature_names = list(feature_names)

        benign_train = train_df[train_df[config.LABEL_COL] == "BENIGN"][self.feature_names]
        if self.benign_subsample and len(benign_train) > self.benign_subsample:
            benign_sample = benign_train.sample(n=self.benign_subsample, random_state=config.RANDOM_STATE)
        else:
            benign_sample = benign_train

        X_benign = benign_sample.values

        # 1. Base robust stats for evidence engine (scale = max(MAD*1.4826, std, 1e-6))
        medians = np.median(X_benign, axis=0)
        mad = np.median(np.abs(X_benign - medians), axis=0)
        std = np.std(X_benign, axis=0)
        scales = np.maximum(mad * 1.4826, np.maximum(std, 1e-6))

        valid_mask = scales > 1e-5
        self.valid_feature_names = [f for f, v in zip(self.feature_names, valid_mask) if v]
        self.benign_medians = medians[valid_mask]
        self.benign_scales = scales[valid_mask]

        # 2. Signed log1p + robust scale on valid features
        X_sub = X_benign[:, valid_mask]
        X_log = signed_log1p(X_sub)
        self.log_medians = np.median(X_log, axis=0)
        log_mad = np.median(np.abs(X_log - self.log_medians), axis=0)
        log_std = np.std(X_log, axis=0)
        self.log_scales = np.maximum(log_mad * 1.4826, np.maximum(log_std, 1e-6))

        X_scaled = (X_log - self.log_medians) / self.log_scales

        # 3. PCA + Ledoit-Wolf Mahalanobis
        self.pca = PCA(n_components=self.n_components, random_state=config.RANDOM_STATE)
        X_proj = self.pca.fit_transform(X_scaled)

        self.cov_estimator = LedoitWolf()
        self.cov_estimator.fit(X_proj)

        raw_scores = self.cov_estimator.mahalanobis(X_proj)
        self.benign_train_scores_sorted = np.sort(raw_scores)

        self.training_time = time.time() - t0
        print(f"Agent 2 (v2) trained in {self.training_time:.2f}s")
        return self

    def calibrate_threshold(self, calib_df: pd.DataFrame):
        benign_calib = calib_df[calib_df[config.LABEL_COL] == "BENIGN"]
        scores = self.predict_scores(benign_calib)
        self.calibrated_threshold = float(np.percentile(scores, self.percentile_threshold * 100))
        print(f"Calibrated v2 is_anomalous threshold on calib: {self.calibrated_threshold:.4f} (target: {self.percentile_threshold})")
        return self.calibrated_threshold

    def predict_raw_scores(self, df: pd.DataFrame) -> np.ndarray:
        X = df[self.feature_names].values
        valid_indices = [self.feature_names.index(f) for f in self.valid_feature_names]
        X_sub = X[:, valid_indices]
        X_log = signed_log1p(X_sub)
        X_scaled = (X_log - self.log_medians) / self.log_scales
        X_proj = self.pca.transform(X_scaled)
        return self.cov_estimator.mahalanobis(X_proj)

    def predict_scores(self, df: pd.DataFrame) -> np.ndarray:
        raw_scores = self.predict_raw_scores(df)
        n_ref = len(self.benign_train_scores_sorted)
        ranks = np.searchsorted(self.benign_train_scores_sorted, raw_scores, side="right")
        return np.clip(ranks / n_ref, 0.0, 1.0)

    def extract_top_evidence(self, X_valid: np.ndarray) -> List[List[Dict[str, Any]]]:
        z_scores = (X_valid - self.benign_medians) / self.benign_scales
        abs_z = np.abs(z_scores)

        top3_indices = np.argsort(-abs_z, axis=1)[:, :3]
        all_evidence = []

        for row_idx, indices in enumerate(top3_indices):
            row_evidence = []
            for col_idx in indices:
                feat_name = self.valid_feature_names[col_idx]
                val = float(X_valid[row_idx, col_idx])
                z_val = float(z_scores[row_idx, col_idx])
                direction = "high" if z_val >= 0 else "low"
                row_evidence.append({
                    "name": feat_name,
                    "value": round(val, 2),
                    "z": round(z_val, 2),
                    "direction": direction
                })
            all_evidence.append(row_evidence)

        return all_evidence

    def predict_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        scores = self.predict_scores(df)
        is_anomalous = scores >= self.calibrated_threshold

        X_valid = df[self.valid_feature_names].values
        top_features = self.extract_top_evidence(X_valid)

        out = pd.DataFrame(index=df.index)
        out[config.ID_COL] = df[config.ID_COL]
        out["anomaly_score"] = np.round(scores, 4)
        out["is_anomalous"] = is_anomalous
        out["top_features"] = top_features

        extra_cols = [c for c in df.columns if c not in self.feature_names and c not in (config.ID_COL, config.LABEL_COL)]
        for col in extra_cols:
            out[col] = df[col]

        return out

    def to_json_records(self, pred_df: pd.DataFrame) -> List[Dict[str, Any]]:
        records = []
        for _, row in pred_df.iterrows():
            record = {
                "record_id": str(row[config.ID_COL]),
                "agent": "anomaly",
                "anomaly_score": float(row["anomaly_score"]),
                "is_anomalous": bool(row["is_anomalous"]),
                "top_features": row["top_features"]
            }
            records.append(record)
        return records
