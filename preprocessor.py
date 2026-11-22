"""Preprocessor module for CyberSentinel.

Encapsulates feature imputation, whitespace cleanup, constant column removal,
and metadata pass-through.
"""

from typing import List, Dict, Optional
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
import config


class FlowPreprocessor:
    """Preprocessor that fits only on train features and transforms any dataset.
    
    Ignores and passes through extra metadata columns (e.g. IPs, ports, timestamps)
    and strictly isolates record_id from the model features.
    """
    def __init__(self):
        self.raw_feature_cols: List[str] = []
        self.selected_feature_cols: List[str] = []
        self.constant_cols: List[str] = []
        self.imputer: Optional[SimpleImputer] = None
        self.train_medians: Dict[str, float] = {}
        self.is_fitted: bool = False

    def fit(self, train_df: pd.DataFrame, label_col: str = config.LABEL_COL, id_col: str = config.ID_COL):
        train_df = train_df.copy()
        train_df.columns = train_df.columns.str.strip()

        candidate_cols = [c for c in train_df.columns if c not in (id_col, label_col)]
        num_cols = train_df[candidate_cols].select_dtypes(include=[np.number]).columns.tolist()
        self.raw_feature_cols = num_cols

        X_raw = train_df[num_cols].replace([np.inf, -np.inf], np.nan)

        self.constant_cols = [c for c in num_cols if X_raw[c].nunique(dropna=True) <= 1]
        self.selected_feature_cols = [c for c in num_cols if c not in self.constant_cols]

        self.imputer = SimpleImputer(strategy="median")
        X_selected = X_raw[self.selected_feature_cols]
        self.imputer.fit(X_selected)
        self.train_medians = dict(zip(self.selected_feature_cols, self.imputer.statistics_))
        self.is_fitted = True
        return self

    def transform_features(self, df: pd.DataFrame) -> pd.DataFrame:
        if not self.is_fitted:
            raise ValueError("Preprocessor has not been fitted.")

        df = df.copy()
        df.columns = df.columns.str.strip()

        missing = [c for c in self.selected_feature_cols if c not in df.columns]
        if missing:
            raise KeyError(f"Missing expected feature columns: {missing}")

        X = df[self.selected_feature_cols].replace([np.inf, -np.inf], np.nan)
        X_imputed = self.imputer.transform(X)
        return pd.DataFrame(X_imputed, columns=self.selected_feature_cols, index=df.index)

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        df_clean = df.copy()
        df_clean.columns = df_clean.columns.str.strip()

        X_transformed = self.transform_features(df_clean)

        cols_to_keep = [c for c in df_clean.columns if c not in self.raw_feature_cols]
        result = pd.concat([df_clean[cols_to_keep], X_transformed], axis=1)
        return result
