"""Agent 2 (v2): Upgraded Anomaly Detection Agent runner

Mahalanobis Distance on Ledoit-Wolf regularized PCA components of signed log1p + robust-scaled features.
"""

import argparse
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
import joblib

import config
from data import load_processed_data
from agent_classes import AnomalyDetectionAgentV2


def run_and_save_v2():
    train_df, calib_df, eval_df, preprocessor = load_processed_data()
    feature_names = preprocessor.selected_feature_cols

    agent2_v2 = AnomalyDetectionAgentV2()
    agent2_v2.fit(train_df, feature_names)
    agent2_v2.calibrate_threshold(calib_df)

    v2_path = config.ARTIFACTS_DIR / "agent2_anomaly_v2.joblib"
    joblib.dump(agent2_v2, v2_path)
    print(f"Saved Agent 2 (v2) model to {v2_path}")

    eval_preds = agent2_v2.predict_batch(eval_df)
    scores = eval_preds["anomaly_score"].values
    is_ano = eval_preds["is_anomalous"].values
    y_true_binary = (eval_df[config.LABEL_COL] != "BENIGN").astype(int).values

    auroc = roc_auc_score(y_true_binary, scores)
    print(f"Agent 2 (v2) Eval Binary AUROC: {auroc:.4f}")
    return agent2_v2


if __name__ == "__main__":
    run_and_save_v2()
