"""CyberSentinel Configuration

Centralized configuration for dataset paths, random seeds, class schemas,
cost matrix, and decision thresholds.
"""

from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent
TRAIN_PATH = BASE_DIR / "Cyber" / "training" / "flows.parquet"
EVAL_PATH = BASE_DIR / "Cyber" / "eval" / "flows.parquet"
ARTIFACTS_DIR = BASE_DIR / "artifacts"
OUTPUTS_DIR = BASE_DIR / "outputs"

# Reproducibility
RANDOM_STATE = 42

# Production Model Version Switch ('v1' for Day 1 baseline, 'v2' for Level 2 production)
MODEL_VERSION = "v2"

# Data contracts
ID_COL = "record_id"
LABEL_COL = "label"
CLASSES = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]
ATTACK_CLASSES = ["BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]

# Splitting
CALIB_SIZE = 0.20  # 80/20 train/calib stratified split

# Cost Matrix
# Missed attack (false allow of an attack) is 5x more costly than false block of benign flow
COST_MISSED_ATTACK = 5.0
COST_FALSE_BLOCK = 1.0
# Cost-optimal decision threshold for blocking attack: P(attack) > C_fb / (C_fb + C_ma) = 1 / 6 ~= 0.1667
COST_BLOCK_THRESHOLD = COST_FALSE_BLOCK / (COST_FALSE_BLOCK + COST_MISSED_ATTACK)

# Agent 1 (Threat Detection) parameters
AGENT1_N_ESTIMATORS = 250
AGENT1_LEARNING_RATE = 0.08
AGENT1_NUM_LEAVES = 63

# Agent 2 (Anomaly Detection) parameters
AGENT2_BENIGN_SUBSAMPLE = 100000
AGENT2_N_ESTIMATORS = 150
AGENT2_MAX_SAMPLES = "auto"
# Percentile threshold on benign calib scores to mark a flow as anomalous
ANOMALY_PERCENTILE_THRESHOLD = 0.95
ANOMALY_EXTREME_PERCENTILE_THRESHOLD = 0.99

# Agent 3 (Fusion) thresholds
ABSTAIN_CONFIDENCE_THRESHOLD = 0.60
HIGH_CONFIDENCE_THRESHOLD = 0.85

# Level 2: Agent 4 (Temporal Correlation) parameters
A4_WINDOW_RECORDS = 50  # Causal sliding window in records per source IP

# Level 2: Agent 5 (Adaptive Defense) parameters
A5_MIN_SUSPICIOUS_FLOWS = 2   # Require multiple suspicious flows (protects against ~5% benign false alarms)
A5_MIN_CONFIDENCE = 0.70       # Mean confidence / suspicious strength
A5_MAX_BENIGN_SHARE = 0.25     # Skip IPs whose window flows are mostly benign
A5_POLICY_TTL_RECORDS = 30     # Policy TTL in records
A5_SCOPE_TYPE = "SOURCE_IP"
A5_POLICY_ACTION = "BLOCK"

# Ensure output directories exist
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
