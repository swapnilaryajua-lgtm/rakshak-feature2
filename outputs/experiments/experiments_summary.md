# CyberSentinel: Post-Submission Experiments & Robustness Report

Generated offline and deterministically with `random_state=42`. No LLM calls.

---

## 1. Agent 2 Upgrade Experiments (BENIGN-Only Detectors)

All models trained strictly on 100,000 `BENIGN` training flows; anomaly thresholds calibrated on `calib` at 5% and 10% Benign False Alarm Rate (FAR). Evaluated on held-out `eval/flows.parquet` (114,185 flows).

### Performance Comparison Across Variants

| Detector Variant | Fit Time | Calib Binary AUROC | Eval Binary AUROC | BRUTE_FORCE AUROC | DOS AUROC | DDOS AUROC | PORT_SCAN AUROC |
|---|---|---|---|---|---|---|---|
| **Baseline: Isolation Forest (Raw Features)** | 5.05s | 0.8783 | 0.8729 | 0.8226 | 0.9302 | 0.9229 | 0.7323 |
| **Variant 1: Isolation Forest (Signed log1p + Robust Scale)** | 6.96s | 0.9051 | 0.9122 | 0.8858 | 0.8822 | 0.8868 | 0.9900 |
| **Variant 2: PCA Reconstruction Error (15 comps)** | 2.19s | 0.8951 | 0.9030 | 0.9761 | 0.8476 | 0.9098 | 0.9814 |
| **Variant 3: Ledoit-Wolf Mahalanobis on PCA (15 comps) [WINNER]** | **2.08s** | **0.9661** | **0.9644** | **0.9458** | **0.9533** | **0.9810** | **0.9681** |

### Per-Class Detection Rates (at 5% and 10% Benign False Alarm Rate on Eval)

- **At 5% Benign FAR (Threshold = 0.9506):**
  - `BENIGN` False Alarms: 5.06%
  - `PORT_SCAN` Catch Rate: **98.85%** (vs 0.00% baseline)
  - `DDOS` Catch Rate: **99.99%** (vs 1.98% baseline)
  - `DOS` Catch Rate: **75.29%** (vs 9.74% baseline)
  - `BRUTE_FORCE` Catch Rate: **26.66%** (vs 0.07% baseline)
- **At 10% Benign FAR (Threshold = 0.9008):**
  - `PORT_SCAN`: **99.95%**
  - `DDOS`: **99.99%**
  - `BRUTE_FORCE`: **99.28%**
  - `DOS`: **92.25%**

### Updated Fusion Ablation with Agent 2 (v2)

| System | Task Mode | Accuracy | Macro-F1 | False Allows | False Blocks | AUROC |
|---|---|---|---|---|---|---|
| **Agent 1 only (Threat)** | 5-Class Classifier | 100.00% | 0.9999 | 2 | 1 | — |
| **Agent 2 (v2) only (Anomaly)** | Binary (Attack vs Benign) | **91.11%** | **0.9104** | 7,113 | 3,037 | **0.9644** |
| **CyberSentinel Fusion (v2)** | Multi-Agent Defense | **100.00%** | **0.9999** | **1** | **1** | — |

- **Agreements with v2:** Jumped from **52.35% $\to$ 91.11%** (104,034 flows agree).
- **Disagreements with v2:** Decreased from **47.65% $\to$ 8.89%** (10,151 flows).
- Saved as `artifacts/agent2_anomaly_v2.joblib` and `agent2_anomaly_v2.py`.

---

## 2. Agent 1 Feature Robustness Check

Testing whether Agent 1 depends artificially on `Destination Port` or `Init_Win_bytes_forward` / `Init_Win_bytes_backward`.

| Model Variant | Active Features | Eval Accuracy | Eval Macro-F1 | BENIGN F1 | BRUTE_FORCE F1 | DOS F1 | DDOS F1 | PORT_SCAN F1 |
|---|---|---|---|---|---|---|---|---|
| **Baseline (All 75 features)** | 75 | **100.00%** | **0.9999** | 1.0000 | 0.9996 | 1.0000 | 1.0000 | 0.9999 |
| **Without Destination Port** | 74 | **100.00%** | **0.9998** | 1.0000 | 0.9989 | 1.0000 | 1.0000 | 0.9999 |
| **Without TCP Window Bytes (fwd & bwd)** | 73 | **100.00%** | **0.9999** | 1.0000 | 0.9996 | 1.0000 | 1.0000 | 1.0000 |
| **Without Dest Port & TCP Window Bytes** | 72 | **99.99%** | **0.9997** | 0.9999 | 0.9989 | 0.9999 | 1.0000 | 0.9999 |

> **Conclusion:** Zero dependence on shortcut features. Removing Destination Port and both initial TCP window features leaves performance virtually identical (Macro-F1 0.9997 vs 0.9999). Flow duration, packet rates, and IAT statistics are highly resilient.

---

## 3. Zero-Day Defense Testing (Simulating Novel Attacks)

One attack class at a time is removed from Agent 1 training data. The classifier is retrained on the remaining classes and tested against held-out zero-day flows. Agent 2 (v2) is kept unchanged.

| Held-Out Attack Class | Eval Test Flows | Agent 1 Miss Rate (Called BENIGN) | Agent 2 Anomaly Catch Rate | Fusion Safe Catch Rate (Blocked or Escalated) | Key Finding & Weakness Highlighted |
|---|---|---|---|---|---|
| **`PORT_SCAN`** | 14,400 | **99.94%** (14,392 flows) | **98.85%** (14,235 flows) | 0.08% | **Where it failed:** Agent 1 was overconfidently outputting `BENIGN` (>0.85). Fusion's baseline override rule trusted Agent 1 because anomaly score (0.97) was below the 0.99 extreme threshold. *Fix: Escalate any conflict where Agent 1 says BENIGN but Agent 2 alerts.* |
| **`DDOS`** | 14,400 | **49.50%** (7,128 flows) | **99.99%** (14,398 flows) | **67.40%** (9,706 flows) | Agent 1 mapped 50.45% to `PORT_SCAN` and 49.50% to `BENIGN`. Agent 2 caught 99.99% of flows. Fusion escalated 23.28% and blocked 44.12%. |
| **`BRUTE_FORCE`** | 1,384 | **100.00%** (1,384 flows) | **26.66%** (at 5% FAR) / **99.28%** (at 10% FAR) | 0.00% | **Where it failed:** Brute force traffic generates few packets per attempt, closely resembling legitimate benign login attempts. At 5% FAR, single-flow anomaly detection catches only 26.66%. Needs temporal aggregation over IP/endpoint metadata. |

---

*All raw metrics saved to `outputs/experiments/agent2_upgrades.json`, `outputs/experiments/agent1_robustness.json`, and `outputs/experiments/zero_day.json`.*
