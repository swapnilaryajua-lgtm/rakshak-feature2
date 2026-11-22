# CyberSentinel: Level 1 Evaluation Summary

## 1. System Performance (Official Evaluation Set)

- **Total Evaluated Flows:** 114,185
- **Baseline Accuracy (Full Coverage):** 100.00%
- **Baseline Macro-F1 (Full Coverage):** 0.9999
- **Selective Accuracy (Confident Flows):** 100.00%
- **Escalation / Abstain Rate:** 0.48% (548 flows)

### Per-Class F1 Scores
- **`BENIGN`**: 1.0000
- **`BRUTE_FORCE`**: 0.9996
- **`DOS`**: 1.0000
- **`DDOS`**: 1.0000
- **`PORT_SCAN`**: 0.9999

### Confusion Matrix
```
                  Pred_BENIGN  Pred_BRUTE_FORCE  Pred_DOS  Pred_DDOS  Pred_PORT_SCAN
True_BENIGN             60000                 1         0          0               0
True_BRUTE_FORCE            0              1384         0          0               0
True_DOS                    0                 0     24000          0               0
True_DDOS                   0                 0         0      14400               0
True_PORT_SCAN              2                 0         0          0           14398
```

---

## 2. Multi-Agent Ablation Analysis

| Architecture / Component | Task Mode | Accuracy | Macro-F1 | False Allows | False Blocks |
|---|---|---|---|---|---|
| **Agent 1 only (Threat)** | 5-Class Classifier | 100.00% | 0.9999 | 2 | 1 |
| **Agent 2 only (Anomaly)** | Binary (Attack vs Benign) | 52.35% | 0.3827 | 51560 | 2854 |
| **CyberSentinel Fusion** | Multi-Agent Defense | 100.00% | 0.9999 | 2 | 1 |

---

## 3. Disagreement & Attribution Analysis

- **Total Agreements:** 59,772 (52.35%)
- **Total Disagreements:** 54,413 (47.65%)

### Disagreement Breakdown:
1. **Classifier Attack vs Anomaly Normal:**
   - Total cases: 51,559
   - Classifier (Agent 1) Right: **51,558 (100.0%)**
   - Anomaly (Agent 2) Right: 1
   - *Insight:* High classifier confidence successfully overrides false normal flags on low-packet port scans and targeted brute-force attacks.

2. **Classifier Benign vs Anomaly Alert:**
   - Total cases: 2,854
   - Classifier (Agent 1) Right: **2,854 (100.0%)**
   - Anomaly (Agent 2) Right: 0
   - *Insight:* Anomaly flags on benign traffic represent novel benign variance or heavy transfers, correctly handled via escalation and cost filtering.

---

## 4. Policy Actions & Evidence Status

- **ALLOW:** 59,454 (52.07%)
- **BLOCK:** 54,183 (47.45%)
- **ESCALATE:** 548 (0.48%)

**Status Breakdown:**
- `CONFIRMED`: 59,772 (52.35%)
- `CONFLICT_RESOLVED`: 53,865 (47.17%)
- `UNKNOWN_THREAT`: 548 (0.48%)

---
*Generated deterministically by CyberSentinel Offline Multi-Agent Pipeline.*
