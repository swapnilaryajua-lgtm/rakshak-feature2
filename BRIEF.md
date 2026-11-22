# CyberSentinel: Project Brief and Workflow Plan

> Purpose of this file: give any AI assistant or teammate the full context so everyone works on the same plan. Read it completely before writing code. If something here conflicts with the official organizer instructions, the organizer instructions win.

---

## 1. Context

- **Event:** Jaypee Agentic AI International Summit 2026
- **Track:** Track 1, Agentic AI for Cybersecurity
- **Problem title:** CyberSentinel: Multi-Agent Network Intrusion Detection & Adaptive Defense
- **Day 1 date:** 30 October 2026. **Level 1 submission deadline: 8:00 PM** (API summary submission; no final CSV upload required; no live demo on Day 1).
- **Level 2:** organizers brief participants during the 6:00-8:00 PM slot. Teams may improve models overnight. Level 2 instructions are NOT known yet, so keep the code modular and easy to extend.
- **Today's schedule (plan updated at 4:13 PM):** all three agents finished by **6:30 PM**; final validation run, ablation table and summary by **7:00 PM**; API submission done between **7:00 and 7:30 PM**. **Hard internal cutoff: 7:30 PM**, which keeps a 30-minute buffer before the 8:00 PM deadline.
- **Heads-up:** the Level 2 briefing happens in the same 6:00-8:00 PM window. Confirm whether attendance is mandatory or online, and have a teammate cover it if needed, so the Level 1 work is not disturbed.

## 2. The official problem (in plain words)

Build an **agentic cybersecurity prototype** that:
1. Classifies network flows.
2. Identifies suspicious activity.
3. Combines evidence from multiple agents.
4. Applies **explainable, simulated ALLOW/BLOCK policies**.

Important constraints:
- It is an **offline traffic-replay challenge** on dataset files. It is **not** a live network attack and **not** a firewall deployment. Nothing should touch a real network.
- **Dataset:** CICIDS2017 (labeled network-flow records). See the data pack facts right below this list.
- **Five benchmark classes:** `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, `PORT_SCAN`. The data pack's `label` column is **already mapped to these five classes**, so no manual mapping is needed (just verify the label values).
- Handle **missing/infinite values** and **class imbalance** appropriately.

### Actual data pack (from the organizers' README)

Only the **Cyber** folder matters for us (the Health/HAM10000 folder belongs to another track; ignore it).

| Partition | File | Rows |
|---|---|---:|
| Training | `Cyber/training/flows.parquet` | 456,737 |
| Eval | `Cyber/eval/flows.parquet` | 114,185 |

- Columns: `record_id`, 78 numeric flow features, `label`.
- Class counts (training / eval): BENIGN 240,000 / 60,001; BRUTE_FORCE 5,537 / 1,384; DOS 96,000 / 24,000; DDOS 57,600 / 14,400; PORT_SCAN 57,600 / 14,400. **BRUTE_FORCE is the rare class (about 1.2%)**, so macro-F1 depends heavily on it.
- The two partitions are **disjoint by source record**.
- Endpoint metadata (`source_ip`, `destination_ip`, ports, protocol, `seq`) is **intentionally absent** from this pack. It ships only with the **hidden evaluation set**, because it is needed for **replay policy matching**. Consequences: (1) we cannot and should not use those columns as features; (2) Level 2 / the hidden set likely applies ALLOW/BLOCK policies per endpoint, so our pipeline must be keyed on `record_id` and be able to join extra columns later.
- `eval/` is a **held-out development set**: "train on training/, tune and report on eval/". The **final ranking uses a hidden set** released on the event day. Hidden record IDs are different from anything in this pack.
- Assumption to confirm in the WhatsApp group: `eval/flows.parquet` is the "official validation records" for the Day 1 run.

### Day 1, Level 1 required agents

| Agent | Required function / output |
|---|---|
| 1. Threat Detection Agent | Train a classifier to predict one of the five classes. Report predicted class and confidence. |
| 2. Anomaly Agent | Independently assess unusual flows. Output anomaly score and supporting feature evidence. |
| 3. Evidence Fusion Agent | Combine Agent 1 and Agent 2, including disagreements. Output final class, evidence status and rationale. |

### Day 1 tasks and submission checklist
- [ ] Inspect and clean the training data.
- [ ] Train Agent 1 and implement independent anomaly scoring in Agent 2.
- [ ] Implement Agent 3 and **record how it handles agreement and disagreement**.
- [ ] Run the complete pipeline on the **official validation records**.
- [ ] Report **baseline accuracy, macro-F1** and a brief summary of the agents' outputs.
- [ ] Submit Level 1 results through the **API shared in the WhatsApp group by 8:00 PM** (summary submission).

## 3. Our solution in one paragraph

We build three deterministic, modular ML agents (**no LLM anywhere in the pipeline**). Agent 1 is a calibrated multi-class classifier. Agent 2 is an independent one-class anomaly detector trained only on BENIGN traffic. Agent 3 fuses both with transparent, cost-aware rules and can **abstain** (escalate for review) when evidence is weak or the agents conflict. On top of the mandatory baseline we add four things that most teams will not do: (a) an **ablation and disagreement analysis** proving the multi-agent design adds value, (b) a **zero-day test** (hold out one attack class) showing the anomaly agent catches what the classifier has never seen, (c) **calibrated confidence with an abstain option**, and (d) **cost-aware ALLOW/BLOCK decisions** where missing an attack costs more than wrongly blocking benign traffic.

## 4. Why we are doing it this way (decisions and reasons)

| Decision | Reason |
|---|---|
| No LLM in the pipeline | Tabular flow classification is better done by tree models; LLMs are slow, can hallucinate, and add deadline risk. Explanations come from numeric evidence plus template text. |
| Tree-based classifier (LightGBM, XGBoost or Random Forest) | Very strong on CICIDS2017, fast, needs little tuning, handles imbalance with class weights. |
| Anomaly agent trained on BENIGN only | Keeps it truly independent from the classifier and lets it flag unknown attack types. |
| Calibrated probabilities | Raw tree probabilities are overconfident. Fusion and abstain logic need trustworthy confidence. |
| Abstain / escalate option | A mature system says "not sure" instead of guessing. Report accuracy on confident decisions plus coverage. |
| Cost-aware decisions | Wrongly allowing an attack is worse than wrongly blocking a benign flow. This also prepares for the "Adaptive Defense" part likely tested in Level 2. |
| Check for duplicates anyway | Partitions are disjoint by source record, but duplicate flows can still exist inside the training file and across train/calib splits. Deduplicate before splitting our internal train/calib split. |
| Report macro-F1 and per-class F1 | Class imbalance makes accuracy misleading; rare classes matter equally. |

## 5. Data handling rules

1. Load `Cyber/training/flows.parquet` and `Cyber/eval/flows.parquet` (needs `pyarrow`). Strip whitespace from column names.
2. Verify `label` contains exactly the five classes. Keep `record_id` as the row key for every output; **never use it as a feature** (check it is not correlated with the label).
3. Features = the 78 numeric flow columns. There are no IP, timestamp or port columns in this pack, so nothing like that needs dropping. Drop constant columns.
4. Replace `inf` / `-inf` with `NaN`. Impute with the training-set median (fit on training data only), or drop rows if very few.
5. Check and drop duplicate feature rows inside the training file (ignore `record_id` when checking).
6. Imbalance: use `class_weight='balanced'` (or sample weights) for Agent 1. BENIGN is only about half the data, so heavy downsampling is not needed; the real problem is rare BRUTE_FORCE. Do **not** change the eval file's distribution.
7. **Splits:**
   - Split `training` into `train` (about 80%) and `calib` (about 20%), stratified, `random_state=42`. `calib` is used for calibration, anomaly threshold, abstain threshold and cost threshold.
   - `eval` is the held-out development set: use it to **report** accuracy and macro-F1 and for the ablation. Prefer to set thresholds on `calib` rather than on `eval`, because the final ranking is on a hidden set and over-tuning on `eval` would overfit.
8. Save the cleaned data and fitted objects (imputer, feature list, models) with `joblib` so every step is reproducible.

## 6. Architecture

```
            flow record (features)
                   |
        +----------+-----------+
        |                      |
  Agent 1: Threat        Agent 2: Anomaly
  Detection (calibrated  (BENIGN-only
  multi-class)           Isolation Forest)
        |                      |
   class + confidence     anomaly score + top features
        |                      |
        +----------+-----------+
                   |
        Agent 3: Evidence Fusion
        (rules + costs + abstain)
                   |
   final_class, action (ALLOW/BLOCK/ESCALATE),
   evidence_status, rationale
```

### Agent 1: Threat Detection Agent
- Model: LightGBM / XGBoost / Random Forest on the five classes.
- Output per flow: `predicted_class`, `confidence` (max class probability), full `probabilities` dict.
- Phase 1 uses raw probabilities. Phase 2 (calibration) wraps the same model so the interface does not change.

### Agent 2: Anomaly Agent
- Model: Isolation Forest (or similar) trained **only on BENIGN training flows**. It must not use Agent 1's output.
- Convert the raw score to a **0 to 1 anomaly score** using the percentile of the score against the BENIGN training distribution. Set an `is_anomalous` threshold from the `calib` set (for example the 95th to 99th percentile of benign scores).
- Evidence: for each flow, compute robust z-scores (median and MAD, or mean and std) against the BENIGN training data and return the **top 3 features** with the largest deviation, with their values and direction (high/low).
- Output: `anomaly_score`, `is_anomalous`, `top_features`.

### Agent 3: Evidence Fusion Agent
Inputs: Agent 1 output and Agent 2 output. Outputs: `final_class`, `action`, `evidence_status`, `rationale`, and a record of agreement/disagreement.

Evidence status values:
- `CONFIRMED`: agents agree (attack + anomalous, or benign + normal).
- `CONFLICT_RESOLVED`: agents disagree but one side has strong enough evidence to decide (rule stated in the rationale).
- `LOW_CONFIDENCE`: weak evidence; abstain/escalate.
- `UNKNOWN_THREAT`: classifier says BENIGN (or is unsure) but the anomaly score is very high; flag as a possible novel attack.

**Build it today in a simple form:** the fusion rules below, plus (a) one abstain threshold and (b) one cost-aware BLOCK threshold (see 7.4), both read from `config.py` with sensible defaults. The deeper studies (calibration plots, cost sweep) come after submission.

Decision logic (starting point; tune thresholds on `calib`, not on the official validation set):
1. Agent 1 says attack and Agent 2 says anomalous -> `CONFIRMED`, `BLOCK`.
2. Agent 1 says BENIGN and Agent 2 says normal -> `CONFIRMED`, `ALLOW`.
3. Agent 1 says attack, Agent 2 says normal -> disagreement. If calibrated confidence is above the high threshold, trust Agent 1 (`CONFLICT_RESOLVED`, `BLOCK`); otherwise `LOW_CONFIDENCE` -> escalate.
4. Agent 1 says BENIGN, Agent 2 says highly anomalous -> disagreement. If the anomaly score is above the extreme threshold, `UNKNOWN_THREAT` -> escalate (and treat as BLOCK-leaning under the cost rule); otherwise trust Agent 1.
5. Any case where the final confidence is below the abstain threshold -> `LOW_CONFIDENCE`, escalate.

Every decision writes a **one-line rationale** that contains the numbers, for example: `Classifier: DDOS (0.97). Anomaly 0.93, driven by Flow Packets/s (high), Fwd IAT Mean (low). Agents agree -> BLOCK.`

**Disagreement log:** count how often the agents agree vs disagree, and for each disagreement type record who was right. This is explicitly required.

## 7. The four differentiators (what makes us stand out)

### 7.1 Ablation and disagreement analysis (core, runs 6:30-7:00 PM)
Produce one table with rows: **Agent 1 only**, **Agent 2 only** (as attack-vs-benign), **Fusion**. Columns: accuracy, macro-F1, per-class F1, false-allow rate, false-block rate. Then a disagreement table: for flows where agents disagreed, how often was Agent 1 right, how often Agent 2, how often neither. This proves the multi-agent design adds value.

### 7.2 Zero-day test (optional today; do it only if the core is done early, otherwise overnight)
Goal: show that two independent agents catch attacks one agent has never seen.
1. Pick a class to hide, for example `PORT_SCAN` (if time permits, repeat with `DDOS` or `BRUTE_FORCE`).
2. Retrain Agent 1 on the data **without** that class (it now knows only four classes). Agent 2 is unchanged because it only learned BENIGN.
3. Run on validation data including the hidden class. Measure on the hidden-class flows:
   - % that Agent 1 wrongly calls BENIGN (the miss rate),
   - % that Agent 2 flags as anomalous,
   - % that Fusion marks as `UNKNOWN_THREAT` / escalated instead of ALLOW.
4. Compare to a "classifier only" system. Report the improvement honestly. If Agent 2 does not catch a class well, report that too and explain why (for example, some attacks look statistically close to normal traffic). Honest results beat inflated ones.

### 7.3 Calibrated confidence plus abstain (basic abstain threshold goes into Agent 3 today; full calibration study overnight)
1. Calibrate Agent 1 on the `calib` split (isotonic or sigmoid). Note: in newer scikit-learn versions `cv='prefit'` is deprecated; wrap the fitted model with `FrozenEstimator` or calibrate with cross-validation. Check the installed version.
2. Show a **reliability diagram** and report **ECE** and **Brier score**, before vs after calibration.
3. Set the abstain threshold on `calib`. Report a **coverage vs accuracy** curve: accuracy and macro-F1 on non-abstained flows, and the % of flows escalated.
4. Report both views: full-coverage metrics (abstained flows keep their best-guess class) and selective metrics (only confident flows). The official submission should use full-coverage numbers unless instructions say otherwise.

### 7.4 Cost-aware ALLOW/BLOCK decisions (basic cost rule goes into Agent 3 today; cost sweep overnight)
1. Define a configurable cost matrix, starting with: missed attack (false ALLOW) = 5, false BLOCK of benign = 1. Keep it in one config.
2. Decision rule from expected cost: compute `P(attack) = 1 - P(BENIGN)` from calibrated Agent 1 (optionally nudged by the anomaly score). BLOCK when `P(attack) * C_missed > (1 - P(attack)) * C_falseblock`, i.e. when `P(attack) > C_falseblock / (C_falseblock + C_missed)`. With 5:1 this threshold is about 0.17.
3. Sweep the cost ratio (for example 1:1, 3:1, 5:1, 10:1) and show how false-allow and false-block counts and total cost change. Tune only on `calib`/`holdout`.
4. Optional extra action if time permits: `RATE_LIMIT` for medium-risk flows. The official policy actions are ALLOW/BLOCK, so keep ALLOW/BLOCK as primary and mark ESCALATE/RATE_LIMIT as additional.

## 8. Build order and time plan (today, 30 October)

**Targets:** agents done by 6:30 PM, results by 7:00 PM, submitted by 7:30 PM at the latest (deadline 8:00 PM).

| Time | Work | Output / checkpoint |
|---|---|---|
| 4:13-4:25 | Setup: `pip install pandas pyarrow scikit-learn lightgbm joblib`, load both parquet files, run `inspect_data.py`, get the API format from WhatsApp | Notebook/repo runs, label values confirmed |
| 4:25-5:00 | Cleaning and splits (section 5): inf/NaN, duplicates, 80/20 train/calib split of the training file | Clean `train`/`calib`/`holdout`, saved objects. **Checkpoint 1 at 5:00** |
| 5:00-5:30 | **Agent 1** baseline (LightGBM or Random Forest with balanced class weights). Raw probabilities are fine | Holdout accuracy, macro-F1, confusion matrix. **Checkpoint 2 at 5:30** |
| 5:30-5:55 | **Agent 2** (Isolation Forest on BENIGN only, percentile scores, top-3 z-score evidence) | Anomaly score and evidence for any flow |
| 5:55-6:30 | **Agent 3** (fusion rules + simple abstain threshold + simple cost threshold + rationale text + agreement/disagreement log), then wire everything into `pipeline.py` | Single function: dataframe in, results out. **Checkpoint 3 at 6:30: all three agents working** |
| 6:30-6:50 | Run the full pipeline on **`eval/flows.parquet`** (the official validation records). Compute accuracy, macro-F1, per-class F1, ablation table (Agent 1 only, Agent 2 only, Fusion), disagreement counts | Final numbers saved to `outputs/` |
| 6:50-7:10 | Write the agents' summary (a few lines per agent) and build the API payload | Payload JSON ready |
| 7:10-7:30 | **Submit through the API**, save the response/receipt, re-check that it succeeded | **Submitted. Hard cutoff 7:30 PM** |
| After 7:30 | Zero-day test, calibration study, cost sweep, then Level 2 changes (overnight) | Extra results for Level 2 |

**Speed rules (important with this little time):**
- Test everything on a **sample first** (for example 50k rows), then run on the full data once.
- Use `n_jobs=-1`. LightGBM with about 200 trees or a Random Forest with about 100 trees is enough; do not tune for hours.
- Isolation Forest on benign data only, 100 to 200 trees, a subsample of BENIGN rows is fine.
- Save models and cleaned data with `joblib` so a crash does not cost you the cleaning time again.
- Do not build plots, dashboards or experiments before Checkpoint 3.

**If you are behind schedule:**
- At Checkpoint 1 (5:00) and still cleaning: use a smaller sample, skip correlation-based feature dropping.
- At Checkpoint 2 (5:30) and Agent 1 is not good: ship the plain Random Forest, improve overnight.
- At Checkpoint 3 (6:30) and Agent 3 is unfinished: ship the simplest rules (agree -> confirm, disagree -> trust Agent 1 unless anomaly is extreme), skip the cost and abstain thresholds for now.
- Never skip the 6:30-6:50 validation run or the 7:10-7:30 submission block.

## 9. Suggested repository structure

```
cybersentinel/
  config.py            # paths, seed, class list, cost matrix, thresholds
  data.py              # load, clean, map labels, split
  agent1_threat.py     # train/predict, calibration wrapper
  agent2_anomaly.py    # fit on benign, score, top-feature evidence
  agent3_fusion.py     # rules, costs, abstain, rationale, disagreement log
  pipeline.py          # run all agents on a dataframe -> results dataframe + JSON
  evaluate.py          # accuracy, macro-F1, per-class F1, ablation, ECE
  experiments/
    zero_day.py
    calibration.py
    cost_sweep.py
  submit.py            # builds summary payload and calls the API
  notebooks/           # exploration only
  outputs/             # metrics, plots, results JSON/CSV
```

## 10. Data contracts (keep these schemas identical everywhere)

Agent 1 output:
```json
{"record_id": "<id>", "agent": "threat_detection", "predicted_class": "DDOS", "confidence": 0.97,
 "probabilities": {"BENIGN": 0.01, "BRUTE_FORCE": 0.00, "DOS": 0.02, "DDOS": 0.97, "PORT_SCAN": 0.00}}
```

Agent 2 output:
```json
{"record_id": "<id>", "agent": "anomaly", "anomaly_score": 0.93, "is_anomalous": true,
 "top_features": [{"name": "Flow Packets/s", "value": 125000.0, "z": 14.2, "direction": "high"}]}
```

Agent 3 output:
```json
{"record_id": "<id>", "agent": "evidence_fusion", "final_class": "DDOS", "action": "BLOCK",
 "evidence_status": "CONFIRMED", "agreement": true,
 "rationale": "Classifier: DDOS (0.97). Anomaly 0.93 driven by Flow Packets/s (high). Agents agree -> BLOCK."}
```

## 11. Metrics and reporting checklist

- Baseline accuracy and **macro-F1** on the official validation set (full coverage).
- Per-class precision/recall/F1 and the **confusion matrix**.
- Ablation table (Agent 1 only, Agent 2 only, Fusion).
- Agreement/disagreement counts and who-was-right analysis.
- Zero-day results (miss rate vs fused catch rate).
- Calibration: ECE/Brier before and after, reliability diagram, coverage vs accuracy.
- Cost sweep: false-allow, false-block and total cost per cost ratio.
- Short written summary of each agent's behavior (this goes into the API summary submission).

## 12. Rules for any AI or teammate working on this

1. **No LLM calls in the pipeline.** Everything is deterministic ML plus rules plus template text.
2. Python with pandas, numpy, scikit-learn, and LightGBM or XGBoost. Set `random_state=42` everywhere.
3. No data leakage: deduplicate before splitting, fit all preprocessing on training data only, never use `record_id` as a feature, and set thresholds on the `calib` split rather than on `eval` (the final ranking is on a hidden set).
4. Keep every agent a separate module with the schemas in section 10. Do not merge agents.
5. Thresholds, costs and class lists live in `config.py`, not hard-coded.
6. Everything is **simulated and offline**. Do not write code that touches live networks or real firewalls.
7. Write code that runs end to end on a small sample first, then on the full data.
8. Report honest numbers. If something underperforms, say so and explain; do not hide it.
9. If the dataset or the API format differs from this brief, ask the team lead (Hidoi) rather than guessing.

## 13. Definition of done for Day 1

**Must have (submit by 7:30 PM):**
- [ ] Data cleaned (inf/NaN handled, duplicates removed, imbalance handled, labels mapped).
- [ ] Agent 1, Agent 2 and Agent 3 working with the schemas in section 10.
- [ ] Full pipeline run on the official validation records.
- [ ] Baseline accuracy and macro-F1, per-class F1, confusion matrix.
- [ ] Ablation table and agreement/disagreement log.
- [ ] Level 1 summary submitted through the API, with the response saved.

**Nice to have today (only if ahead of schedule):**
- [ ] Zero-day test on one held-out class.
- [ ] Calibration of Agent 1 and a reliability plot.

**Overnight / Level 2:**
- [ ] Zero-day test (all classes if possible), calibration study, coverage vs accuracy curve.
- [ ] Cost sweep and RATE_LIMIT action, adapted to the Level 2 instructions.
- [ ] Code stays modular so Level 2 changes are small.

---

## 14. LEVEL 2 (31 October): five-agent system with replay and adaptive defense

Source: organizers' Day 2 brief. Level 1 is already submitted. **Keep A1-A3 exactly as they are** and add two agents.

### 14.1 The two new agents

| Agent | Job | Required output |
|---|---|---|
| A4 Temporal Correlation | Group related suspicious flows using **observed endpoints and time windows** (only flows seen so far) | Group IDs, member record IDs, supporting evidence |
| A5 Adaptive Defense | Create **temporary, simulated** ALLOW/BLOCK policies | Flow decisions, policy activation, scope and expiry logs |

How the five agents talk: A1 + A2 DETECT (class + confidence, anomaly score) -> A3 + A4 CORRELATE (A3 fuses evidence, A4 links repeated suspicious flows seen so far and names a pattern) -> A5 RESPOND (activates a temporary SOURCE_IP policy **after** the triggering flow; only **later** matching flows are BLOCKED).

### 14.2 Replay rules (hard rules)

1. Replay the flows in the **supplied/chronological order**. Use organizer-provided record IDs.
2. For each record, **first apply policies that are already active.** If the record's source IP matches an active BLOCK policy, the action is BLOCK and `applied_policy_id` is that policy.
3. If no active policy matches, the action is ALLOW. Then analyze the flow (A1-A4), and A5 may create a policy that affects **later** records only. The triggering flow itself stays ALLOW.
4. **Never use future records or hidden labels** to make a decision. A4 and A5 are strictly causal (state built only from records already replayed).
5. A1-A3 must still produce a prediction for **every** record, including records that get blocked by a policy (`classification.csv` has all records).
6. Record every ALLOW/BLOCK action, policy ID, activation and expiry.

Note: because A1-A3 look only at a record's own features, their predictions can be computed in one batch before the replay loop. A4 and A5 must run record by record in order.

### 14.3 Policy semantics (scored interface)

- `scope_type = SOURCE_IP`, `policy_action = BLOCK`, replay `action` is ALLOW or BLOCK.
- A policy applies only to **later matching records while active**: records after `activated_after_record_id` up to `expires_after_record_id` in replay order (confirm whether the expiry record itself is included).
- Expiry should be decided with a record-count TTL (for example "block this IP for the next N records") and converted into `expires_after_record_id` from the replay order. If time-based expiry is used, it must be applied as time passes during replay, never by peeking at future timestamps.
- A BLOCK must reference a valid applicable policy. ALLOW has an empty `applied_policy_id`.

### 14.4 Data caveat (important)

- The training/eval pack has **no** endpoint metadata. The hidden set ships with `source_ip`, `destination_ip`, ports, protocol and `seq`, used for replay policy matching.
- Use the endpoint columns **only in A4/A5**. Keep A1-A3 features exactly the 75 cleaned flow features from the pack (confirm with organizers which columns are "permitted flow features").
- To build and test A4/A5 before the hidden data arrives, use organizer dev metadata if they provide it; otherwise generate a **simulated replay** from the labeled eval file (synthetic source IPs, destination IPs, ordering and timestamps; attack flows arrive in bursts from a few attacker IPs, benign flows from many IPs, plus a few IPs that mix benign and attack to test collateral damage). Mark it clearly as synthetic. Labels may be used only to build the simulation and to score it, never inside agent decisions.

### 14.5 Suggested design

**A4 Temporal Correlation.** Keep a sliding window (by record count, configurable; by time only if timestamps exist) of suspicious flows seen so far, keyed by `source_ip` (optionally also by `destination_ip`). A flow is "suspicious" if A3 says attack, or the anomaly score is high. For each source IP compute: number of suspicious flows, mean confidence, majority class, number of distinct destination ports and destinations, and flow rate. Name a pattern (for example repeated DOS/DDOS flood, port sweep with many ports, repeated login attempts to one port). Assign a `group_id` and list members.

```json
{"agent": "temporal_correlation", "group_id": "G0007", "source_ip": "x.x.x.x",
 "member_record_ids": ["..."], "window_records": 200,
 "stats": {"n_flows": 12, "distinct_dst_ports": 11, "mean_confidence": 0.99, "majority_class": "PORT_SCAN"},
 "pattern": "port_sweep",
 "evidence": "12 suspicious flows from x.x.x.x within 200 records, 11 distinct destination ports"}
```

**A5 Adaptive Defense.** When a group passes thresholds (minimum suspicious flows, minimum mean confidence, majority attack class, low benign share), create a SOURCE_IP BLOCK policy: `activated_after_record_id` = the triggering record, `expires_after_record_id` = TTL records later, log the reason and the group that caused it. Do not create duplicate policies for an IP that is already blocked. Safeguards against false blocks: require several suspicious flows (not one), keep TTL short unless the evidence persists, and skip IPs whose recent flows are mostly benign. Thresholds and TTL are tuned on the simulated/dev replay using the cost view (a missed attack costs more than a false block, but blocking a whole source IP also blocks its benign flows).

```json
{"agent": "adaptive_defense", "policy_id": "P0001", "activated_after_record_id": "...",
 "scope_type": "SOURCE_IP", "scope_value": "x.x.x.x",
 "expires_after_record_id": "...", "policy_action": "BLOCK",
 "reason": "G0007: port sweep, 12 suspicious flows"}
```

### 14.6 Final submission: three CSV files uploaded to the API

| File | Content |
|---|---|
| `classification.csv` | One row per record, **every** hidden record exactly once: `record_id, predicted_class, anomaly_score, evidence_status` (from A3: final class, A2 anomaly score, evidence status). Includes flows that get blocked during replay. |
| `policy.csv` | One row per policy created: `policy_id, activated_after_record_id, scope_type, scope_value, expires_after_record_id, policy_action` |
| `replay.csv` | One row per record exactly once, in replay order. The printed table in the brief repeats the policy columns, but the text describes `action` (ALLOW/BLOCK) and `applied_policy_id`. **Likely columns: `record_id, action, applied_policy_id`. Confirm the exact columns with the organizers/API spec.** |

Do not submit actual labels. Use organizer record IDs exactly as given.

### 14.7 Validation script (must pass before every upload)

- Every hidden record appears exactly once in `classification.csv` and in `replay.csv`, same IDs as the input file.
- `predicted_class` is one of the five classes; no empty `anomaly_score`/`evidence_status`.
- Every BLOCK references an existing policy whose scope matches the record's source IP and whose active window contains the record.
- Every ALLOW has an empty `applied_policy_id`.
- No policy applies to the record that triggered it or to earlier records.
- Policy IDs unique, `scope_type = SOURCE_IP`, `policy_action = BLOCK`.
- Replay order equals the supplied order.

### 14.8 Final live demonstration (panel)

Run the code live and show: all five agents' outputs for sample flows (A1 class and confidence, A2 anomaly and evidence, A3 consensus and status, A4 group with members and evidence, A5 policy with activation, scope and expiry), sample ALLOW and BLOCK decisions with their policy IDs, and an explanation of false positives, false blocks and the trade-off between containing attacks and keeping benign traffic. The panel may ask for a fresh replay, so one command must reproduce the whole run from the input file. Judges assess implementation and evidence, not only the API score.

### 14.9 Schedule

- **Tonight (30 Oct):** finish and verify A1-A3 as predict-only code that needs no labels; build the replay engine, A4, A5, simulated dev replay, validator and demo script; tune thresholds on the simulated replay.
- **31 Oct, 10:00 AM:** hidden unlabeled replay data released. Run the full replay in the supplied order. Do not look for labels.
- **Around 1:30 PM:** final deadline, input files and API link announced in WhatsApp. Validate the three CSVs, upload, keep the receipt.
- **After upload:** rehearse the demo and the false-positive/false-block explanation.

### 14.10 Questions to confirm with the organizers

1. Exact columns of `replay.csv` (record ID, action, applied policy ID?).
2. Is endpoint/time metadata (source IP, sequence) available for the labeled eval file so A4/A5 can be tested on real structure, or only for the hidden set?
3. Which columns count as "permitted flow features" for classification?
4. Is the expiry record included in the policy window, and are windows measured in replay order of record IDs?

---

## 15. OFFICIAL LEVEL 2 SPEC AND CURRENT STATUS (31 Oct, supersedes section 14 wherever they differ)

**Read this section first.** It comes from the organizers' stage page (`c-thon.vercel.app/cyber/L2`) and the hidden-set README. Section 14 was written before these details were known.

**Deadline: 31 Oct 2026, 12:30 PM IST.** The latest valid submission counts, so submit a valid first version early (target 12:05) and resubmit improvements only if time remains.

### 15.1 Hidden input

- `records.csv`: **200 unlabeled flows**, official replay order `seq` 1-200. Columns: `record_id` (F000001..F000200), `seq`, `day`, `time_offset`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`, plus the same 78 numeric flow features as the training pack. No label column.
- Endpoint columns and `source_port`, `destination_port`, `protocol`, `day`, `time_offset` are metadata for correlation only, **never classifier features**. A1-A3 must use only the model feature columns (select by name), so extra columns must be ignored. The file is **CSV** (our dev pipeline used parquet, so support both).
- Because there are only 200 records, parameters tuned on the 30,000-flow simulated replay (window 200 records, TTL 250 records, min flows 3) are far too large. Rescale: use a window of about 40-60 records and a TTL of about 20-40 records, then adjust after looking at the actual per-source-IP structure of the hidden flows.

### 15.2 Official output files (exact names and headers)

| File | Exact header | Rows |
|---|---|---|
| `classification.csv` | `record_id,predicted_class,anomaly_score,evidence_status` | exactly 200, one per record_id |
| `replay.csv` | `record_id,action,active_policy_id` | exactly 200, one per record_id, any order |
| `policies.csv` | `policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id` | 0 or more, a ledger |

**Differences from section 14 and from our existing code (fix these):**
1. The policy file is named **`policies.csv`** (not `policy.csv`) and has **no `policy_action` column**.
2. `replay.csv` column is **`active_policy_id`** (not `applied_policy_id`). An ALLOW must have the literal value **`NONE`** (not empty).
3. `evidence_status` must be exactly one of **`AGREE`, `CONFLICT`, `UNCERTAIN`**. Our internal statuses (CONFIRMED, CONFLICT_RESOLVED, LOW_CONFIDENCE, UNKNOWN_THREAT) must be mapped only at the output stage: A1 and A2 agree -> `AGREE`; A1 and A2 disagree (including a BENIGN class with an anomalous flow) -> `CONFLICT`; low confidence or escalated for lack of evidence -> `UNCERTAIN`. Keep the internal statuses in the logs and demo.
4. `predicted_class` is one of BENIGN, BRUTE_FORCE, DOS, DDOS, PORT_SCAN. `anomaly_score` is a number from 0 to 1 (higher = more anomalous). It must not be empty.

### 15.3 Policy semantics (exact)

- `scope_type` is `SOURCE_IP`, `DESTINATION_IP` or `SRC_DST_PAIR`; for the scored interface use **`SOURCE_IP`** with an exact observed source IP (pairs use `source|destination`; no wildcards or CIDR).
- A policy is active for records with `seq` strictly after `activated_after_record_id` up to and **including** `expires_after_record_id`. Rule used by the validator: `activatedIndex < i <= expiresIndex` and the scope matches the flow exactly.
- For each record: if any policy matches, `action = BLOCK` and `active_policy_id` = the **lexicographically smallest** matching `policy_id`; otherwise `action = ALLOW` and `active_policy_id = NONE`. An ALLOW must never have a matching active policy. The validator recomputes every replay row from `policies.csv`, so any mismatch rejects the submission.
- The triggering record itself is not blocked by the policy it creates (the window starts on the next record). Policies are created only from evidence in records already replayed (no future records, no labels).

### 15.4 Scoring (what to optimize)

| Component | Points | Source |
|---|---:|---|
| Classification macro-F1 | 30 | `classification.csv` |
| Anomaly evidence | 10 | `classification.csv` |
| Attack containment | 25 | `replay.csv` (attack flows blocked) |
| Benign preservation | 25 | `replay.csv` (benign flows not blocked) |
| Early containment | 10 | `replay.csv` (blocking soon after attacks start) |

The trade-off is between containment and early containment (block quickly, use a low evidence threshold such as 2 suspicious flows) and preservation (do not block benign IPs). With only 200 records, quick action matters, so a minimum of 2 suspicious flows is probably better than 3. Inspect the hidden data's per-IP structure (without labels) before choosing.

### 15.5 Current status (what already exists in the project folder)

- Agent 1 v2 (LightGBM without Destination Port, 74 features), Agent 2 v2 (Ledoit-Wolf Mahalanobis on 15 PCA components of signed log1p features, benign-only), Agent 3 with the zero-day-hardened conflict rule (BENIGN + anomalous -> UNKNOWN_THREAT, escalate, `suspicious = true`). Eval: accuracy about 100%, macro-F1 0.9998.
- Level 2 code already built and validated on a **simulated** 30,000-flow replay: `predict.py`, `make_dev_replay.py`, `agent4_temporal.py`, `agent5_defense.py`, `replay_engine.py`, `validate_submission.py`, `evaluate_replay.py`, `demo.py`. It uses `MODEL_VERSION = "v2"` in `config.py`.
- On the simulated replay (TTL 250, min flows 3): containment 84.67%, collateral 4.37% (all on shared gateway IPs, 0 pure benign IPs blocked).
- Independent official-rule checker: `check_official.py` (see 15.6). It supersedes `validate_submission.py` for the final files.

### 15.6 Final run procedure (follow exactly)

1. Put `records.csv` in the project folder. Run the pipeline: A1-A3 batch inference (`predict.py` logic) on all 200 records, then the causal replay loop in `seq` order (A4, A5).
2. Write the three official files (headers in 15.2) to `outputs/final/`.
3. Run: `python check_official.py --records records.csv --classification outputs/final/classification.csv --replay outputs/final/replay.csv --policies outputs/final/policies.csv`. All checks must pass.
4. Upload all three CSVs to the stage page. Keep a copy of the files and the receipt.
5. Only then improve parameters, regenerate, re-check and resubmit if there is time before 12:30 PM.
6. Never inspect, guess or use labels. Never use future records in decisions.
7. After submission: prepare the live demo (`demo.py` shows all five agents, a group, a policy activation and expiry, ALLOW/BLOCK samples) and the false-positive / false-block explanation.
