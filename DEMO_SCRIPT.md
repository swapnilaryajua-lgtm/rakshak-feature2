# CyberSentinel: 5-Minute Live Demonstration Script & Panel Q&A

**Jaypee Agentic AI International Summit 2026 — Track 1: Agentic AI for Cybersecurity**  
**Project:** CyberSentinel: Multi-Agent Network Intrusion Detection & Adaptive Defense  
**Architecture:** 5 Deterministic Agents | Offline Causal Traffic Replay | No LLMs

---

## 1. Quick Startup & Commands

To launch the live presentation app for the judging panel:
```bash
# Option A: Full fresh run from records.csv (starts server & opens browser)
python demo_app.py

# Option B: Instant launch using cached precomputed data (safe fallback for stage)
python demo_app.py --precomputed
```

### Presentation Keybindings:
- **`P`**: Toggle Presenter Mode (enlarges text, dims chrome, shows live section talking points).
- **`Space`**: Play / Pause sequential traffic replay.
- **`Left` / `Right`**: Step backward / forward one flow.
- **`N`**: Jump directly to the next policy activation or expiry event.
- **`R`**: Trigger fresh end-to-end pipeline execution from the UI.
- **`?`**: Open keyboard shortcut and controls guide.

---

## 2. 5-Minute Presentation Flow (What to Click & What to Say)

### Minute 0:00 – 1:00: Problem & Architecture (Hero & Pipeline Section)
- **What to do:** Open the app. Point out the top badges: `SIMULATED / OFFLINE REPLAY`, `5 Deterministic Agents (No LLM)`, and the green `Matches Submitted Files` indicator.
- **What to say:**
  > *"Respected panel, CyberSentinel solves Track 1: combining multiple specialized AI agents to detect intrusions and actuate explainable, causal defense policies in network traffic replays.*
  > *Crucially, we do not use an LLM in this pipeline: tabular network flows require microsecond latency, zero hallucination, and deterministic mathematical guarantees.*
  > *Our pipeline splits responsibilities cleanly: Agent 1 classifies known threat signatures; Agent 2 independently assesses statistical anomaly distance on benign baselines; Agent 3 fuses their evidence with cost-aware decision boundaries; Agent 4 causally tracks sliding-window IP bursts; and Agent 5 activates bounded firewall policies."*

### Minute 1:00 – 2:00: Live Causal Replay (Section 2)
- **What to do:** Press **`Space`** to start replay at `2x` speed. Watch the timeline cells fill from left to right.
- **What to say:**
  > *"Here is the causal replay running across all 200 hidden flows. Watch how the firewall enforces existing policies first. At Seq 1 through 13, all traffic is benign and allowed.*
  > *At Seq 14, attacker IP `172.16.0.1` sends its first attack flow. Per firewall causality, that triggering packet itself stays ALLOW because no policy existed yet.*
  > *At Seq 18, the attacker sends a second suspicious flow. Agent 4 detects the burst, and Agent 5 immediately actuates policy `P0001`!*
  > *From Seq 19 onward, every subsequent hostile flow from `172.16.0.1` is immediately BLOCKED by active firewall rules."*

### Minute 2:00 – 3:00: Multi-Agent Record Inspection (Section 3)
- **What to do:** Click on cell **Seq 18 (`F000018`)** or **Seq 20 (`F000020`)**.
- **What to say:**
  > *"When we inspect an individual flow, we see full transparency across all five agents:*
  > *Agent 1 predicts the attack class with full probability distributions.*
  > *Agent 2 provides concrete feature evidence: here, the top deviations are Flow Packets/s and Forward Inter-Arrival Times, with exact numeric z-scores.*
  > *Agent 3 records an explainable rationale string with real numbers.*
  > *Agent 4 names the attack pattern—in this case a port sweep or flood attack—and lists the causal cluster members.*
  > *And Agent 5 logs the exact active window: Seq 19 through 48."*

### Minute 3:00 – 4:00: Policy Ledger & Source IP Containment (Sections 4 & 5)
- **What to do:** Scroll down to the **Policy Ledger (Gantt)** and **Source IP Telemetry Board**.
- **What to say:**
  > *"Look at our Policy Ledger: rather than permanently blacklisting an IP, CyberSentinel creates bounded, 30-record TTL policies. Over 200 flows, exactly 6 sequential policies (`P0001` through `P0006`) provide continuous containment.*
  > *Now look at the 14 observed source IPs: attacker `172.16.0.1` is 96% contained—96 flows blocked out of 100.*
  > *Most importantly: all 13 benign IPs (`192.168.10.x`) are 100% preserved. Four benign IPs had an isolated anomaly alert due to natural 5% statistical variance, but our `min_suspicious_flows = 2` safeguard prevented them from ever being blocked. Collateral damage is strictly zero."*

### Minute 4:00 – 5:00: Safe Defense, What-If & Validation (Sections 6, 7 & 8)
- **What to do:** Scroll to the **"Why This Is Safe" What-If Grid** and the **Official Validator Card**.
- **What to say:**
  > *"Judges often ask: why not block on the very first anomaly? In our interactive What-If sensitivity grid, you can see that setting `min_flows = 1` immediately causes false blocks on legitimate corporate IPs.*
  > *Our configuration (2 flows, TTL 30) was mathematically calibrated on our training split to maximize containment while eliminating false blocks.*
  > *Finally, our independent validator verifies all 15 official submission checks from `check_official.py`: all schemas match, every policy window is strictly causal, and replay decisions recompute identically from the ledger."*

---

## 3. Panel Q&A: 8 Likely Judge Questions with Concise Honest Answers

### Q1: What is the difference between false positives and false blocks in your system?
> **Answer:**
> *"A **false positive** occurs at the detection layer (Agents 1 & 2): a benign flow that receives an elevated anomaly score (our benign false-alarm rate is ~5%).*
> *A **false block** occurs at the actuation layer (Agent 5): actually dropping legitimate traffic at the firewall.*
> *By decoupling detection from response through Agent 4 and Agent 5, we ensure a false positive does NOT become a false block. A single anomalous flow only increases suspicion; it takes repeated, grouped hostility to actuate a policy."*

### Q2: Why require a minimum of 2 suspicious flows instead of blocking immediately on 1?
> **Answer:**
> *"In real-world networks and in our benign training data, natural statistical variance causes ~5% of normal flows to exceed the 95th percentile anomaly threshold. If we blocked on 1 flow, four legitimate enterprise IPs (`192.168.10.8`, `.17`, `.25`, `.19`) would have suffered firewall lockouts.*
> *Requiring 2 suspicious flows within a 50-record window acts as an evidence threshold: the probability of two independent false alarms occurring in the same short window is $0.05 \times 0.05 = 0.25\%$, effectively eliminating collateral damage."*

### Q3: Why use a 30-record TTL with renewal instead of permanent blacklisting?
> **Answer:**
> *"Permanent IP blacklisting is dangerous in modern networks due to DHCP reassignment, NAT gateways, and cloud IP recycling. A bounded TTL of 30 records ensures that defenses automatically cool down if traffic normalizes.*
> *If the attack continues—as seen with `172.16.0.1`—Agent 4 continuously observes the hostile traffic and Agent 5 immediately renews the policy (`P0001` &rarr; `P0002` &rarr; `...` &rarr; `P0006`), providing unbroken 96% containment without permanent lockouts."*

### Q4: Why did you choose NOT to use an LLM in the pipeline?
> **Answer:**
> *"Three reasons: latency, determinism, and safety.*
> *1. **Latency:** Our LightGBM and PCA-Mahalanobis pipeline processes over 2,000 flows per second. An LLM API call takes 200–800 ms per flow, which would collapse high-throughput network firewalls.*
> *2. **Determinism:** Security policies must be auditable and reproducible under `random_state=42`. LLMs can hallucinate IP addresses or reason unpredictably.*
> *3. **Cost & Reliability:** Our pipeline runs 100% offline with zero cloud tokens, zero API keys, and zero internet dependencies."*

### Q5: What are the 28 CONFLICT flows in your classification output?
> **Answer:**
> *"All 28 conflict flows belong to attacker `172.16.0.1`. In these flows, Agent 1 detected an attack signature with high confidence ($>0.85$), but Agent 2's anomaly score was moderate (~0.60–0.75) because the flow's statistical packet counters happened to resemble certain benign distributions.*
> *Agent 3's cost-aware rule specifically resolves this conflict: because a false allow (missed attack) is 5x more costly than a false block, high classifier confidence overrides anomaly neutrality. Fusion correctly categorized these as CONFLICT &rarr; BLOCK, and all 28 were contained."*

### Q6: Why does the triggering flow itself stay ALLOW?
> **Answer:**
> *"This is a fundamental law of firewall causality. When a packet arrives, the firewall checks its active rule ledger. At the instant packet $N$ arrives, no blocking rule exists yet. The packet is allowed through while the security engine inspects it.*
> *When inspection completes at record $N$, the firewall creates a rule: `activated_after_record_id = F000018`. The rule takes effect starting at packet $N+1$. Retroactively blocking packet $N$ would violate physical causality."*

### Q7: What would happen if an attacker IP was mixed with legitimate user traffic (e.g., a shared corporate proxy or NAT)?
> **Answer:**
> *"Agent 5 includes an explicit **benign-share safeguard**: if an IP's temporal window contains more than 25% benign flows, whole-IP blocking is suppressed to prevent locking out legitimate users.*
> *In production, we would escalate to narrower scopes: instead of `SOURCE_IP`, we would actuate `SRC_DST_PAIR` or port-specific rate-limiting (`RATE_LIMIT 10 req/s`), penalizing the attack vector while preserving user traffic."*

### Q8: What would you change for Level 3 or a commercial production deployment?
> **Answer:**
> *"Three key enhancements:*
> *1. **Sub-second Wall-Clock Leaky Bucket:** Transition from discrete record counts to real-time microsecond sliding windows with token-bucket rate limiting.*
> *2. **Hierarchical CIDR / Subnet Grouping:** Aggregate suspicious endpoints by `/24` or `/16` subnets to combat distributed botnets (DDoS) where each node only sends one packet.*
> *3. **Dynamic Feedback Loop:** Allow the firewall's drop-counter telemetry to directly update Agent 2's anomaly baseline, adapting to novel zero-day attack shifts in real time."*
