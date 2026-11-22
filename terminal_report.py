"""CyberSentinel terminal report: run log + accuracy results, printed in the terminal (no dashboard).

    python terminal_report.py                 # summary of the final hidden-set replay + accuracy results
    python terminal_report.py --log           # also print every record's decision (200 lines)
    python terminal_report.py --no-color      # plain text (if colors look odd)
    python terminal_report.py --skip-accuracy # only the replay log

Defaults: records.csv, outputs/final/{classification,replay,policies}.csv,
          outputs/results.csv + Cyber/eval/flows.parquet (labeled eval accuracy).
Only the Python standard library is needed (pandas + pyarrow only for the labeled-eval accuracy part).
"""
import argparse
import csv
import os
import sys
from collections import Counter, defaultdict

ap = argparse.ArgumentParser()
ap.add_argument("--records", default="records.csv")
ap.add_argument("--dir", default="outputs/final")
ap.add_argument("--results", default="outputs/results.csv")
ap.add_argument("--eval", default="Cyber/eval/flows.parquet")
ap.add_argument("--log", action="store_true")
ap.add_argument("--no-color", action="store_true")
ap.add_argument("--skip-accuracy", action="store_true")
a = ap.parse_args()

USE_COLOR = not a.no_color
if USE_COLOR and os.name == "nt":
    os.system("")  # enables ANSI colors in the Windows terminal


def c(txt, code):
    return f"\033[{code}m{txt}\033[0m" if USE_COLOR else str(txt)


G = lambda t: c(t, "92")
R = lambda t: c(t, "91")
Y = lambda t: c(t, "93")
B = lambda t: c(t, "96")
M = lambda t: c(t, "95")
D = lambda t: c(t, "90")
BOLD = lambda t: c(t, "1")


def banner(title):
    print()
    print(B("=" * 78))
    print(BOLD(f"  {title}"))
    print(B("=" * 78))


def read_csv(path):
    if not os.path.exists(path):
        sys.exit(R(f"File not found: {path}"))
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def bar(n, total, width=28):
    k = int(round(width * n / total)) if total else 0
    return "#" * k + "." * (width - k)


def table(header, rows, widths):
    line = "  " + "  ".join(str(h).ljust(w) for h, w in zip(header, widths))
    print(BOLD(line))
    print("  " + "  ".join("-" * w for w in widths))
    for r in rows:
        print("  " + "  ".join(str(x).ljust(w) for x, w in zip(r, widths)))


# ---------------------------------------------------------------- load
recs = read_csv(a.records)
recs.sort(key=lambda r: int(r["seq"]))
cls = {r["record_id"]: r for r in read_csv(os.path.join(a.dir, "classification.csv"))}
rep = {r["record_id"]: r for r in read_csv(os.path.join(a.dir, "replay.csv"))}
pols = read_csv(os.path.join(a.dir, "policies.csv"))
ids = [r["record_id"] for r in recs]
pos = {r: i for i, r in enumerate(ids)}
N = len(recs)

rows = []
for r in recs:
    rid = r["record_id"]
    pol = rep[rid]["active_policy_id"].strip()
    rows.append({"id": rid, "seq": int(r["seq"]), "src": r["source_ip"], "dst": r["destination_ip"],
                 "dport": r.get("destination_port", ""), "cls": cls[rid]["predicted_class"],
                 "score": float(cls[rid]["anomaly_score"]), "status": cls[rid]["evidence_status"],
                 "action": rep[rid]["action"], "pol": "" if pol.upper() == "NONE" else pol})


def flagged(x):
    return x["cls"] != "BENIGN" or x["status"] != "AGREE"


banner("CYBERSENTINEL  |  FINAL REPLAY REPORT (hidden records, official order)")
print(f"  records file     : {a.records}  ({N} flows, seq {rows[0]['seq']} to {rows[-1]['seq']})")
print(f"  results folder   : {a.dir}")
print(f"  files            : classification.csv ({len(cls)} rows) | replay.csv ({len(rep)} rows) | policies.csv ({len(pols)} policies)")

# ---------------------------------------------------------------- replay verification (official rules)
bad = 0
for i, x in enumerate(rows):
    m = []
    for p in pols:
        ap_, ep_ = p["activated_after_record_id"], p["expires_after_record_id"]
        if ap_ in pos and ep_ in pos and pos[ap_] < i <= pos[ep_]:
            v = {"SOURCE_IP": x["src"], "DESTINATION_IP": x["dst"], "SRC_DST_PAIR": x["src"] + "|" + x["dst"]}[p["scope_type"]]
            if v == p["scope_value"]:
                m.append(p["policy_id"])
    exp = ("BLOCK", min(m)) if m else ("ALLOW", "")
    if (x["action"], x["pol"]) != exp:
        bad += 1
ok_ids = sorted(cls) == sorted(ids) and sorted(rep) == sorted(ids)
print(f"  one row per record_id      : {G('PASS') if ok_ids else R('FAIL')}")
print(f"  replay matches policy ledger: {G('PASS') if bad == 0 else R('FAIL (' + str(bad) + ' rows differ)')}  "
      f"{D('(active window: activated < record <= expires, smallest policy id, ALLOW = NONE)')}")

# ---------------------------------------------------------------- distributions
banner("1. AGENT OUTPUTS")
cc = Counter(x["cls"] for x in rows)
print(BOLD("  A1 predicted class"))
for k, v in cc.most_common():
    print(f"    {k:<12} {str(v).rjust(4)}  {bar(v, N)}  {v / N * 100:5.1f}%")
sc = Counter(x["status"] for x in rows)
print(BOLD("\n  A3 evidence status (official labels)"))
for k in ("AGREE", "CONFLICT", "UNCERTAIN"):
    v = sc.get(k, 0)
    print(f"    {k:<12} {str(v).rjust(4)}  {bar(v, N)}  {v / N * 100:5.1f}%")
atk = [x["score"] for x in rows if x["cls"] != "BENIGN"]
ben = [x["score"] for x in rows if x["cls"] == "BENIGN"]
mean = lambda v: sum(v) / len(v) if v else float("nan")
print(BOLD("\n  A2 anomaly score (0 to 1, higher = more anomalous)"))
print(f"    mean on predicted-attack flows : {mean(atk):.3f}  (n={len(atk)})")
print(f"    mean on predicted-benign flows : {mean(ben):.3f}  (n={len(ben)})")

# ---------------------------------------------------------------- decisions
banner("2. REPLAY DECISIONS (A4 correlation + A5 adaptive defense)")
ac = Counter(x["action"] for x in rows)
for k in ("ALLOW", "BLOCK"):
    col = G if k == "ALLOW" else R
    print(f"    {col(k):<14} {str(ac.get(k, 0)).rjust(4)}  {bar(ac.get(k, 0), N)}  {ac.get(k, 0) / N * 100:5.1f}%")

blocked_by_pol = Counter(x["pol"] for x in rows if x["action"] == "BLOCK")
print(BOLD("\n  Policy ledger (temporary SOURCE_IP blocks)"))
prow = []
for p in pols:
    a0, e0 = pos[p["activated_after_record_id"]], pos[p["expires_after_record_id"]]
    prow.append([p["policy_id"], p["scope_type"], p["scope_value"],
                 f"{p['activated_after_record_id']} (seq {a0 + 1})", f"{p['expires_after_record_id']} (seq {e0 + 1})",
                 e0 - a0, blocked_by_pol.get(p["policy_id"], 0)])
if prow:
    table(["policy", "scope", "value", "activated after", "expires after", "span", "blocked"], prow, [7, 10, 14, 22, 22, 5, 7])
else:
    print("    (no policies were created)")

# ---------------------------------------------------------------- per IP
print(BOLD("\n  Per source IP"))
st = defaultdict(lambda: [0, 0, 0, 0])
for x in rows:
    s = st[x["src"]]
    s[0] += 1
    s[1] += x["cls"] != "BENIGN"
    s[2] += flagged(x)
    s[3] += x["action"] == "BLOCK"
iprows = []
for ip, (n, atkn, fl, bl) in sorted(st.items(), key=lambda kv: (-kv[1][2] / kv[1][0], -kv[1][0])):
    hot = n >= 5 and fl / n >= 0.5
    iprows.append([ip, n, atkn, fl, (R(bl) if bl else str(bl)) if USE_COLOR else bl, R("attacker") if hot and USE_COLOR else ("attacker" if hot else "normal")])
table(["source ip", "flows", "attack-class", "flagged", "blocked", "profile"], [[*r[:4], r[4], r[5]] for r in iprows], [16, 6, 12, 8, 8, 10])
hot_ips = {ip for ip, (n, _, fl, _) in st.items() if n >= 5 and fl / n >= 0.5}
safe_blocked = sum(1 for x in rows if x["action"] == "BLOCK" and x["src"] not in hot_ips)
atk_flows = [x for x in rows if x["src"] in hot_ips]
atk_blocked = sum(1 for x in atk_flows if x["action"] == "BLOCK")
benign_flows = [x for x in rows if x["src"] not in hot_ips]
print(f"\n    flows from normal IPs blocked      : {G(safe_blocked) if safe_blocked == 0 else R(safe_blocked)} of {len(benign_flows)}"
      f"   {D('(by predicted behaviour; true labels are hidden)')}")
print(f"    flows from attacking IPs blocked    : {atk_blocked} of {len(atk_flows)}"
      f"   {D('(the first flow can never be blocked: policies only affect later records)')}")

# ---------------------------------------------------------------- events
banner("3. KEY EVENTS (in replay order)")
ev = []
first_atk = next((x for x in rows if x["src"] in hot_ips and flagged(x)), None)
if first_atk:
    ev.append((first_atk["seq"], 0, f"first attack-class flow {first_atk['id']} from {first_atk['src']} ({first_atk['cls']}, anomaly {first_atk['score']:.2f}) -> {first_atk['action']}"))
for p in pols:
    ev.append((pos[p["activated_after_record_id"]] + 1, 3, f"{p['policy_id']} CREATED after {p['activated_after_record_id']}: {p['scope_type']} {p['scope_value']} (applies to later records)"))
    ev.append((pos[p["expires_after_record_id"]] + 1, 2, f"{p['policy_id']} EXPIRES after {p['expires_after_record_id']} (inclusive)"))
fb = next((x for x in rows if x["action"] == "BLOCK"), None)
if fb:
    ev.append((fb["seq"], 1, f"first BLOCK {fb['id']} from {fb['src']} by {fb['pol']}"))
fa = next((x for x in rows if x["src"] not in hot_ips and flagged(x) and x["action"] == "ALLOW"), None)
if fa:
    ev.append((fa["seq"], 1, f"isolated anomaly flag on normal IP: {fa['id']} from {fa['src']} (status {fa['status']}) -> {fa['action']}, no policy"))
for seq, _prio, txt in sorted(ev):
    print(f"    seq {str(seq).rjust(3)}  {txt}")

# ---------------------------------------------------------------- optional full log
if a.log:
    banner("4. FULL DECISION LOG")
    print(D("  seq  record    source ip         class         anomaly  status     action  policy"))
    for x in rows:
        act = R("BLOCK") if x["action"] == "BLOCK" else G("ALLOW")
        stc = Y(x["status"].ljust(9)) if x["status"] != "AGREE" else x["status"].ljust(9)
        print(f"  {str(x['seq']).rjust(3)}  {x['id']}  {x['src'].ljust(16)}  {x['cls'].ljust(12)}  {x['score']:.3f}    {stc}  {act}{'' if x['action'] == 'BLOCK' else ' '}   {x['pol'] or '-'}")

# ---------------------------------------------------------------- accuracy
banner("ACCURACY AND SCORES")
print(BOLD("  A) Official API result on the hidden set (organizers' scorer, 31 Oct)"))
table(["component", "weight", "result"],
      [["Classification macro-F1", "30", "100.00%"], ["Anomaly evidence", "10", "93.10%"], ["Attack containment", "25", "99.00%"],
       ["Benign preservation", "25", "100.00%"], ["Early containment", "10", "95.16%"], ["TOTAL", "100", G("98.58 / 100")]],
      [26, 7, 14])
print(D("  The hidden set has no labels on our side, so this official score is the accuracy on it."))

if not a.skip_accuracy:
    print(BOLD("\n  B) Labeled eval set (114,185 flows), local check from saved results"))
    if not (os.path.exists(a.results) and os.path.exists(a.eval)):
        print(Y(f"    skipped: need {a.results} and {a.eval} (use --results / --eval to point to them)"))
    else:
        try:
            import pandas as pd
            res = pd.read_csv(a.results)
            pc = next((k for k in ("final_class", "predicted_class") if k in res.columns), None)
            lab = (pd.read_csv(a.eval, usecols=["record_id", "label"]) if a.eval.lower().endswith(".csv") else pd.read_parquet(a.eval, columns=["record_id", "label"]))
            m = res.merge(lab, on="record_id")
            y, p = list(m["label"]), list(m[pc])
            classes = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]
            tot = len(y)
            correct = sum(1 for u, v in zip(y, p) if u == v)
            print(f"    rows scored : {tot}   (results file: {a.results}, predictions column: {pc})")
            print(f"    accuracy    : {G(f'{correct / tot * 100:.4f}%')}   ({tot - correct} errors)")
            f1s, prow2 = [], []
            for k in classes:
                tp = sum(1 for u, v in zip(y, p) if u == k and v == k)
                fp = sum(1 for u, v in zip(y, p) if u != k and v == k)
                fn = sum(1 for u, v in zip(y, p) if u == k and v != k)
                pr = tp / (tp + fp) if tp + fp else 0.0
                rc = tp / (tp + fn) if tp + fn else 0.0
                f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
                f1s.append(f1)
                prow2.append([k, f"{pr:.4f}", f"{rc:.4f}", f"{f1:.4f}", tp + fn])
            print(f"    macro-F1    : {G(f'{sum(f1s) / len(f1s):.4f}')}\n")
            table(["class", "precision", "recall", "F1", "support"], prow2, [13, 10, 8, 8, 8])
            print(BOLD("\n    confusion matrix (rows = true, columns = predicted)"))
            print("    " + "".join(k[:9].rjust(11) for k in [""] + classes))
            for t in classes:
                print("    " + t[:11].ljust(11) + "".join(str(sum(1 for u, v in zip(y, p) if u == t and v == q)).rjust(11) for q in classes))
            print(D("\n    note: this uses the saved Day 1 results file; eval is a development set, the hidden set is the real test."))
        except Exception as e:
            print(Y(f"    could not compute: {e}"))

print()
print(G("Report complete."))