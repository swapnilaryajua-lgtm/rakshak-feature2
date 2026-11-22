"""Independent checker for the three Level 2 CSVs, written from the organizers' stage page rules.
Usage:
    python check_official.py --records records.csv --classification outputs/classification.csv \
        --replay outputs/replay.csv --policies outputs/policies.csv
Prints PASS/FAIL per rule and exits with code 1 if anything fails.
"""
import argparse
import sys
import pandas as pd

CLASSES = {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"}
STATUS = {"AGREE", "CONFLICT", "UNCERTAIN"}
SCOPES = {"SOURCE_IP", "DESTINATION_IP", "SRC_DST_PAIR"}
H_CLS = ["record_id", "predicted_class", "anomaly_score", "evidence_status"]
H_REP = ["record_id", "action", "active_policy_id"]
H_POL = ["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id"]

ap = argparse.ArgumentParser()
ap.add_argument("--records", required=True)
ap.add_argument("--classification", required=True)
ap.add_argument("--replay", required=True)
ap.add_argument("--policies", required=True)
a = ap.parse_args()

fails = []
def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else f"  -> {detail}"))
    if not ok:
        fails.append(name)

rec = pd.read_csv(a.records, dtype=str, usecols=["record_id", "seq", "source_ip", "destination_ip"])
rec["seq"] = rec["seq"].astype(int)
rec = rec.sort_values("seq").reset_index(drop=True)
ids = list(rec["record_id"])
pos = {r: i for i, r in enumerate(ids)}

cls = pd.read_csv(a.classification, dtype=str, keep_default_na=False)
rep = pd.read_csv(a.replay, dtype=str, keep_default_na=False)
pol = pd.read_csv(a.policies, dtype=str, keep_default_na=False)

check("classification header", list(cls.columns) == H_CLS, list(cls.columns))
check("replay header", list(rep.columns) == H_REP, list(rep.columns))
check("policies header", list(pol.columns) == H_POL, list(pol.columns))
if fails:
    sys.exit(1)

check("classification: one row per record_id", sorted(cls.record_id) == sorted(ids), f"{len(cls)} rows vs {len(ids)}")
check("replay: one row per record_id", sorted(rep.record_id) == sorted(ids), f"{len(rep)} rows vs {len(ids)}")
check("predicted_class valid", cls.predicted_class.isin(CLASSES).all(), cls.loc[~cls.predicted_class.isin(CLASSES), "predicted_class"].unique()[:5])
sc = pd.to_numeric(cls.anomaly_score, errors="coerce")
check("anomaly_score numeric in [0,1]", sc.notna().all() and sc.between(0, 1).all())
check("evidence_status valid", cls.evidence_status.isin(STATUS).all(), cls.loc[~cls.evidence_status.isin(STATUS), "evidence_status"].unique()[:5])
check("action valid", rep.action.isin({"ALLOW", "BLOCK"}).all())

check("policy_id unique", pol.policy_id.is_unique)
check("scope_type valid", pol.scope_type.isin(SCOPES).all())
check("policy record ids exist", pol.activated_after_record_id.isin(ids).all() and pol.expires_after_record_id.isin(ids).all())

src = set(rec.source_ip); dst = set(rec.destination_ip)
pairs = set(rec.source_ip + "|" + rec.destination_ip)
def scope_ok(r):
    return (r.scope_type == "SOURCE_IP" and r.scope_value in src) or \
           (r.scope_type == "DESTINATION_IP" and r.scope_value in dst) or \
           (r.scope_type == "SRC_DST_PAIR" and r.scope_value in pairs)
check("scope_value is an exact observed endpoint", all(scope_ok(r) for r in pol.itertuples()) if len(pol) else True)
if len(pol) and pol.activated_after_record_id.isin(ids).all() and pol.expires_after_record_id.isin(ids).all():
    check("activation is before expiry", all(pos[r.activated_after_record_id] < pos[r.expires_after_record_id] for r in pol.itertuples()))

# recompute replay from the ledger: activated < i <= expires, scope match, smallest policy_id
exp = {}
for i, r in enumerate(rec.itertuples()):
    m = []
    for p in pol.itertuples():
        if p.activated_after_record_id in pos and p.expires_after_record_id in pos and pos[p.activated_after_record_id] < i <= pos[p.expires_after_record_id]:
            v = {"SOURCE_IP": r.source_ip, "DESTINATION_IP": r.destination_ip, "SRC_DST_PAIR": r.source_ip + "|" + r.destination_ip}[p.scope_type]
            if v == p.scope_value:
                m.append(p.policy_id)
    exp[r.record_id] = ("BLOCK", min(m)) if m else ("ALLOW", "NONE")
bad = [(r.record_id, r.action, r.active_policy_id, exp.get(r.record_id)) for r in rep.itertuples() if (r.action, r.active_policy_id) != exp.get(r.record_id)]
check("replay recomputes exactly from policies.csv (window, scope, smallest id, NONE for ALLOW)", not bad, bad[:3])

print()
print("ALL CHECKS PASSED" if not fails else f"{len(fails)} CHECK(S) FAILED")
sys.exit(1 if fails else 0)
