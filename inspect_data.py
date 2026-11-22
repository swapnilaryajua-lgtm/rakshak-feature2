"""Quick look at the Cyber data pack. Edit the two paths if needed, then run:
    pip install pandas pyarrow
    python inspect_data.py
Paste the printed output back so the next code matches your exact data.
"""
import numpy as np
import pandas as pd

TRAIN_PATH = "Cyber/training/flows.parquet"
EVAL_PATH = "Cyber/eval/flows.parquet"
LABEL = "label"
ID = "record_id"

tr = pd.read_parquet(TRAIN_PATH)
ev = pd.read_parquet(EVAL_PATH)
tr.columns = tr.columns.str.strip()
ev.columns = ev.columns.str.strip()

for name, df in [("TRAIN", tr), ("EVAL", ev)]:
    feats = [c for c in df.columns if c not in (ID, LABEL)]
    num = df[feats].select_dtypes(include=[np.number])
    print("=" * 70)
    print(name, "shape:", df.shape)
    print("non-numeric feature columns:", [c for c in feats if c not in num.columns])
    print("label counts:")
    print(df[LABEL].value_counts(dropna=False))
    print("inf values:", int(np.isinf(num).sum().sum()), "| NaN values:", int(df.isna().sum().sum()))
    print("duplicate feature rows (ignoring record_id):", int(df.duplicated(subset=feats + [LABEL]).sum()))
    print("constant columns:", [c for c in num.columns if num[c].nunique(dropna=True) <= 1])
    print("record_id sample:", df[ID].head(3).tolist(), "| unique ids:", df[ID].nunique() == len(df))

print("=" * 70)
print("same feature columns in both files:", list(tr.columns) == list(ev.columns))
print("record_id overlap between train and eval:", len(set(tr[ID]) & set(ev[ID])))
print("labels only in train:", set(tr[LABEL]) - set(ev[LABEL]), "| only in eval:", set(ev[LABEL]) - set(tr[LABEL]))
