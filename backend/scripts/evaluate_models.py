"""Reproducible evaluation of the INSTALLED models. Recomputes every reported metric from scratch and
compares it with the figures stored next to the model, so the published numbers can be checked.

  python scripts/evaluate_models.py                        # anomaly model only (needs no external data)
  python scripts/evaluate_models.py --phishing-data DIR    # also the phishing classifier (see fetch_datasets.sh)
Exit code 1 if any recomputed metric differs from the stored one.
"""
import argparse
import json
import random
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from app.analysis.ioc import registered_domain  # noqa: E402
from app.ml import train_anomaly, train_phishing  # noqa: E402
from app.ml.features import vectorise  # noqa: E402

MODELS = ROOT / "data" / "models"
ok = True


def check(name, stored, recomputed):
    global ok
    same = abs(stored - recomputed) < 1e-4
    ok &= same
    print(f"  {name:<22} stored {stored:<8} recomputed {round(recomputed, 4):<8} {'OK' if same else 'MISMATCH'}")


def anomaly():
    print("Network anomaly model (IsolationForest), held-out synthetic set, seed 43")
    b = joblib.load(MODELS / "anomaly_iforest.joblib")
    stored = json.loads((MODELS / "anomaly_metrics.json").read_text())["metrics"]
    X, y, _ = train_anomaly.synth(random.Random(train_anomaly.SEED + 1), 3000, 150)
    score = -b["model"].score_samples(X)
    pred = (score >= b["threshold"]).astype(int)
    check("precision", stored["precision"], precision_score(y, pred))
    check("recall", stored["recall"], recall_score(y, pred))
    check("f1", stored["f1"], f1_score(y, pred))
    check("roc_auc", stored["roc_auc"], roc_auc_score(y, score))
    print("  confusion matrix (tn, fp, fn, tp):", confusion_matrix(y, pred).ravel().tolist())


def phishing(data_dir: Path):
    print("Phishing URL classifier (RandomForest), domain-grouped held-out split, seed 42")
    b = joblib.load(MODELS / "phishing_rf.joblib")
    stored = json.loads((MODELS / "phishing_metrics.json").read_text())
    urls, y = train_phishing.load(data_dir)
    groups = np.array([registered_domain(u.split("/")[0].split(":")[0]) or u.split("/")[0] for u in urls])
    X = np.array([vectorise(u) for u in urls])
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=train_phishing.SEED).split(X, y, groups))
    assert not set(groups[tr]) & set(groups[te])
    p = b["model"].predict_proba(X[te])[:, 1]
    for thr, key in ((0.5, "test_metrics_threshold_0.5"), (0.8, "test_metrics_threshold_0.8_used_for_findings")):
        m = train_phishing.metrics(y[te], (p >= thr).astype(int), p)
        print(f" threshold {thr}:")
        for k in ("accuracy", "precision", "recall", "f1", "roc_auc"):
            check(k, stored[key][k], m[k])
        print("  confusion matrix:", m["confusion_matrix"])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--phishing-data")
    args = ap.parse_args()
    anomaly()
    if args.phishing_data:
        phishing(Path(args.phishing_data))
    else:
        print("Phishing classifier: skipped (pass --phishing-data; the corpus is not bundled)")
    print("RESULT:", "all recomputed metrics match the stored figures" if ok else "MISMATCH")
    sys.exit(0 if ok else 1)
