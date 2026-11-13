"""Train + evaluate the lexical phishing URL classifier.

Dataset: Sahingoz et al., "Machine learning based phishing detection from URLs" (Expert Systems with
Applications, 2019) - 37,175 phishing (PhishTank) and 36,400 legitimate (Yandex search) URLs,
published at https://github.com/ebubekirbbr/pdd . Fetch it with scripts/fetch_datasets.sh.

Leakage controls:
  * exact-duplicate URLs removed after canonicalisation
  * train/test split is GROUPED BY REGISTERED DOMAIN, so no domain appears on both sides
  * scheme and leading "www." are stripped (dataset artefacts)
Usage: python -m app.ml.train_phishing --data <dir with the two json files>
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from ..analysis.ioc import registered_domain
from ..config import get_settings
from .features import FEATURES, canonical, vectorise

SEED = 42


def load(data_dir: Path):
    urls, labels = [], []
    for name, label in (("data_phishing_37175.json", 1), ("data_legitimate_36400.json", 0)):
        for u in json.loads((data_dir / name).read_text(encoding="utf-8", errors="replace")):
            if isinstance(u, str) and u.strip():
                urls.append(canonical(u))
                labels.append(label)
    seen, U, y = set(), [], []
    for u, l in zip(urls, labels):
        if u not in seen:
            seen.add(u)
            U.append(u)
            y.append(l)
    return U, np.array(y)


def metrics(y, pred, proba):
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return {"accuracy": round(accuracy_score(y, pred), 4), "precision": round(precision_score(y, pred), 4), "recall": round(recall_score(y, pred), 4),
            "f1": round(f1_score(y, pred), 4), "roc_auc": round(roc_auc_score(y, proba), 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}, "false_positive_rate": round(fp / (fp + tn), 4)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", default=str(get_settings().data_dir / "models"))
    args = ap.parse_args()
    urls, y = load(Path(args.data))
    groups = np.array([registered_domain(u.split("/")[0].split(":")[0]) or u.split("/")[0] for u in urls])
    X = np.array([vectorise(u) for u in urls])
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED).split(X, y, groups))
    assert not set(groups[tr]) & set(groups[te]), "domain leakage between train and test"

    rf = RandomForestClassifier(n_estimators=80, min_samples_leaf=2, n_jobs=-1, random_state=SEED, class_weight="balanced")
    rf.fit(X[tr], y[tr])
    p_rf = rf.predict_proba(X[te])[:, 1]
    lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, random_state=SEED))
    lr.fit(X[tr], y[tr])
    p_lr = lr.predict_proba(X[te])[:, 1]

    report = {
        "model": "RandomForestClassifier(n_estimators=80, min_samples_leaf=2, class_weight=balanced)",
        "dataset": {"name": "Sahingoz et al. 2019 phishing URL dataset", "source": "https://github.com/ebubekirbbr/pdd",
                    "rows_after_dedup": int(len(urls)), "phishing": int(y.sum()), "legitimate": int((1 - y).sum())},
        "split": {"method": "GroupShuffleSplit by registered domain, test_size=0.2, seed=42", "train": int(len(tr)), "test": int(len(te)),
                  "train_domains": int(len(set(groups[tr]))), "test_domains": int(len(set(groups[te]))), "shared_domains": 0},
        "test_metrics_threshold_0.5": metrics(y[te], (p_rf >= 0.5).astype(int), p_rf),
        "test_metrics_threshold_0.8_used_for_findings": metrics(y[te], (p_rf >= 0.8).astype(int), p_rf),
        "baseline_logistic_regression_threshold_0.5": metrics(y[te], (p_lr >= 0.5).astype(int), p_lr),
        "feature_importance": dict(sorted(((n, round(float(i), 4)) for n, i in zip(FEATURES, rf.feature_importances_)), key=lambda kv: -kv[1])),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "limitations": ["Lexical features only: page content, hosting and reputation are not seen by the model.",
                        "Corpus dates from 2017-2018; URL fashions drift, so real-world accuracy today is expected to be lower than the held-out score.",
                        "Legitimate class comes from search results (deep content URLs); bare login pages of legitimate services are under-represented and may be over-flagged.",
                        "Scheme and 'www.' were removed as dataset artefacts.",
                        "Output is a model prediction, never verified threat intelligence. ARGUS caps ML-only findings at 'suspicious'."],
    }
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": rf, "features": FEATURES, "medians": np.median(X[tr], axis=0).tolist()}, out / "phishing_rf.joblib", compress=3)
    (out / "phishing_metrics.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
