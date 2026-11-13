"""Train + evaluate the Isolation Forest network anomaly model.

Why Isolation Forest: unsupervised (benign-only training matches reality: labelled attacks are scarce),
no distance metric to tune, handles mixed-scale features, cheap inference per flow.
Usage: python -m app.ml.train_anomaly [--pcap-dir DIR]   (DIR = your own benign captures, optional)
"""
import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

from ..analysis.network import FEATURE_NAMES, flow_features, parse_pcap
from ..config import get_settings
from .synthetic_traffic import ANOMALY_PROFILES, BENIGN_PROFILES, make_flow

SEED = 42
TARGET_FPR = 0.02


def synth(rng, n_benign, n_anom):
    X, y, prof = [], [], []
    for _ in range(n_benign):
        p = rng.choice(BENIGN_PROFILES)
        f, fan = make_flow(rng, p)
        X.append([flow_features(f, fan)[k] for k in FEATURE_NAMES]); y.append(0); prof.append(p)
    for _ in range(n_anom):
        p = rng.choice(ANOMALY_PROFILES)
        f, fan = make_flow(rng, p)
        X.append([flow_features(f, fan)[k] for k in FEATURE_NAMES]); y.append(1); prof.append(p)
    return np.array(X), np.array(y), prof


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir")
    ap.add_argument("--out", default=str(get_settings().data_dir / "models"))
    args = ap.parse_args()
    rng = random.Random(SEED)
    X_train, _, _ = synth(rng, 6000, 0)
    source = "synthetic benign baseline (app/ml/synthetic_traffic.py)"
    if args.pcap_dir:
        rows = []
        for p in sorted(Path(args.pcap_dir).glob("*.pcap*")):
            parsed = parse_pcap(str(p))
            fan = {}
            for f in parsed["flows"].values():
                fan.setdefault((f.client, f.server), set()).add(f.port)
            rows += [[flow_features(f, len(fan[(f.client, f.server)]))[k] for k in FEATURE_NAMES] for f in parsed["flows"].values()]
        if rows:
            X_train = np.vstack([X_train, np.array(rows)])
            source += f" + {len(rows)} flows from user captures"
    model = IsolationForest(n_estimators=300, contamination="auto", random_state=SEED, n_jobs=-1).fit(X_train)
    # Decision threshold = score exceeded by TARGET_FPR of an independent benign validation set (never the test set).
    X_val, _, _ = synth(random.Random(SEED + 7), 3000, 0)
    threshold = float(np.quantile(-model.score_samples(X_val), 1 - TARGET_FPR))

    # Held-out evaluation set generated with a different seed: 3000 benign + 150 anomalous flows (~4.8% anomalies).
    X_te, y_te, prof = synth(random.Random(SEED + 1), 3000, 150)
    score = -model.score_samples(X_te)          # higher = more anomalous
    pred = (score >= threshold).astype(int)
    sweep = {}
    for fpr in (0.005, 0.01, 0.02, 0.05):
        t = float(np.quantile(-model.score_samples(X_val), 1 - fpr)); pr = (score >= t).astype(int)
        sweep[str(fpr)] = {'precision': round(precision_score(y_te, pr, zero_division=0), 3), 'recall': round(recall_score(y_te, pr), 3)}
    tn, fp, fn, tp = confusion_matrix(y_te, pred).ravel()
    per_profile = {}
    for p in sorted(set(prof)):
        idx = [i for i, q in enumerate(prof) if q == p]
        per_profile[p] = {"n": len(idx), "flagged": int(pred[idx].sum())}
    report = {
        "model": "IsolationForest(n_estimators=300)", "decision_threshold": round(threshold, 5), "threshold_rule": f"score at the {100 * (1 - TARGET_FPR):.0f}th percentile of an independent benign validation set (target FPR {TARGET_FPR})", "threshold_sweep_target_fpr": sweep, "features": FEATURE_NAMES, "training_data": source, "train_rows": int(len(X_train)),
        "evaluation_data": "held-out synthetic set, independent seed: 3000 benign + 150 anomalous flows",
        "metrics": {"precision": round(precision_score(y_te, pred), 4), "recall": round(recall_score(y_te, pred), 4), "f1": round(f1_score(y_te, pred), 4),
                    "roc_auc": round(roc_auc_score(y_te, score), 4), "average_precision": round(average_precision_score(y_te, score), 4),
                    "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}},
        "flagged_by_profile": per_profile, "trained_at": datetime.now(timezone.utc).isoformat(),
        "limitations": ["Trained and evaluated on SYNTHETIC traffic. The scores measure agreement with the generator, not performance on a real network.",
                        "An anomaly is statistical rarity relative to the baseline, not evidence of malice. ARGUS reports ML-only anomalies as 'suspicious' at most.",
                        "Per-flow features cannot see payloads or multi-flow campaigns.",
                        "Retrain with --pcap-dir on benign captures from the monitored network before relying on it."],
    }
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "threshold": threshold, "features": FEATURE_NAMES, "median": np.median(X_train, axis=0).tolist(),
                 "iqr": (np.percentile(X_train, 75, axis=0) - np.percentile(X_train, 25, axis=0)).tolist(),
                 "p01": np.percentile(X_train, 1, axis=0).tolist(), "p99": np.percentile(X_train, 99, axis=0).tolist()}, out / "anomaly_iforest.joblib", compress=3)
    (out / "anomaly_metrics.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
