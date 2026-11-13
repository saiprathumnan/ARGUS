"""Inference for the network anomaly model."""
import json
from functools import lru_cache

import joblib
import numpy as np

from ..config import get_settings


@lru_cache
def _load():
    path = get_settings().data_dir / "models" / "anomaly_iforest.joblib"
    return joblib.load(path) if path.exists() else None


def model_metrics() -> dict | None:
    p = get_settings().data_dir / "models" / "anomaly_iforest.joblib"
    m = get_settings().data_dir / "models" / "anomaly_metrics.json"
    return json.loads(m.read_text()) if p.exists() and m.exists() else None


def score_flows(feature_rows: list[dict]) -> list[dict] | None:
    """For each flow return {'anomalous', 'score', 'deviations'}.

    'deviations' lists features outside the 1st-99th percentile of the training baseline, with a robust
    z-score ((x - median) / IQR). They describe *how* the flow is unusual; they are not the model's
    internal attribution (Isolation Forest has no exact per-feature decomposition).
    """
    b = _load()
    if b is None or not feature_rows:
        return None if b is None else []
    names = b["features"]
    X = np.array([[row[n] for n in names] for row in feature_rows])
    score = -b["model"].score_samples(X)
    out = []
    for i in range(len(X)):
        dev = []
        for j, n in enumerate(names):
            if X[i, j] < b["p01"][j] or X[i, j] > b["p99"][j]:
                iqr = b["iqr"][j] or 1.0
                dev.append({"feature": n, "value": round(float(X[i, j]), 3), "baseline_median": round(b["median"][j], 3), "robust_z": round(float((X[i, j] - b["median"][j]) / iqr), 2)})
        dev.sort(key=lambda d: -abs(d["robust_z"]))
        out.append({"anomalous": bool(score[i] >= b["threshold"]), "score": round(float(score[i]), 4), "deviations": dev[:5]})
    return out
