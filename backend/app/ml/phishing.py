"""Inference for the phishing URL classifier, with a per-prediction explanation."""
import json
from functools import lru_cache

import joblib
import numpy as np

from ..config import get_settings
from .features import FEATURES, extract_features

FINDING_THRESHOLD = 0.8


@lru_cache
def _load():
    path = get_settings().data_dir / "models" / "phishing_rf.joblib"
    if not path.exists():
        return None
    return joblib.load(path)


def model_metrics() -> dict | None:
    p = get_settings().data_dir / "models" / "phishing_metrics.json"
    return json.loads(p.read_text()) if p.exists() else None


def predict(url: str) -> dict | None:
    """Return {'probability', 'features', 'contributions'} or None when no trained model is installed.

    Contributions are computed by single-feature ablation: each feature is replaced by its training
    median and the change in predicted probability is recorded. This is a local sensitivity measure,
    not a causal explanation.
    """
    bundle = _load()
    if bundle is None:
        return None
    feats = extract_features(url)
    x = np.array([[float(feats[n]) for n in FEATURES]])
    model = bundle["model"]
    p = float(model.predict_proba(x)[0, 1])
    medians = bundle["medians"]
    batch = np.repeat(x, len(FEATURES), axis=0)
    for i in range(len(FEATURES)):
        batch[i, i] = medians[i]
    deltas = p - model.predict_proba(batch)[:, 1]
    contrib = sorted(({"feature": FEATURES[i], "value": round(float(x[0, i]), 4), "training_median": round(float(medians[i]), 4), "delta_probability": round(float(deltas[i]), 4)}
                      for i in range(len(FEATURES)) if abs(deltas[i]) >= 0.01), key=lambda c: -abs(c["delta_probability"]))[:6]
    return {"probability": round(p, 4), "threshold": FINDING_THRESHOLD, "contributions": contrib}
