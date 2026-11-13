#!/usr/bin/env bash
# Fetch the public phishing URL corpus used to train the classifier (not redistributed with ARGUS).
# Sahingoz et al., "Machine learning based phishing detection from URLs", Expert Systems with Applications, 2019.
set -euo pipefail
DEST="${1:-./datasets}"
mkdir -p "$DEST"
if [ ! -d "$DEST/pdd" ]; then git clone --depth 1 https://github.com/ebubekirbbr/pdd.git "$DEST/pdd"; fi
echo "Dataset at $DEST/pdd/input"
echo "Train:    python -m app.ml.train_phishing --data $DEST/pdd/input"
echo "Evaluate: python scripts/evaluate_models.py --phishing-data $DEST/pdd/input"
