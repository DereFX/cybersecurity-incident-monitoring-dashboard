"""Train the supervised network classifier and save reproducible metadata."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.network_model import train_model


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--data",
        type=Path,
        default=ROOT / "data/raw/unsw_nb15_network_events_quickstart.csv",
    )
    parser.add_argument(
        "--model", type=Path, default=ROOT / "models/network_classifier.joblib"
    )
    parser.add_argument(
        "--metadata", type=Path, default=ROOT / "models/network_classifier_metrics.json"
    )
    parser.add_argument("--minimum-recall", type=float, default=0.95)
    args = parser.parse_args()
    metadata = train_model(
        args.data,
        args.model,
        args.metadata,
        minimum_recall=args.minimum_recall,
    )
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()

