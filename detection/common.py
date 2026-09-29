"""Common helpers for deterministic rule alerts."""

from __future__ import annotations

import hashlib
from datetime import datetime


def stable_detection_key(
    rule_name: str,
    source_dataset: str,
    entity: str,
    window_start: datetime,
) -> str:
    """Build a repeatable key used by MongoDB and MySQL deduplication."""

    material = "|".join(
        [rule_name, source_dataset, entity, window_start.isoformat()]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def alert_id_from_key(detection_key: str) -> str:
    return f"ALT-{detection_key[:20].upper()}"

