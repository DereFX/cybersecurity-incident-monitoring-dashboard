"""Standard alert contract shared by every detection rule."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class DetectionAlert:
    alert_id: str
    detection_key: str
    rule_name: str
    timestamp: datetime
    severity: str
    source_dataset: str
    title: str
    description: str
    event_references: list[str]
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_document(self) -> dict[str, Any]:
        return asdict(self)

