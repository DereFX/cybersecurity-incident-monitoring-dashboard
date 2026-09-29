"""Shared ETL data structures."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class NormalizedEvent:
    """Canonical event envelope stored in MongoDB.

    Source-specific fields remain available in ``raw_event``; optional canonical
    fields are populated only when the inspected source actually contains them.
    """

    event_id: str
    timestamp: datetime
    source_dataset: str
    event_type: str
    source_ip: str | None = None
    destination_ip: str | None = None
    user_id: str | None = None
    device_id: str | None = None
    protocol: str | None = None
    authentication_result: str | None = None
    attack_category: str | None = None
    original_labels: dict[str, Any] = field(default_factory=dict)
    raw_event: dict[str, Any] = field(default_factory=dict)

    def to_document(self) -> dict[str, Any]:
        """Return a MongoDB-ready dictionary without inventing absent fields."""

        return {key: value for key, value in asdict(self).items() if value is not None}


@dataclass(slots=True)
class ValidationReport:
    source_dataset: str
    row_count: int
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not self.errors


@dataclass(slots=True)
class LoadResult:
    events: list[NormalizedEvent]
    report: ValidationReport


class DatasetValidationError(ValueError):
    """Raised when a source file cannot be safely normalized."""

