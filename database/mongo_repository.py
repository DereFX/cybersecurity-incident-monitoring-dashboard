"""Idempotent MongoDB persistence for events and generated alerts."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from pymongo import UpdateOne
from pymongo.collection import Collection

from detection.models import DetectionAlert
from etl.models import NormalizedEvent


@dataclass(frozen=True, slots=True)
class BatchWriteSummary:
    received: int
    inserted: int
    duplicates: int


class SecurityEventRepository:
    def __init__(self, events: Collection, alerts: Collection) -> None:
        self.events = events
        self.alerts = alerts

    def store_events(self, events: Iterable[NormalizedEvent]) -> BatchWriteSummary:
        documents = [event.to_document() for event in events]
        if not documents:
            return BatchWriteSummary(received=0, inserted=0, duplicates=0)
        operations = [
            UpdateOne(
                {"event_id": document["event_id"]},
                {"$setOnInsert": document},
                upsert=True,
            )
            for document in documents
        ]
        result = self.events.bulk_write(operations, ordered=False)
        inserted = len(result.upserted_ids)
        return BatchWriteSummary(
            received=len(documents), inserted=inserted, duplicates=len(documents) - inserted
        )

    def store_alerts(self, alerts: Iterable[DetectionAlert]) -> BatchWriteSummary:
        documents = [alert.to_document() for alert in alerts]
        if not documents:
            return BatchWriteSummary(received=0, inserted=0, duplicates=0)
        operations = [
            UpdateOne(
                {"detection_key": document["detection_key"]},
                {"$setOnInsert": document},
                upsert=True,
            )
            for document in documents
        ]
        result = self.alerts.bulk_write(operations, ordered=False)
        inserted = len(result.upserted_ids)
        return BatchWriteSummary(
            received=len(documents), inserted=inserted, duplicates=len(documents) - inserted
        )

    def list_events(
        self,
        *,
        query: dict | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict]:
        if page < 1 or not 1 <= page_size <= 1_000:
            raise ValueError("page must be positive and page_size must be 1-1000")
        return list(
            self.events.find(query or {}, {"raw_event": 0})
            .sort("timestamp", -1)
            .skip((page - 1) * page_size)
            .limit(page_size)
        )

