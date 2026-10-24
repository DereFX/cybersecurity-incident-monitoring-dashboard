"""MongoDB pipelines used by the dashboard."""

from __future__ import annotations

from typing import Any


def events_by_category() -> list[dict[str, Any]]:
    return [
        {"$match": {"attack_category": {"$nin": [None, ""]}}},
        {"$group": {"_id": "$attack_category", "event_count": {"$sum": 1}}},
        {"$sort": {"event_count": -1, "_id": 1}},
    ]


def daily_event_trend() -> list[dict[str, Any]]:
    return [
        {
            "$group": {
                "_id": {
                    "$dateTrunc": {"date": "$timestamp", "unit": "day", "timezone": "UTC"}
                },
                "event_count": {"$sum": 1},
            }
        },
        {"$sort": {"_id": 1}},
    ]


def hourly_event_trend() -> list[dict[str, Any]]:
    return [
        {
            "$group": {
                "_id": {
                    "$dateTrunc": {"date": "$timestamp", "unit": "hour", "timezone": "UTC"}
                },
                "event_count": {"$sum": 1},
            }
        },
        {"$sort": {"_id": 1}},
    ]


def top_source_ips(limit: int = 10) -> list[dict[str, Any]]:
    if limit < 1:
        raise ValueError("limit must be positive")
    return [
        {"$match": {"source_ip": {"$nin": [None, ""]}}},
        {"$group": {"_id": "$source_ip", "event_count": {"$sum": 1}}},
        {"$sort": {"event_count": -1, "_id": 1}},
        {"$limit": limit},
    ]


def failed_logins_by_user(limit: int = 20) -> list[dict[str, Any]]:
    if limit < 1:
        raise ValueError("limit must be positive")
    return [
        {
            "$match": {
                "event_type": "authentication",
                "authentication_result": "failure",
                "user_id": {"$nin": [None, ""]},
            }
        },
        {"$group": {"_id": "$user_id", "failed_logins": {"$sum": 1}}},
        {"$sort": {"failed_logins": -1, "_id": 1}},
        {"$limit": limit},
    ]


def high_severity_alerts_by_rule() -> list[dict[str, Any]]:
    return [
        {"$match": {"severity": {"$in": ["high", "critical"]}}},
        {
            "$group": {
                "_id": "$rule_name",
                "alert_count": {"$sum": 1},
                "latest_alert": {"$max": "$timestamp"},
            }
        },
        {"$sort": {"alert_count": -1, "_id": 1}},
    ]

