"""Loader tests use explicitly synthetic CSV fixtures matching inspected schemas."""

from __future__ import annotations

from io import StringIO

import pandas as pd

from etl.authentication_loader import load_authentication_csv
from etl.network_loader import load_network_csv
from etl.schema_detection import detect_dataset_type
from config.dataset_mappings import AUTH_REQUIRED_COLUMNS, NETWORK_REQUIRED_COLUMNS


def test_authentication_loader_preserves_labels_without_using_them_as_detection(
) -> None:
    csv_buffer = StringIO()
    pd.DataFrame(
        [
            {
                "event_id": "SYN-AUTH-1",
                "login_timestamp": "2026-01-01T00:00:00Z",
                "user_id": "SYN-USER-1",
                "ip_address": "192.0.2.10",
                "country": "ZZ",
                "city": "Synthetic City",
                "device_id": "SYN-DEVICE-1",
                "device_type": "Test Device",
                "os": "Test OS",
                "browser": "Test Browser",
                "login_successful": False,
                "failure_reason": None,
                "is_attack_ip": True,
                "is_account_takeover": False,
            }
        ]
    ).to_csv(csv_buffer, index=False)
    csv_buffer.seek(0)

    event = load_authentication_csv(csv_buffer).events[0]
    assert event.authentication_result == "failure"
    assert event.original_labels["is_attack_ip"] is True
    assert event.event_type == "authentication"


def test_network_loader_keeps_observed_label_separate() -> None:
    csv_buffer = StringIO()
    row = {
        "id": 1,
        "event_timestamp": "2026-01-01T00:00:00Z",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "dur": 0.5,
        "proto": "tcp",
        "service": "http",
        "spkts": 10,
        "dpkts": 8,
        "sbytes": 1000,
        "dbytes": 800,
        "rate": 20.0,
        "sload": 100.0,
        "dload": 80.0,
        "ct_srv_src": 2,
        "ct_dst_ltm": 3,
        "ct_src_ltm": 4,
        "ct_dst_src_ltm": 1,
        "attack_cat": "Normal",
        "label": 0,
    }
    pd.DataFrame([row]).to_csv(csv_buffer, index=False)
    csv_buffer.seek(0)

    event = load_network_csv(csv_buffer).events[0]
    assert event.event_id == "unsw-nb15:1"
    assert event.attack_category == "Normal"
    assert event.original_labels == {"label": 0}
    assert "alert" not in event.to_document()


def test_schema_detection_uses_columns_not_filename() -> None:
    assert detect_dataset_type(AUTH_REQUIRED_COLUMNS) == "authentication"
    assert detect_dataset_type(NETWORK_REQUIRED_COLUMNS) == "network"


def test_schema_detection_rejects_unknown_csv() -> None:
    import pytest

    with pytest.raises(ValueError, match="Unsupported dataset schema"):
        detect_dataset_type({"one", "two"})
