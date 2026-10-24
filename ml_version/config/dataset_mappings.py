"""Column mappings for the inspected development datasets.

The mappings intentionally keep the two source environments separate. They do
not imply that a user, address, device, or timestamp in one dataset is related
to a value in the other dataset.
"""

from __future__ import annotations

from typing import Final

AUTH_SOURCE_DATASET: Final = "rba_representative_development"
NETWORK_SOURCE_DATASET: Final = "unsw_nb15_representative_development"

AUTH_COLUMN_MAP: Final[dict[str, str]] = {
    "event_id": "event_id",
    "timestamp": "login_timestamp",
    "user_id": "user_id",
    "source_ip": "ip_address",
    "device_id": "device_id",
    "authentication_successful": "login_successful",
    "failure_reason": "failure_reason",
    "observed_attack_ip_label": "is_attack_ip",
    "observed_account_takeover_label": "is_account_takeover",
}

NETWORK_COLUMN_MAP: Final[dict[str, str]] = {
    "source_event_id": "id",
    "timestamp": "event_timestamp",
    "source_ip": "source_ip",
    "destination_ip": "destination_ip",
    "protocol": "proto",
    "service": "service",
    "observed_attack_category": "attack_cat",
    "observed_binary_label": "label",
}

AUTH_REQUIRED_COLUMNS: Final[frozenset[str]] = frozenset(AUTH_COLUMN_MAP.values())
NETWORK_REQUIRED_COLUMNS: Final[frozenset[str]] = frozenset(
    {
        *NETWORK_COLUMN_MAP.values(),
        "dur",
        "spkts",
        "dpkts",
        "sbytes",
        "dbytes",
        "rate",
        "sload",
        "dload",
        "ct_srv_src",
        "ct_dst_ltm",
        "ct_src_ltm",
        "ct_dst_src_ltm",
    }
)

