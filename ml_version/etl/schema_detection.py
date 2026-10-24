"""Identify supported CSV schemas without assuming file names."""

from __future__ import annotations

from collections.abc import Iterable

from config.dataset_mappings import AUTH_REQUIRED_COLUMNS, NETWORK_REQUIRED_COLUMNS


def detect_dataset_type(columns: Iterable[str]) -> str:
    available = set(columns)
    auth_match = AUTH_REQUIRED_COLUMNS.issubset(available)
    network_match = NETWORK_REQUIRED_COLUMNS.issubset(available)
    if auth_match and not network_match:
        return "authentication"
    if network_match and not auth_match:
        return "network"
    if auth_match and network_match:
        raise ValueError("CSV matches more than one supported schema.")
    auth_missing = sorted(AUTH_REQUIRED_COLUMNS - available)
    network_missing = sorted(NETWORK_REQUIRED_COLUMNS - available)
    raise ValueError(
        "Unsupported CSV schema. Authentication fields missing: "
        f"{', '.join(auth_missing[:6]) or 'none'}; network fields missing: "
        f"{', '.join(network_missing[:6]) or 'none'}."
    )


def safe_source_name(filename: str, dataset_type: str) -> str:
    cleaned = "".join(character if character.isalnum() else "_" for character in filename)
    cleaned = cleaned.strip("_")[:60] or "uploaded_csv"
    return f"uploaded_{dataset_type}:{cleaned.lower()}"

