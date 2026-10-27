"""Explicitly synthetic, schema-valid authentication data for a guided demo."""

from datetime import datetime, timedelta, timezone

import pandas as pd


def authentication_demo_csv(run_id: str, start: datetime | None = None) -> bytes:
    start = start or datetime.now(timezone.utc).replace(second=0, microsecond=0)
    records = []
    groups = [("BRUTE", 5, False, 0), ("MULTI", 3, True, 10), ("CONTROL", 4, False, 20)]
    for group, count, successful, offset in groups:
        for index in range(count):
            records.append({
                "event_id": f"SYN-{run_id}-{group}-{index + 1}",
                "login_timestamp": (start + timedelta(minutes=offset + index)).isoformat(),
                "user_id": f"SYN-{run_id}-{group}",
                "ip_address": f"192.0.2.{index + 20 if group == 'MULTI' else 10}",
                "device_id": f"SYN-DEVICE-{index + 1 if group == 'MULTI' else 1}",
                "login_successful": successful,
                "failure_reason": "" if successful else "Synthetic invalid password",
                "is_attack_ip": False,
                "is_account_takeover": False,
                "data_origin": "SYNTHETIC DEMONSTRATION ONLY",
            })
    return pd.DataFrame(records).to_csv(index=False).encode("utf-8")
