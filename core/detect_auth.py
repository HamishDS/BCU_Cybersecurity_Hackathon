from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta
from typing import Any


FAILED_LOGIN_MARKERS = ("fail", "failed", "invalid", "denied", "unauthor")
AUTH_EVENT_MARKERS = ("login", "logon", "auth")
WINDOW_SECONDS = 60 # a value that is going to run iterably through the loop
THRESHOLD = 5  # a variable i initialised for the total number of attempts


def detect_brute_force(logs: list[Any]) -> list[dict[str, Any]]:
    
    #the goal with this is that it will scan login/auth logs and then it will riase a high severity "brute force"    
    #it will doe this when one IP will have more than five failed login wihtin 60 seconfs.
    failed_by_ip: dict[str, list[tuple[datetime, dict[str, Any]]]] = defaultdict(list)

    for raw in logs:
        log = _to_dict(raw)
        if not _is_failed_auth_event(log):
            continue

        source_ip = _pick(log, "sourceAddress", "src_ip", "source_ip", "ip", "source")
        timestamp = _parse_timestamp(_pick(log, "timestamp", "time", "ts", "eventTime"))
        if not source_ip or not timestamp:
            continue

        failed_by_ip[str(source_ip)].append((timestamp, log))

    alerts: list[dict[str, Any]] = []
    for source_ip, events in failed_by_ip.items():
        events.sort(key=lambda item: item[0])
        window: deque[tuple[datetime, dict[str, Any]]] = deque()

        for timestamp, log in events:
            window.append((timestamp, log))
            window_start_cutoff = timestamp - timedelta(seconds=WINDOW_SECONDS)
            while window and window[0][0] < window_start_cutoff:
                window.popleft()

            if len(window) > THRESHOLD:
                start_time = window[0][0]
                end_time = window[-1][0]
                alerts.append(
                    {
                        "type": "Brute Force",
                        "severity": "High",
                        "sourceAddress": source_ip,
                        "eventCount": len(window),
                        "startTime": start_time.isoformat(),
                        "endTime": end_time.isoformat(),
                        "technique": "MITRE ATT&CK T1110 - Brute Force",
                        "description": (
                            f"{len(window)} failed login attempts from {source_ip} "
                            f"within 1 minute."
                        ),
                    }
                )
                # Reset window to avoid duplicate alerts for the same burst.
                window.clear()

    return alerts


def _to_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return item
    if is_dataclass(item):
        return asdict(item)
    return vars(item) if hasattr(item, "__dict__") else {}


def _pick(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    return None


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None

    ts = value.strip()
    if not ts:
        return None

    # Handle ISO-8601 timestamps with trailing Z.
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"

    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _is_failed_auth_event(log: dict[str, Any]) -> bool:
    event_type = str(_pick(log, "eventType", "event_type", "action", "activity", "category") or "").lower()
    result = str(_pick(log, "result", "status", "outcome", "auth_result", "message") or "").lower()

    auth_like = any(marker in event_type for marker in AUTH_EVENT_MARKERS)
    failed_like = any(marker in result for marker in FAILED_LOGIN_MARKERS)

    # Some datasets encode failure in the event/action field.
    failed_in_action = any(marker in event_type for marker in FAILED_LOGIN_MARKERS)
    return (auth_like and failed_like) or failed_in_action