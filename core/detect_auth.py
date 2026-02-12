from __future__ import annotations

from collections import defaultdict, deque   #dictionary that auto-creates empty list and deque is just a faster queue ammend & pop 
from dataclasses import asdict, is_dataclass #converts data class objects into dictionaries
from datetime import datetime, timedelta     #used for timestamps n time windows
from typing import Any                       #this is used to basically say that this variable can be any type


FAILED_LOGIN_MARKERS = ("fail", "failed", "invalid", "denied", "unauthor")
AUTH_EVENT_MARKERS = ("login", "logon", "auth")
WINDOW_SECONDS = 60 # a value that is going to run iterably through the loop
THRESHOLD = 5  # a variable i initialised for the total number of attempts


def detect_brute_force(logs: list[Any]) -> list[dict[str, Any]]:
    
    #the goal with this is that it will scan login/auth logs and then it will riase a high severity "brute force"    
    #it will doe this when one IP will have more than five failed login wihtin 60 seconfs.
    #this will also input a list of logs and then putput a list of alerts

    failed_by_ip: dict[str, list[tuple[datetime, dict[str, Any]]]] = defaultdict(list)
    #this "failed_by_ip" will keep a list of failed events an example output of this should be when we test 
    
    #{
    #"192.168.1.10": [(timestamp, log), (timestamp, log)]
    #} this is an example of hwo it should be


    for raw in logs:
        log = _to_dict(raw)
        if not _is_failed_auth_event(log):
            continue
        # this basically just says that if this isnt a failed login event just continue on 

        source_ip = _pick(log, "sourceAddress", "src_ip", "source_ip", "ip", "source")
        timestamp = _parse_timestamp(_pick(log, "timestamp", "time", "ts", "eventTime"))
        if not source_ip or not timestamp:
            continue
        # if it is missing it will just move on

        failed_by_ip[str(source_ip)].append((timestamp, log))

        # this stores failure under that ip


    # the above loop will inspect each loop and then convert logs into a dictionary format as logs could be
    # a dict a data class or even an object

    alerts: list[dict[str, Any]] = []

    # the following loop will check each ip separately

    for source_ip, events in failed_by_ip.items():
        events.sort(key=lambda item: item[0])
        window: deque[tuple[datetime, dict[str, Any]]] = deque()

        #^^ sorts by timestamp and a window that will hold the recent failures 

        for timestamp, log in events:
            window.append((timestamp, log)) # will aadd the latest failure
            window_start_cutoff = timestamp - timedelta(seconds=WINDOW_SECONDS)     # this will check the timestamp
            while window and window[0][0] < window_start_cutoff:                    
                window.popleft()                                    # this will make it so that it will only check failures in the last minute


            if len(window) > THRESHOLD:                             # this is the main logic behind which it will create the alert
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
                # what this will do is that it will record the type, severity, source ip,
                # event count, start & end time, MITRE technique, description
                # and will reset window to avoid duplicate alerts for the same burst

                window.clear()  # this will prevent duplicated alerts

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
    # this will see whether the event looks like a login/auth event

    failed_like = any(marker in result for marker in FAILED_LOGIN_MARKERS)
    # this will check whether it was a failure or not

    # Some datasets encode failure in the event/action field 
    failed_in_action = any(marker in event_type for marker in FAILED_LOGIN_MARKERS)
    return (auth_like and failed_like) or failed_in_action