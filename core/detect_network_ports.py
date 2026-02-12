"""Network / pattern-based detection logic (BSc Student 3 - Detection Logic B: Network).

This module focuses on detecting network-level attacks from Zeek-style conn.log
network flow data. The primary implemented detector is a basic port-scan
indicator: one IP hitting many distinct ports within a short time window.

Key concepts
------------
- Input: an *iterator* of parsed network connection records (NetworkConnection).
- Output: a list of Alert objects (from core.models) describing suspicious
  activity.
- Implementation: streaming-friendly sliding-window algorithm that only keeps
  recent activity per source IP in memory, so it can operate on very large
  (GB-sized) log files.

This is the responsibility area for:
BSc Student 3 (Detection Logic B: Network) - Adam
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Deque, Iterable, Iterator, List, Mapping, Optional, Tuple
import csv
from collections import defaultdict, deque

from core.models import Alert


# ------------------------- Data model for network flows -------------------------

@dataclass
class NetworkConnection:
    """Minimal representation of a Zeek conn.log network flow.

    Fields are intentionally kept small and focused on what the port-scan
    detection needs. Additional attributes can be added later if other
    detectors require them.
    """

    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    label: Optional[str] = None  # From CTU dataset; not used in detection


# --------------------------- CSV parsing helpers ---------------------------

CONN_REQUIRED_FIELDS = ["ts", "id.orig_h", "id.resp_h", "id.resp_p", "proto"]


def parse_conn_row(row: Mapping[str, str]) -> Optional[NetworkConnection]:
    """Parse a Zeek conn.log CSV row into a NetworkConnection.

    Returns None if required fields are missing or malformed.

    Expected columns (Zeek conn.log style):
    - ts: epoch seconds (float or int)
    - id.orig_h: source IP
    - id.resp_h: destination IP
    - id.resp_p: destination port (int)
    - proto: transport protocol (tcp/udp/icmp)
    - label: optional high-level label (Benign/Malicious)
    """

    for field in CONN_REQUIRED_FIELDS:
        if field not in row or row[field] in ("", "-"):
            return None

    try:
        ts_raw = float(row["ts"])
        # CTU datasets typically use epoch seconds
        ts = datetime.fromtimestamp(ts_raw)
    except (TypeError, ValueError, OSError):
        return None

    src_ip = row["id.orig_h"].strip()
    dst_ip = row["id.resp_h"].strip()

    try:
        dst_port = int(row["id.resp_p"])
    except (TypeError, ValueError):
        return None

    proto = row.get("proto", "").strip() or "?"
    label = row.get("label") or None

    if not src_ip or not dst_ip or dst_port <= 0:
        return None

    return NetworkConnection(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto,
        label=label,
    )


def iter_conn_csv(path: str, *, encoding: str = "utf-8") -> Iterator[NetworkConnection]:
    """Stream NetworkConnection objects from a Zeek conn.log CSV file.

    This function is *streaming-friendly*: it yields one record at a time and
    never loads the entire file into memory, so it can be used with very large
    datasets (e.g., multi-GB logs).
    """

    with open(path, "r", encoding=encoding, newline="") as f:
        # Skip Zeek-style comment lines starting with '#', if present.
        # Some CTU CSVs may already be clean and have a single header row.
        # We'll detect the header row dynamically.
        # Read a small buffer to find the header.
        first_line = f.readline()
        while first_line and first_line.lstrip().startswith("#"):
            first_line = f.readline()

        if not first_line:
            return

        # Use DictReader starting from the header line we just found.
        header = first_line.rstrip("\n")
        # Create a new iterator that yields the header then the remaining lines
        def line_iter() -> Iterator[str]:
            yield header + "\n"
            for line in f:
                yield line

        reader = csv.DictReader(line_iter())
        for row in reader:
            conn = parse_conn_row(row)
            if conn is not None:
                yield conn


# ------------------------- Port scan detection logic -------------------------

@dataclass
class _SrcIPState:
    """Internal sliding-window state for a single source IP."""

    # Deque of (timestamp, dst_ip, dst_port)
    events: Deque[Tuple[datetime, str, int]]
    # Set of distinct destination ports seen in the current window
    distinct_ports: Dict[int, int]  # port -> refcount in events
    # Whether we're currently above threshold (to avoid duplicate alerts)
    in_scan_episode: bool = False


def detect_port_scan(
    logs: Iterable[NetworkConnection],
    *,
    # Smaller window focuses on fast/aggressive scans
    window_seconds: int = 120,
    # Make defaults more restrictive: require more distinct ports to alert
    min_distinct_ports: int = 5,
    # Ports above this count are considered very noisy / high severity
    high_severity_threshold: int = 100,
) -> List[Alert]:
    """Detect basic port-scanning behavior from a stream of connections.

    A simple heuristic: if a source IP contacts *many* distinct destination
    ports within a short time window, we raise a Port Scan alert.

    The default thresholds here are intentionally **restrictive** so that
    only very noisy / clear scanning behavior is flagged:

    - window_seconds = 60: only bursts within 1 minute are considered.
    - min_distinct_ports = 50: at least 50 distinct ports in that minute.
    - high_severity_threshold = 100: 100+ distinct ports in the minute is
      treated as a "High" severity scan.

    You can override these values when calling this function if you need a
    more sensitive detector for a different environment.
    """

    alerts: List[Alert] = []

    per_ip_state: Dict[str, _SrcIPState] = defaultdict(
        lambda: _SrcIPState(events=deque(), distinct_ports={})
    )

    window_delta = timedelta(seconds=window_seconds)

    for conn in logs:
        src = conn.src_ip
        state = per_ip_state[src]
        now = conn.timestamp

        # Append new event
        state.events.append((conn.timestamp, conn.dst_ip, conn.dst_port))
        state.distinct_ports[conn.dst_port] = state.distinct_ports.get(conn.dst_port, 0) + 1

        # Evict old events outside the sliding window
        cutoff = now - window_delta
        while state.events and state.events[0][0] < cutoff:
            old_ts, _old_dst_ip, old_dst_port = state.events.popleft()
            # Decrement refcount for this port
            if old_dst_port in state.distinct_ports:
                state.distinct_ports[old_dst_port] -= 1
                if state.distinct_ports[old_dst_port] <= 0:
                    del state.distinct_ports[old_dst_port]

        distinct_port_count = len(state.distinct_ports)

        # Determine if we should trigger a new episode alert
        if distinct_port_count >= min_distinct_ports and not state.in_scan_episode:
            # Start of a new scanning episode for this IP
            state.in_scan_episode = True

            severity = "High" if distinct_port_count >= high_severity_threshold else "Medium"

            # The window start is approximated as the timestamp of the oldest
            # event still in the deque for this source.
            window_start = state.events[0][0] if state.events else now
            window_end = now

            description = (
                f"Port scan detected: {src} contacted {distinct_port_count} distinct "
                f"ports in approximately {int((window_end - window_start).total_seconds())}s "
                f"(from {window_start.isoformat()} to {window_end.isoformat()})."
            )

            alerts.append(
                Alert(
                    timestamp=now,
                    src_ip=src,
                    severity=severity,
                    alert_type="Port Scan",
                    description=description,
                )
            )

        # If activity has dropped below threshold, mark episode as ended so a
        # future spike can generate a new alert.
        if distinct_port_count < min_distinct_ports and state.in_scan_episode:
            state.in_scan_episode = False

        # Optional cleanup: if state has no events and we're not in an episode,
        # we could delete the IP from the dict to bound memory further. For now
        # we keep it simple; the per-IP structures are small.

    return alerts


def run_network_detections_from_csv(
    path: str,
    *,
    window_seconds: int = 60,
    min_distinct_ports: int = 5,
    high_severity_threshold: int = 100,
) -> List[Alert]:
    """High-level helper to run network detections on a conn.log CSV file.

    The parameters are passed straight through to :func:`detect_port_scan` and
    inherit its **restrictive** defaults.
    """

    logs = iter_conn_csv(path)
    port_scan_alerts = detect_port_scan(
        logs,
        window_seconds=window_seconds,
        min_distinct_ports=min_distinct_ports,
        high_severity_threshold=high_severity_threshold,
    )
    return port_scan_alerts

