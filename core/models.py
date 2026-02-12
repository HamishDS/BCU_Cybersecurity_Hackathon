from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

@dataclass
class LogEntry:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    action: str  # e.g., "Failed Login", "Connection-Attempt"
    raw_text: str

@dataclass
class Alert:
    timestamp: datetime
    src_ip: str
    severity: str  # "Low", "Medium", "High"
    alert_type: str  # e.g., "Brute Force", "Port Scan"
    description: str

@dataclass
class Incident:
    id: str
    start_time: datetime
    end_time: datetime
    primary_ip: str  # The attacker
    alerts: List[Alert]
    status: str = "New"  # "New", "Investigating"
