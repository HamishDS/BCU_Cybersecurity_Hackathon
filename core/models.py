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
    # Extended fields for Analysis
    proto: str = "unknown"
    service: str = "other"
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0

@dataclass
class Alert:
    timestamp: datetime
    src_ip: str
    severity: str  # "Low", "Medium", "High"
    alert_type: str  # e.g., "Brute Force", "Port Scan"
    description: str
    mitre_id: str = "T1000"  # Default to 'Technique' generic

@dataclass
class Incident:
    id: str
    start_time: datetime
    end_time: datetime
    primary_ip: str  # The attacker
    alerts: List[Alert]
    status: str = "New"  # "New", "Investigating"
    severity_score: int = 0  # 0-100 score
