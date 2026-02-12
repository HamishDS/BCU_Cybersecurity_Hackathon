from typing import List, Dict
from datetime import timedelta
import uuid
from .models import Alert, Incident

def correlate_alerts(alerts: List[Alert]) -> List[Incident]:
    """
    Groups alerts by Source IP and creates Incidents.
    Logic:
    1. Group by Source IP.
    2. (Optional enhancement) Split by time windows if needed.
    3. Aggregate severity.
    """
    # 1. Bucket by Source IP
    grouped_alerts: Dict[str, List[Alert]] = {}
    for alert in alerts:
        if alert.src_ip not in grouped_alerts:
            grouped_alerts[alert.src_ip] = []
        grouped_alerts[alert.src_ip].append(alert)

    incidents: List[Incident] = []

    # 2. Process each bucket
    for src_ip, ip_alerts in grouped_alerts.items():
        if not ip_alerts:
            continue

        # Sort alerts by timestamp
        ip_alerts.sort(key=lambda x: x.timestamp)
        
        current_batch = []
        
        for alert in ip_alerts:
            if not current_batch:
                current_batch.append(alert)
                continue
            
            # Check time difference with the LAST alert in the current batch
            last_alert = current_batch[-1]
            if alert.timestamp - last_alert.timestamp > timedelta(hours=1):
                # Gap > 1 hour, close current incident and start new one
                incidents.append(_create_incident(src_ip, current_batch))
                current_batch = [alert] # Start new batch
            else:
                current_batch.append(alert)
        
        # Add the final batch
        if current_batch:
            incidents.append(_create_incident(src_ip, current_batch))

    return incidents

def _create_incident(src_ip: str, alerts: List[Alert]) -> Incident:
    """Helper to create an incident from a list of alerts."""
    start_time = alerts[0].timestamp
    end_time = alerts[-1].timestamp
    incident_id = str(uuid.uuid4())[:8]
    
    # Calculate Severity Score
    # Base scores: High=50, Medium=30, Low=10
    # Add 10 per alert, capped at 100
    base_score = 0
    weights = {"High": 50, "Medium": 30, "Low": 10}
    
    # Find max severity
    max_severity_val = 0
    for a in alerts:
        val = weights.get(a.severity, 10)
        if val > max_severity_val:
            max_severity_val = val
            
    # Formula: Max Severity + (Count * 5)
    # e.g., 2 High alerts = 50 + 10 = 60
    # e.g., 10 High alerts = 50 + 50 = 100
    score = max_severity_val + (len(alerts) * 5)
    score = min(score, 100) # Cap at 100
    
    return Incident(
        id=incident_id,
        start_time=start_time,
        end_time=end_time,
        primary_ip=src_ip,
        alerts=alerts,
        status="New",
        severity_score=score
    )

    return incidents
