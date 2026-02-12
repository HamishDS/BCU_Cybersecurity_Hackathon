from datetime import datetime
from core.models import LogEntry, Alert
from core.correlation import correlate_alerts

def main():
    print("Intelligent Threat Detection Platform - MVP")
    
    # 1. Ingest (Mock for now)
    # logs = ingest_logs("data/sample.csv")
    
    # 2. Detect (Mock for now - simulating output from BSc 2 & 3)
    mock_alerts = [
        Alert(timestamp=datetime.now(), src_ip="192.168.1.50", severity="High", alert_type="Brute Force", description="5 failed logins in 1 min"),
        Alert(timestamp=datetime.now(), src_ip="192.168.1.50", severity="Low", alert_type="Port Scan", description="Scanned port 22 and 80"),
        Alert(timestamp=datetime.now(), src_ip="10.0.0.99", severity="Medium", alert_type="Suspicious Ops", description="Sudo used by non-admin"),
    ]
    
    print(f"Received {len(mock_alerts)} alerts from Detection Modules.")
    
    # 3. Correlate
    incidents = correlate_alerts(mock_alerts)
    
    # 4. Output
    print(f"Generated {len(incidents)} Incidents.")
    for inc in incidents:
        print(f"Incident {inc.id}: {inc.primary_ip} ({len(inc.alerts)} alerts) - Status: {inc.status}")

if __name__ == "__main__":
    main()
