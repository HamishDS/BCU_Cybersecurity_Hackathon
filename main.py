from datetime import datetime
from pathlib import Path
from core.models import LogEntry, Alert
from core.correlation import correlate_alerts
from core.ingest import load_logs, validate_data

def main():
    print("Intelligent Threat Detection Platform - MVP")
    print()
    
    # 1. Ingest - Load network logs from CTU dataset
    data_dir = Path("data")
    sample_file = data_dir / "CTU-IoT-Malware-Capture-20-1conn.log.labeled.csv"
    
    if sample_file.exists():
        print(f"[Step 1] Loading network logs from {sample_file.name}...")
        logs = load_logs(sample_file)
        stats = validate_data(logs)
        print(f"✓ Loaded {stats['total_logs']} network logs")
        print(f"  Source IPs: {stats['unique_src_ips']} | Dest IPs: {stats['unique_dst_ips']} | Actions: {stats['unique_actions']}")
        print(f"  Time range: {stats['earliest_timestamp']} to {stats['latest_timestamp']}")
        print()
    else:
        print(f"⚠ Data file not found: {sample_file}")
    
    # 2. Detect - Extract alerts (Mock simulation of detection modules output)
    print("[Step 2] Simulating threat detection modules...")
    mock_alerts = [
        Alert(timestamp=datetime.now(), src_ip="192.168.1.50", severity="High", alert_type="Brute Force", description="5 failed logins in 1 min"),
        Alert(timestamp=datetime.now(), src_ip="192.168.1.50", severity="Low", alert_type="Port Scan", description="Scanned port 22 and 80"),
        Alert(timestamp=datetime.now(), src_ip="10.0.0.99", severity="Medium", alert_type="Suspicious Ops", description="Sudo used by non-admin"),
    ]
    print(f"✓ Generated {len(mock_alerts)} alerts from detection modules")
    print()
    
    # 3. Correlate - Identify related incidents
    print("[Step 3] Correlating alerts into incidents...")
    incidents = correlate_alerts(mock_alerts)
    print(f"✓ Generated {len(incidents)} correlated incidents")
    print()
    
    # 4. Output - Display results
    print("[Step 4] Incident Summary:")
    for inc in incidents:
        print(f"  Incident {inc.id}: {inc.primary_ip} ({len(inc.alerts)} alerts) - Status: {inc.status}")

if __name__ == "__main__":
    main()
