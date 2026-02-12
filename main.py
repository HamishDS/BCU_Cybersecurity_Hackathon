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
        print(f"[OK] Loaded {stats['total_logs']} network logs")
        print(f"  Source IPs: {stats['unique_src_ips']} | Dest IPs: {stats['unique_dst_ips']} | Actions: {stats['unique_actions']}")
        print(f"  Time range: {stats['earliest_timestamp']} to {stats['latest_timestamp']}")
        print()
    else:
        print(f"⚠ Data file not found: {sample_file}")
    
    # 2. Detect - Extract alerts
    print("[Step 2] Running Threat Detection Modules...")
    all_alerts = []
    
    if 'logs' in locals() and logs:
        # A. AI Anomaly Detection
        from core.ai_detection import detect_ml_anomalies
        print(f"  [>] Running AI Anomaly Detection on {len(logs)} logs...")
        ai_alerts = detect_ml_anomalies(logs)
        all_alerts.extend(ai_alerts)
        print(f"    - Generated {len(ai_alerts)} AI alerts")
        
        # B. Data Exfiltration Detection
        from core.detect_exfil import detect_data_exfiltration
        print(f"  [>] Running Data Exfiltration Detection...")
        exfil_alerts = detect_data_exfiltration(logs)
        all_alerts.extend(exfil_alerts)
        print(f"    - Generated {len(exfil_alerts)} exfiltration alerts")
        
    else:
        print("WARN: No logs to analyze.")

    print(f"[OK] Total Alerts Generated: {len(all_alerts)}")
    print()
    
    # 3. Correlate - Identify related incidents
    print("[Step 3] Correlating alerts into incidents...")
    incidents = correlate_alerts(all_alerts)
    print(f"[OK] Generated {len(incidents)} correlated incidents")
    print()
    
    # 4. Output - Display results
    print("[Step 4] Incident Summary:")
    for inc in incidents:
        print(f"  Incident {inc.id}: {inc.primary_ip} ({len(inc.alerts)} alerts) - Status: {inc.status}")

if __name__ == "__main__":
    main()
