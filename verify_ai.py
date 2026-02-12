from core.ai_detection import detect_ml_anomalies
from core.models import LogEntry
from datetime import datetime

def test_inference():
    print("Testing Benign Log...")
    # Mock Benign Entry (UDP, Short duration, standard ports)
    benign_log = LogEntry(
        timestamp=datetime.now(),
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        action="DNS Query",
        raw_text="",
    )
    # Add extra fields usually found in dict/raw logs but not in dataclass
    # The detector accepts dicts too, or looks for attributes.
    # We will pass a dictionary to ensure all fields are present
    benign_dict = {
        'timestamp': datetime.now(),
        'src_ip': "192.168.1.100",
        'proto': 'udp',
        'service': 'dns',
        'conn_state': 'SF',
        'duration': 0.05,
        'orig_bytes': 60,
        'resp_bytes': 100,
        'orig_pkts': 1,
        'resp_pkts': 1
    }
    
    alerts = detect_ml_anomalies([benign_dict])
    print(f"Benign Alerts: {len(alerts)}")
    for a in alerts:
        print(a)

    print("\nTesting Malicious Log (C&C Pattern)...")
    # Mock Malicious (Long TCP connection, C&C characteristics inferred from training data)
    # Based on training data: proto=tcp, conn_state=S0, duration=~3.0, orig_bytes=0
    malicious_dict = {
        'timestamp': datetime.now(),
        'src_ip': "192.168.100.113", # Known bad IP from dataset
        'proto': 'tcp',
        'service': '-',
        'conn_state': 'S0',
        'duration': 3.15,
        'orig_bytes': 0,
        'resp_bytes': 0,
        'orig_pkts': 3,
        'resp_pkts': 0
    }
    
    alerts = detect_ml_anomalies([malicious_dict])
    print(f"Malicious Alerts: {len(alerts)}")
    for a in alerts:
        print(f"  - {a.alert_type}: {a.description}")

if __name__ == "__main__":
    test_inference()
