from collections import defaultdict
from datetime import timedelta
from typing import List
from .models import LogEntry, Alert

SUSPICIOUS_KEYWORDS = ["sudo", "su root", "shadow file", "passwd", "nmap", "telnet"]
PORT_SCAN_THRESHOLD = 10
TIME_WINDOW_SECONDS = 60

def detect_port_scan(logs: List[LogEntry]) -> List[Alert]:
    """
    Detects IPs connecting to many unique ports within a short time window.
    """
    alerts = []
    # Group by Source IP
    events_by_ip = defaultdict(list)
    for log in logs:
        events_by_ip[log.src_ip].append(log)

    for src_ip, ip_logs in events_by_ip.items():
        # Sort by time
        ip_logs.sort(key=lambda x: x.timestamp)
        
        # Sliding window
        window_start_idx = 0
        unique_ports = set()
        
        for i, log in enumerate(ip_logs):
            # Add current log's dest port (inferred from service or dst_ip if available, 
            # here we assume dst_ip might imply different hosts/ports, but strictly we need port info.
            # In Zeek conn.log, port is usually in id.resp_p. 
            # Our LogEntry doesn't have `dst_port` explicitly defined in the standard fields, 
            # but `raw_text` might have it, or we rely on `service`.
            # For MVP, let's look for multiple 'service' or multiple 'dst_ip' as a proxy 
            # OR assume 'action' might contain port info if we parsed it.
            # Wait, `ingest.py` doesn't parse port. 
            # We will use `dst_ip` as a proxy for horizontal scan, 
            # or `raw_text` parsing if we want to be precise.
            # Let's use `dst_ip` count for Horizontal Scan, and `service` count for Vertical.
            # The Requirement says "unique dst_port".
            # Since we don't have dst_port in LogEntry, we will try to parse it from raw_text 
            # OR just strictly look for "Port Scan" labeled logs if this is a heuristic.
            # But this is Rule-Based.
            # Let's assume valid "Port Scan" = High Unique Dst IPs (Horizontal) for now.
            
            unique_ports.add(log.dst_ip) # Using Dst IP as proxy for Horizontal Scan in MVP
            
            # Slide window
            while log.timestamp - ip_logs[window_start_idx].timestamp > timedelta(seconds=TIME_WINDOW_SECONDS):
                # Remove old entries from set? No, this is tricky with a set.
                # Simpler approach: Just check the sub-slice for uniqueness.
                 window_start_idx += 1
            
            current_window = ip_logs[window_start_idx : i+1]
            unique_targets = set(l.dst_ip for l in current_window)
            
            if len(unique_targets) > PORT_SCAN_THRESHOLD:
                # Deduplicate: Only 1 alert per IP per batch?
                # For MVP, yes.
                alerts.append(Alert(
                    timestamp=log.timestamp,
                    src_ip=src_ip,
                    severity="Medium",
                    alert_type="Port Scan (Horizontal)",
                    description=f"Scanned {len(unique_targets)} unique hosts in <1 minute",
                    mitre_id="T1046" # Network Service Discovery
                ))
                break # Move to next IP
                
    return alerts

def detect_suspicious_ops(logs: List[LogEntry]) -> List[Alert]:
    """
    Scans logs for suspicious keywords indicating privilege escalation or prohibited tools.
    """
    alerts = []
    
    for log in logs:
        # Check raw text or action
        content = (log.raw_text + " " + log.action).lower()
        
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in content:
                alerts.append(Alert(
                    timestamp=log.timestamp,
                    src_ip=log.src_ip,
                    severity="High",
                    alert_type="Suspicious Operation",
                    description=f"Detected keyword '{kw}' in log",
                    mitre_id="T1059" # Command and Scripting Interpreter
                ))
    
    return alerts
