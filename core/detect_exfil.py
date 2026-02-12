from typing import List
from .models import LogEntry, Alert

# Threshold: 50 MB in bytes
EXFIL_THRESHOLD_BYTES = 50 * 1024 * 1024 

def detect_data_exfiltration(logs: List[LogEntry]) -> List[Alert]:
    """
    Scans logs for connections with unusually high data transfer (outbound).
    """
    alerts = []
    
    for log in logs:
        # Check if response bytes (server to client) helps identify exfil
        # In this dataset, if 'src_ip' is internal and 'dst_ip' is external, 
        # 'orig_bytes' is upload. 
        # However, usually we look for large transfers regardless of direction in a simplified MVP.
        # We will flag any single connection > Threshold.
        
        # Check total flow volume (orig + resp) or just large outbound? 
        # Using resp_bytes as primary indicator for download, orig_bytes for upload.
        # We'll sum them to catch large transfers.
        
        total_bytes = log.orig_bytes + log.resp_bytes
        
        if total_bytes > EXFIL_THRESHOLD_BYTES:
            
            # Determine direction description (simplified)
            # Assuming 192.168.x.x is internal
            direction = "Internal-to-External" if log.src_ip.startswith("192.168.") and not log.dst_ip.startswith("192.168.") else "Traffic"
            
            alert = Alert(
                timestamp=log.timestamp,
                src_ip=log.src_ip,
                severity="High",
                alert_type="Data Exfiltration",
                description=f"Large Data Transfer detected: {total_bytes / (1024*1024):.2f} MB ({direction}) to {log.dst_ip}"
            )
            alerts.append(alert)
            
    return alerts
