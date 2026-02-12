"""
Data Ingestion Module

Handles reading network logs from CSV/JSON files, normalizing data,
and converting them to standard LogEntry objects.
"""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Union
from core.models import LogEntry


def load_logs(filepath: Union[str, Path]) -> List[LogEntry]:
    """
    Load and parse network logs from a CSV or JSON file.
    
    Supports:
    - Zeek/Bro conn.log format (pipe-delimited CSV)
    - Generic JSON network logs
    
    Args:
        filepath: Path to the data file (CSV or JSON)
        
    Returns:
        List of normalized LogEntry objects
        
    Raises:
        FileNotFoundError: If file does not exist
        ValueError: If file format is unsupported or data is malformed
    """
    filepath = Path(filepath)
    
    if not filepath.exists():
        raise FileNotFoundError(f"Data file not found: {filepath}")
    
    if filepath.suffix.lower() == ".csv":
        return _load_csv(filepath)
    elif filepath.suffix.lower() == ".json":
        return _load_json(filepath)
    else:
        raise ValueError(f"Unsupported file format: {filepath.suffix}. Use .csv or .json")


def _load_csv(filepath: Path) -> List[LogEntry]:
    """
    Load logs from a pipe-delimited CSV file (Zeek conn.log format).
    
    CSV Format (Zeek conn.log):
    - Delimiter: pipe (|)
    - Timestamp: epoch seconds (column: ts)
    - Source IP: id.orig_h
    - Destination IP: id.resp_h
    - Connection state: conn_state
    - Label: label or detailed-label
    """
    logs = []
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f, delimiter="|")
            
            if reader.fieldnames is None:
                raise ValueError("CSV file is empty or has no headers")
            
            for row_num, row in enumerate(reader, start=2):  # start=2 because header is row 1
                try:
                    log_entry = _parse_zeek_row(row, filepath.name)
                    if log_entry:
                        logs.append(log_entry)
                except (ValueError, KeyError) as e:
                    print(f"Warning: Skipping malformed row {row_num} in {filepath.name}: {e}")
                    continue
    
    except Exception as e:
        raise ValueError(f"Error reading CSV file {filepath}: {e}")
    
    return logs


def _load_json(filepath: Path) -> List[LogEntry]:
    """
    Load logs from a JSON file.
    
    Expected JSON structure (array of objects or single object):
    [
        {
            "timestamp": 1234567890 or "2023-01-01T12:00:00Z",
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.2",
            "action": "Connection",
            ...
        }
    ]
    """
    logs = []
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # Handle both single object and array of objects
        records = data if isinstance(data, list) else [data]
        
        for row_num, record in enumerate(records, start=1):
            try:
                log_entry = _parse_json_record(record)
                if log_entry:
                    logs.append(log_entry)
            except (ValueError, KeyError, TypeError) as e:
                print(f"Warning: Skipping malformed record {row_num} in {filepath.name}: {e}")
                continue
    
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in file {filepath}: {e}")
    except Exception as e:
        raise ValueError(f"Error reading JSON file {filepath}: {e}")
    
    return logs


def _parse_zeek_row(row: dict, source_file: str) -> Union[LogEntry, None]:
    """
    Parse a single row from Zeek conn.log CSV.
    
    Maps Zeek fields to LogEntry model:
    - ts → timestamp (convert from epoch seconds to datetime)
    - id.orig_h → src_ip
    - id.resp_h → dst_ip
    - conn_state / label → action
    """
    # Extract required fields
    ts_str = row.get("ts", "").strip()
    src_ip = row.get("id.orig_h", "").strip()
    dst_ip = row.get("id.resp_h", "").strip()
    conn_state = row.get("conn_state", "").strip()
    label = row.get("label", "").strip()
    detailed_label = row.get("detailed-label", "").strip()
    
    # Validate required fields
    if not ts_str or not src_ip or not dst_ip:
        raise ValueError(f"Missing required fields: ts={ts_str}, src_ip={src_ip}, dst_ip={dst_ip}")
    
    # Parse timestamp
    try:
        timestamp = _parse_timestamp(ts_str)
    except ValueError as e:
        raise ValueError(f"Invalid timestamp '{ts_str}': {e}")
    
    # Determine action from available fields
    action = _determine_action(conn_state, label, detailed_label)
    
    # Build raw text from the entire row (for audit trail)
    raw_text = "|".join([f"{k}={v}" for k, v in row.items()])
    
    return LogEntry(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        action=action,
        raw_text=raw_text
    )


def _parse_json_record(record: dict) -> Union[LogEntry, None]:
    """
    Parse a JSON record with flexible key naming.
    
    Accepts various key names:
    - timestamp, ts, time
    - src_ip, source_ip, source_address, sourceAddress
    - dst_ip, dest_ip, destination_ip, destinationAddress
    - action, event_type, conn_state
    """
    # Helper function to find a key among alternatives
    def get_field(record, *keys):
        for key in keys:
            if key in record and record[key]:
                return str(record[key]).strip()
        return None
    
    # Extract fields with fallbacks
    ts_value = get_field(record, "timestamp", "ts", "time")
    src_ip = get_field(record, "src_ip", "source_ip", "source_address", "sourceAddress")
    dst_ip = get_field(record, "dst_ip", "dest_ip", "destination_ip", "destinationAddress")
    action = get_field(record, "action", "event_type", "conn_state", "event")
    
    # Validate required fields
    if not ts_value or not src_ip or not dst_ip:
        raise ValueError(f"Missing required fields in JSON record: timestamp={ts_value}, src_ip={src_ip}, dst_ip={dst_ip}")
    
    # Parse timestamp
    try:
        timestamp = _parse_timestamp(ts_value)
    except ValueError as e:
        raise ValueError(f"Invalid timestamp '{ts_value}': {e}")
    
    # Default action if not provided
    if not action:
        action = "Network Event"
    
    # Build raw text
    raw_text = json.dumps(record)
    
    return LogEntry(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        action=action,
        raw_text=raw_text
    )


def _parse_timestamp(ts_value: str) -> datetime:
    """
    Parse timestamp from various formats.
    
    Supports:
    - Epoch seconds (float or int): 1234567890, 1234567890.123456
    - ISO 8601: 2023-01-01T12:00:00Z
    - Common formats: YYYY-MM-DD HH:MM:SS
    
    Args:
        ts_value: Timestamp string to parse
        
    Returns:
        datetime object
        
    Raises:
        ValueError: If timestamp format is unrecognized
    """
    ts_value = str(ts_value).strip()
    
    # Try to parse as epoch seconds (float or int)
    try:
        epoch = float(ts_value)
        return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None)
    except (ValueError, OSError):
        pass
    
    # Try common ISO 8601 format
    iso_formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]
    
    for fmt in iso_formats:
        try:
            return datetime.strptime(ts_value, fmt)
        except ValueError:
            continue
    
    raise ValueError(f"Unable to parse timestamp: {ts_value}")


def _determine_action(conn_state: str, label: str, detailed_label: str) -> str:
    """
    Determine the action/event type from available fields.
    
    Priority: detailed_label > label > conn_state
    
    Args:
        conn_state: Zeek connection state (S0, S1, SF, RSTO, etc.)
        label: High-level label (Benign, Malicious)
        detailed_label: Detailed label (malware family, etc.)
        
    Returns:
        Action string for the log entry
    """
    # Return most detailed information available
    if detailed_label and detailed_label != "-":
        return detailed_label
    
    if label and label != "-":
        return label
    
    if conn_state and conn_state != "-":
        return f"Connection:{conn_state}"
    
    return "Unknown"


def validate_data(logs: List[LogEntry]) -> dict:
    """
    Validate and provide statistics about loaded logs.
    
    Args:
        logs: List of LogEntry objects
        
    Returns:
        Dictionary with validation statistics
    """
    stats = {
        "total_logs": len(logs),
        "unique_src_ips": len(set(log.src_ip for log in logs)),
        "unique_dst_ips": len(set(log.dst_ip for log in logs)),
        "unique_actions": len(set(log.action for log in logs)),
        "earliest_timestamp": min((log.timestamp for log in logs), default=None),
        "latest_timestamp": max((log.timestamp for log in logs), default=None),
    }
    
    return stats


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ingest.py <filepath>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    try:
        logs = load_logs(filepath)
        stats = validate_data(logs)
        
        print(f"Successfully loaded {stats['total_logs']} logs from {filepath}")
        print(f"Unique source IPs: {stats['unique_src_ips']}")
        print(f"Unique destination IPs: {stats['unique_dst_ips']}")
        print(f"Unique actions: {stats['unique_actions']}")
        print(f"Time range: {stats['earliest_timestamp']} to {stats['latest_timestamp']}")
        
        # Display first 3 logs
        print("\nFirst 3 logs:")
        for i, log in enumerate(logs[:3], 1):
            print(f"{i}. {log.timestamp} | {log.src_ip} → {log.dst_ip} | {log.action}")
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
