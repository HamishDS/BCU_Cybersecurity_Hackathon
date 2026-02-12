# Task 1: detailed Implementation Plan - Correlation Engine & Architecture

**Assignee:** Hamish (MSc Lead)
**Goal:** Build the "Brain" of the system that structures data and groups simplified alerts into meaningful incidents.

## 1. Project Structure & Core Models
Before writing logic, the shared data structures must be defined so other teams (Ingestion, Detection) know what to output.

### 1.1 Define Data Classes (`core/models.py`)
Create a file to hold the standard schemas.
*   **`LogEntry`**: Represents a single raw log line.
    *   `timestamp`: datetime
    *   `src_ip`: str
    *   `dst_ip`: str
    *   `action`: str (e.g., "Failed Login", "Connection-Attempt")
    *   `raw_text`: str (original line)
*   **`Alert`**: The output of Detection Logic (Students 2 & 3).
    *   `timestamp`: datetime
    *   `src_ip`: str
    *   `severity`: str ("Low", "Medium", "High")
    *   `alert_type`: str (e.g., "Brute Force", "Port Scan")
    *   `description`: str
*   **`Incident`**: The output of this Task 1 (Correlation).
    *   `id`: unique_id
    *   `start_time`: datetime
    *   `end_time`: datetime
    *   `primary_ip`: str (The attacker)
    *   `alerts`: List[Alert] (All nested alerts)
    *   `status`: str ("New", "Investigating")

## 2. Correlation Engine Logic (`core/correlation.py`)
The core function `correlate_alerts(alerts: List[Alert]) -> List[Incident]` needs to group scattered alerts.

### 2.1 Grouping Strategy
*   **By Source IP**: The primary key for grouping.
*   **Time Window**: (Optional for MVP, but good for "Intelligent" part) Group alerts from the same IP that occur within a 5-minute rolling window.
*   **Severity Aggregation**: 
    *   If an IP has > 3 Low severity alerts -> Create Medium Incident.
    *   If an IP has > 1 High severity alert -> Create High Incident.

### 2.2 detailed Workflow
1.  **Input**: Receive a list of 50 mixed `Alert` objects.
2.  **Sort**: Sort by timestamp.
3.  **Bucket**: efficient dictionary mapping `{src_ip: [List of Alerts]}`.
4.  **Analyze Buckets**:
    *   Iterate through each IP's list.
    *   Create an `Incident` object for that IP.
    *   Calculate start/end times based on the first/last alert.
5.  **Output**: Return list of `Incident` objects.

## 3. Integration & merging (Main Loop)
As Team Lead, this task also involves writing the `main.py` driver script.
*   **Step 1**: Call Ingestion (Student 1) -> get `logs`.
*   **Step 2**: specific calls to Detection Modules (Students 2 & 3).
    *   `alerts_A = detect_auth(logs)`
    *   `alerts_B = detect_network(logs)`
*   **Step 3**: Combine `alerts_total = alerts_A + alerts_B`.
*   **Step 4**: Call `correlate_alerts(alerts_total)`.
*   **Step 5**: Pass result to UI or save to JSON for frontend to read.

## 4. Immediate Todo List
- [ ] Create folder `core/` and file `core/models.py` with dataclasses.
- [ ] Create `core/correlation.py` with the `correlate_alerts` stub.
- [ ] Write unit test `tests/test_correlation.py` with dummy data to prove grouping works.
