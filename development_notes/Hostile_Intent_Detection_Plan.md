# Hostile Intent Detection Plan

**Goal:** Identify malicious actors based on their behavior patterns using two specialized detection modules.

## 1. Authentication Anomaly Detection (Brute Force)
**Schedule ID:** Task 3 (BSc Student 2)
**Assignee:** BSc Student 2 (Ayaan)
**Target:** Actors trying to guess passwords.


### 1.1 Logic (`detection/detect_auth.py`)
*   **Input:** List of `LogEntry` objects.
*   **Filter:** Select logs where `action` or `status` indicates "Failed Login" or "Auth Failure".
*   **Algorithm (Sliding Window):**
    1.  Group failed events by `src_ip`.
    2.  Sort events by `timestamp`.
    3.  Iterate through events: Count how many failures occur within a **60-second window**.
    4.  **Threshold:** If Count > 5, Trigger Alert.
*   **Output:**
    *   `Alert(type="Brute Force", severity="High", description="X failed logins in 1 minute")`

### 1.2 Edge Cases
*   **Distributed Attack:** If multiple IPs attack one account (not covered in MVP, strictly per-IP for now).
*   **Valid Failures:** Users mistyping passwords once or twice should NOT trigger an alert (Threshold > 5 handles this).

---

## 2. Network Pattern Detection (Port Scanning & Suspicious Ops)
**Schedule ID:** Task 4 (BSc Student 3)
**Assignee:** BSc Student 3 (Adam)
**Target:** Reconnaissance and unauthorized admin access.


### 2.1 Port Scanning Logic (`detection/detect_network.py`)
*   **Input:** List of `LogEntry` objects.
*   **Filter:** Select logs where `action` is "Connection Attempt" or protocol is TCP/UDP.
*   **Algorithm:**
    1.  Group events by `src_ip`.
    2.  Track unique `dst_port` accessed by that IP within a **1-minute window**.
    3.  **Threshold:** If (`unique_ports` > 10) AND (`time_window` < 60s), Trigger Alert.
*   **Output:**
    *   `Alert(type="Port Scan", severity="Medium", description="Scanned 10+ ports in 1 minute")`

### 2.2 Suspicious Operations (Privilege Escalation)
*   **Logic:**
    *   Scan `raw_text` or `action` for keywords: `"sudo"`, `"su root"`, `"shadow file accessed"`.
    *   **Condition:** If `src_ip` is NOT in a simplified "Admin Whitelist" (or just flag all for MVP), Trigger Alert.
*   **Output:**
    *   `Alert(type="Suspicious Ops", severity="High", description="Potential Privilege Escalation")`

---

## 3. Integration Checks
**Schedule ID:** Task 1 (MSc Lead) & Phase 3
*   **Data Contract:** Both modules must accept `List[LogEntry]` and return `List[Alert]`.

*   **Performance:** Code must handle ~1000 logs in < 2 seconds (simple Python loops are sufficient).
*   **Deduplication:** Ensure the same "event" doesn't generate 100 alerts.
    *   *Strategy:* Once an IP triggers a "Port Scan" alert, ignore subsequent scans from that IP for 5 minutes (Cooldown).

---

## 4. AI/ML Anomaly Detection (Advanced Security Layer)
**Schedule ID:** *Not currently scheduled*
**Goal:** Train a Supervised Learning model on the historical labeled data (`label` column) to detect zero-day or complex patterns that simple rules miss.


### 4.1 Data Preparation
*   **Source:** `data/CTU-IoT-Malware-Capture-*.csv`
*   **Features (Input):**
    *   `duration`: Flow duration.
    *   `orig_bytes`, `resp_bytes`: Data volume.
    *   `orig_pkts`, `resp_pkts`: Packet counts.
    *   `service`: (One-hot encoded) e.g., `http`, `ssl`, `ssh`.
    *   `conn_state`: (One-hot encoded) e.g., `SF`, `S0`.
*   **Target (Label):**
    *   Column: `label`
    *   Class mapping: `Benign` -> 0, `Malicious*` -> 1.

### 4.2 Model Training (`detection/train_model.py`)
*   **Algorithm:** Random Forest Classifier (Robust, handles mixed data types well).
*   **Library:** `scikit-learn`.
*   **Steps:**
    1.  Load all CSVs.
    2.  Preprocess: Handle missing values, encode categorical strings.
    3.  Split: 80% Train, 20% Test.
    4.  Train Model.
    5.  Save Model: `model.pkl`.

### 4.3 Real-time Inference (`detection/detect_ai.py`)
*   **Integration:**
    *   Load `model.pkl` on startup.
    *   Function: `detect_ml_anomlay(logs) -> List[Alert]`
    *   For each new `LogEntry`, extract features -> Predict Probability.
    *   **Threshold:** If `Prob(Malicious) > 0.8`, Trigger Alert.
*   **Output:**
    *   `Alert(type="AI Anomaly", severity="Medium", description="ML Model detected malicious traffic pattern (Conf: 85%)")`
