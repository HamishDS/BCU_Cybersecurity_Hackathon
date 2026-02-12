# 🛡️ Intelligent Threat Detection Platform

### Next-Generation Cybersecurity Analysis & Response System

The **Intelligent Threat Detection Platform** is a modular, AI-driven security solution designed to identify, analyze, and correlate malicious network activity in real-time. By combining machine learning models with traditional heuristic rules, it provides a robust defense against both known and emerging cyber threats.

---

## 🚀 Key Features

### 🤖 1. AI Anomaly Detection (Machine Learning)
Leverages a supervised **Random Forest** model trained on labeled network traffic (Zeek logs).
- **Capability**: Detects complex, non-linear attack patterns such as Command & Control (C&C) beaconing and malware communication.
- **Advantage**: Identifies zero-day threats that evade static signatures.

### 📤 2. Data Exfiltration Monitoring
Real-time volume analysis to prevent data loss.
- **Trigger**: Flags connections transferring unusually large amounts of data (>50MB).
- **Use Case**: Detects compromised insiders or malware exfiltrating sensitive files.

### 🕸️ 3. Network Pattern Recognition
Behavioral analysis to spot reconnaissance and lateral movement.
- **Port Scan Detection**: Identifies hosts scanning multiple targets rapidly (>10 unique hosts in 1 min).
- **Suspicious Operations**: Flags dangerous keywords (e.g., `sudo`, `su root`, `shadow file`) in unencrypted traffic logs.

### 🔐 4. Authentication Security
Protects user accounts from unauthorized access.
- **Brute Force Detection**: Correlates failed login attempts per source IP.
- **Threshold**: Alerts on >5 failures within a 60-second window.

### 🔗 5. Automated Incident Correlation
Reduces alert fatigue by grouping related alerts into actionable **Incidents**.
- **Logic**: Aggregates multiple alerts from the same Source IP into a single investigation unit.
- **Benefit**: Provides analysts with a full context of the attack lifecycle.

---

## 🏗️ Architecture

The platform follows a streamlined pipeline architecture:

1.  **Ingest**: Raw network logs (CSV/JSON) are normalized into standard `LogEntry` objects.
2.  **Detect**: Four specialized modules scan the logs in parallel:
    - `core/ai_detection.py` (ML Inference)
    - `core/detect_exfil.py` (Heuristic Rules)
    - `core/detect_net.py` (Pattern Matching)
    - `core/detect_auth.py` (Stateful Analysis)
3.  **Correlate**: The Correlation Engine groups alerts by attacker IP (`core/correlation.py`).
4.  **Visualize**: A dynamic **Streamlit Dashboard** (`app.py`) presents real-time insights.

---

## 📊 Interactive Dashboard

The platform features a modern web interface built with **Streamlit**:

- **Real-time Metrics**: Total logs processed, active threats, and unique attackers.
- **Incident Explorer**: Drill down into specific incidents to see all associated alerts.
- **Threat Analytics**: Visual charts showing attack frequency over time and top attacking IPs.
- **Source Attribution**: Clearly identifies which detection module flagged the threat (e.g., 🤖 AI vs 🕸️ Network Rule).

---

## ⚡ Getting Started

### Prerequisites
- Python 3.8+
- Network Logs (CSV format, e.g., Zeek `conn.log`)

### Installation

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/HamishDS/BCU_Cybersecurity_Hackathon.git
    cd BCU_Cybersecurity_Hackathon
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

### Running the Platform

Launch the interactive dashboard:
```bash
streamlit run app.py
```

Or run the CLI version for batch processing:
```bash
python main.py
```

---

## 🧠 AI Model Training

The system comes with a pre-trained model. To retrain it on new datasets:

1.  Place labeled CSV logs in the `data/` directory.
2.  Run the training script:
    ```bash
    python training/train_model.py
    ```
    This will generate a new `threat_model.pkl` with updated accuracy metrics.

---

**Developed for the BCU Cybersecurity Hackathon**
