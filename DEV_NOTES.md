# Intelligent Threat Detection Platform

A modular cybersecurity platform designed to ingest network logs, detect anomalies using Machine Learning and heuristic rules, and correlate alerts into actionable incidents.

## Features

- **AI Anomaly Detection**: Random Forest model trained on Zeek logs to identify malicious traffic patterns (C&C, Malware).
- **Data Exfiltration Detection**: Flags large outbound transfers (>50MB).
- **Network Pattern Detection**: Identifies Port Scans and Suspicious Operations (e.g., "sudo" usage).
- **Authentication Analysis**: Detects Brute Force attempts.
- **Incident Correlation**: Groups related alerts by Source IP.

## Installation

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/HamishDS/BCU_Cybersecurity_Hackathon.git
    cd BCU_Cybersecurity_Hackathon
    ```

2.  **Install Dependencies**:
    Requires Python 3.8+.
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Running the Platform

### Running the Platform

#### Option 1: Web Interface (Recommended)
Launch the interactive dashboard:
```bash
streamlit run app.py
```

#### Option 2: CLI Mode
Run the script to process logs in the terminal:
```bash
python main.py
```

This will:
1.  Load network logs from the `data/` directory (e.g., `CTU-IoT-Malware-Capture-20-1conn.log.labeled.csv`).
2.  Run all detection modules (AI, Exfil, Network, Auth).
3.  Display a summary of detected threats and correlated incidents.

### Re-training the AI Model

The AI model (`core/ai_models/threat_model.pkl`) is pre-trained. To re-train it on new data:

1.  Place labeled CSV logs in the `data/` directory.
2.  Run the training script:

```bash
python training/train_model.py
```

Arguments:
- The script automatically picks up all `.labeled.csv` files in `data/`.
- It outputs model accuracy metrics and saves the new model to `core/ai_models/`.

## Directory Structure

- `core/`: Detection logic and data models.
  - `ai_detection.py`: Inference engine.
  - `detect_exfil.py`: Data exfiltration rules.
  - `detect_net.py`: Network pattern rules.
  - `detect_auth.py`: Authentication rules.
- `training/`: Model training scripts.
- `data/`: Network log datasets.
- `development_notes/`: Project documentation and plans.
