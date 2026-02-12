# Hackathon Schedule: Intelligent Threat Detection Platform (3 Hours)

## Team Composition
*   **Total:** 6 Members
*   **Stack:** 1 MSc (Team Lead), 5 BSc (First Years)
*   **Goal:** MVP of a Threat Detection & Correlation Platform

## Time Allocation (Total: 3 Hours)

### Phase 1: Planning & Architecture (00:00 - 00:30)
*   **All Hands (15 mins):**
    *   Agree on the **Data Schema** (standard JSON format for a "Log Event"). THIS IS CRITICAL.
    *   Agree on the **Incident Schema** (what the output looks like).
    *   Select datasets (e.g., small subset of a Kaggle intrusion dataset or manually created CSV).
*   **MSc Lead:** Set up the Git repository, create empty folders (`ingestion`, `detection`, `ui`), and `requirements.txt`.

### Phase 2: Parallel Development (00:30 - 02:00)
*   *See "Roles & Tasks" below for individual assignments.*
*   **Checkpoint (01:30):** Integration check. ensuring everyone's Python functions accept/return the agreed data formats.

### Phase 3: Integration & Testing (02:00 - 02:30)
*   **Code Freeze:** No new features.
*   **Integration:** Connect `Ingestion` -> `Detection` -> `Correlation` -> `UI`.
*   **MSc Lead:** Merges modules into `main.py`.

### Phase 4: Polish & Pitch Prep (02:30 - 03:00)
*   **BSc 5:** Finalize Pitch Deck.
*   **Team:** Rehearse the demo flow.
*   **Final Bug Fixes:** Only critical crashes.

---

## Roles & Task Breakdown

### 1. MSc Student (Team Lead & Correlation Engine) - Hamish
*   **Responsibility:** Architecture, Code Merging, and the "Brain" of the system.
*   **Tasks:**
    *   Define `LogEntry` and `Incident` classes (Python Dataclasses).
    *   Write the file `correlation_engine.py`: Logic to group diverse alerts (from BSc 2 & 3) into a single "Incident" based on IP address or Time Window.
    *   **Deliverable:** A function `correlate_alerts(alerts) -> incidents`.

### 2. BSc Student 1 (Data Ingest)
*   **Responsibility:** Getting data INTO the system.
*   **Tasks:**
    *   Find/Create a clean CSV/JSON dataset (or use synthetic data).
    *   Write `ingest.py`: Reads the raw file, cleans timestamps, renormalizes keys (e.g., rename `src_ip` to `sourceAddress`), and returns a list of standard `LogEntry` objects.
    *   **Deliverable:** A function `load_logs(filepath) -> list[LogEntry]`.

### 3. BSc Student 2 (Detection Logic A: Auth) - Ayaan Ahmed
*   **Responsibility:** Detecting Identity/Login attacks.
*   **Tasks:**
    *   Write `detect_auth.py`.
    *   Implement logic: Count failed logins by IP. If > 5 in 1 minute, create an Alert with severity "High" and type "Brute Force".
    *   **Deliverable:** A function `detect_brute_force(logs) -> list[Alert]`.

### 4. BSc Student 3 (Detection Logic B: Network) - Adam
*   **Responsibility:** Detecting Network/Pattern attacks.
*   **Tasks:**
    *   Write `detect_network.py`.
    *   Implement logic: E.g., Port Scanning (one IP hitting multiple ports) or Suspicious Ops (sudo usage).
    *   **Deliverable:** A function `detect_port_scan(logs) -> list[Alert]`.

### 5. BSc Student 4 (Frontend / Visualization)
*   **Responsibility:** Making it look good (The "Dashboard").
*   **Tasks:**
    *   Use **Streamlit** (recommended for speed) or Flask.
    *   Create a simple app that uploads the log file, runs the processing pipeline, and displays:
        *   A metric counter ("5 Incidents Detected").
        *   A dataframe/table of the Incidents.
        *   A simple bar chart (Alerts per Type).
    *   **Deliverable:** `app.py` that runs the full visualization.

### 6. BSc Student 5 (Presentation & QA)
*   **Responsibility:** The "Pitch" and Quality Control.
*   **Tasks:**
    *   **The Pitch Deck:** Create 5-7 slides covering the criteria: Problem, Solution, Architecture, Innovation.
    *   **QA:** Manually test the detection logic with "fake" bad logs to prove it works.
    *   **Documentation:** Write the `README.md` (how to run it) and `requirements.txt`.
    *   **Deliverable:** Slide deck (PDF/PPT) and polished README.

---

## Technical Architecture (Data Flow)
1.  **Input:** `logs.csv`
2.  **Ingest (BSc 1):** -> `List[LogEntry]`
3.  **Detect (BSc 2 & 3):** -> `List[Alert]`
4.  **Correlate (MSc):** -> `List[Incident]` (Groups Alerts by IP)
5.  **Display (BSc 4):** -> Streamlit Dashboard
6.  **Explain (BSc 5):** -> Pitch Deck & Demo

## Risk Management (What if we run out of time?)
*   **Drop Correlation:** If the MSc student gets stuck, just display the raw Alerts on the dashboard.
*   **Mock Data:** If Ingestion (BSc 1) fails, hardcode a list of 10 sample logs in Python to ensure the rest of the pipeline works.
*   **Static Slides:** If the Dashboard (BSc 4) breaks, use screenshots of "expected" output for the pitch.
