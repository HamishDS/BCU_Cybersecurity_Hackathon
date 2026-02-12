# Problem Statement: Intelligent Threat Detection & Incident Correlation

## Platform
**Develop a web-based security platform that ingests raw system or network logs, detects malicious behaviour, and correlates related security events into structured incidents.**

The system should identify suspicious patterns, map activity to recognised attack techniques, and present a clear incident timeline to support rapid investigation and response.

## Context
Modern organisations generate vast volumes of security logs across networks, endpoints, and applications. While detection tools may flag isolated alerts, security teams often struggle to:
*   Correlate multiple alerts into a single attack narrative
*   Prioritise genuine threats over noise
*   Understand how observed behaviour maps to recognised attack techniques

Security Operations Centres require systems that not only detect suspicious behaviour, but also reconstruct attack sequences in a clear and structured way.

This challenge focuses on building an intelligent detection and correlation engine that transforms raw logs into actionable security insight.

## Ideal Deliverables

### Prototype or MVP
A functional web application or service that:
*   Ingests structured logs (JSON or CSV)
*   Detects at least two types of suspicious activity, for example:
    *   Brute-force login attempts
    *   Port scanning
    *   Lateral movement indicators
    *   Suspicious process execution
*   Correlates related alerts into a single incident
*   Generates a structured incident summary including:
    *   Affected assets
    *   Timeline of events
    *   Suspected attack technique
    *   Severity score

The system must demonstrate:
*   Clear and defensible detection logic
*   Defined correlation methodology
*   Structured output such as a dashboard, timeline, or JSON report

### Pitch Deck
Explain:
*   The challenge of alert fatigue in Security Operations
*   How your system improves clarity and response speed
*   The logic behind your detection and correlation model
*   How the platform could scale to enterprise SOC environments
*   Potential integration with SIEM or cloud logging systems

## Technical Summary

### System Architecture Overview
`User uploads logs` → `Log parsing and normalisation` → `Detection engine` → `Correlation engine` → `Incident scoring` → `Dashboard and structured output`

Your architecture should clearly separate:
*   Ingestion
*   Detection logic
*   Correlation logic
*   Presentation layer

### Dataset Source and Preprocessing
You may use:
*   Public intrusion detection datasets
*   Sample SOC logs
*   Generated synthetic logs

Data should be:
*   Normalised into a consistent schema
*   Timestamp synchronised
*   Cleaned of irrelevant noise
*   **Optional:** implement time-window logic for event correlation.

### Example of User Output
> "Multiple failed login attempts from 192.168.1.25 followed by successful authentication and internal port scanning. Likely brute-force followed by reconnaissance. Severity: High."

> "Five alerts correlated into one incident spanning 14 minutes across two hosts."

### GitHub Repository
Include:
*   Full source code
*   Modular detection and correlation components
*   README with setup instructions and dependencies
*   Sample log dataset for testing
*   Screenshots or demo GIFs of dashboard and incident timeline

### Optional Features
*   Mapping detected behaviour to MITRE ATT&CK techniques
*   Interactive attack timeline visualisation
*   Risk scoring based on asset criticality
*   Live streaming log simulation
*   AI-assisted plain-English explanation of incidents

## Judging Criteria

| Category | Description | Weight |
| :--- | :--- | :--- |
| **Innovation** | Originality of approach, creativity in detection and correlation logic, and effective use of AI where appropriate | 20% |
| **Technical Implementation** | Code quality, modular architecture, correctness of implementation, scalability considerations, and overall system robustness | 35% |
| **Security Accuracy & Threat Modelling** | Validity of detection logic, realistic threat assumptions, correct mapping of behaviours, and sound correlation methodology | 35% |
| **Presentation** | Clarity of demo, structured explanation of system design, and effectiveness of the final pitch | 10% |

## Useful Tools
*   Python (FastAPI, Flask)
*   Node.js (Express)
*   Plotly or Chart.js for visualisation
*   NetworkX for graph-based correlation
*   Elastic-style log processing tools
*   AI models for classification or explanation

## Data Sources
*   Kaggle intrusion detection datasets
*   Public SOC log samples
*   Synthetic generated logs
*   MITRE ATT&CK framework reference

## One-Line Task Description
**Build an intelligent platform that detects, correlates, and explains cyber attacks from raw security logs**
