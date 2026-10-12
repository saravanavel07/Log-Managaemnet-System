# LogSentry

LogSentry is a lightweight log management and security analytics platform built with Python and Flask. It demonstrates how raw system and application logs can be ingested, normalized, stored, analyzed, and converted into actionable security insights and compliance-ready reports.

The project is designed as a practical, self-contained alternative to enterprise SIEM tooling, with core capabilities for log collection, anomaly detection, alerting, and reporting.

## Overview

LogSentry combines multiple layers of modern log operations into one application:

- Log ingestion from multiple sources
- Parsing and normalization of structured and semi-structured logs
- Centralized storage in SQLite
- Search, filtering, and dashboard visualization
- Rule-based and machine-learning-based alerting
- Compliance-oriented reporting for audit use cases

This repository is ideal for learning, demos, security exploration, and internal tooling prototypes.

## Key Features

### Log Ingestion and Normalization
- Parses common log formats including Linux-style auth logs, JSON application logs, and Nginx access logs
- Standardizes records into a consistent schema for downstream analysis
- Supports centralized log storage for easier monitoring and investigation

### Dashboard and Search
- Web-based dashboard for overview metrics and operational insights
- Logs page with filtering by source, severity, and keyword search
- Charts and summary views for volume trends and severity distribution

### Alerting
- Detects suspicious patterns using rule-based logic
- Correlates related events to identify potential attack sequences
- Uses ML-based anomaly detection to flag abnormal behavior
- Keeps alerts in a triage queue with status updates such as open, acknowledged, and resolved

### Compliance Reporting
- Generates audit-style HTML reports aligned with security and compliance themes
- Summarizes authentication events, privileged actions, access patterns, and retention posture
- Useful for demonstrating evidence collection and governance workflows

### Synthetic Data Generation
- Includes demo log generation to simulate real-world traffic and attack scenarios
- Helps validate detection and reporting modules without needing production data

## Architecture

```text
Sample logs / raw data
        │
        ▼
   ingest.py  ──► normalized data ──► SQLite database
        │
        ▼
anomaly_detection.py ──► risk/anomaly scoring
        │
        ▼
  alerting.py  ──► alert queue + correlation logic
        │
        ▼
    app.py (Flask) ──► dashboard, logs, reports
        │
        ▼
compliance_report.py ──► HTML compliance report
```

## Tech Stack

- Python
- Flask
- SQLite
- scikit-learn
- pandas and numpy
- Jinja2 templates
- Chart.js for frontend visualizations
- pytest for testing

## Repository Structure

```text
Log-Managaemnet-System/
├── app.py                     # Flask application and dashboard routes
├── models.py                  # Database schema and connection helpers
├── ingest.py                  # Log parsing and normalization pipeline
├── anomaly_detection.py       # ML-based anomaly detection logic
├── alerting.py                # Rule engine and alert generation
├── compliance_report.py        # Compliance/report generation logic
├── log_generator.py           # Synthetic log generator and attack simulation
├── requirements.txt           # Python dependencies
├── LICENSE                    # MIT license
├── logsentry.db               # Local SQLite database
├── static/                    # Frontend CSS/JS assets
├── templates/                 # HTML templates for the dashboard
├── tests/                     # Project tests
├── README.md                  # Project documentation
└── sample_logs/               # Generated or raw log inputs
```

## Getting Started

### Prerequisites

- Python 3.9+
- pip
- Virtual environment support

### Installation

```bash
git clone https://github.com/saravanavel07/Log-Managaemnet-System.git
cd Log-Managaemnet-System
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run the Application

```bash
python app.py
```

Then open the application in a browser:

```text
http://localhost:5000
```

## Typical Workflow

```bash
# Generate synthetic log traffic
python log_generator.py --events 2000 --attack brute_force

# Load logs into the database
python ingest.py

# Run anomaly detection
python anomaly_detection.py

# Trigger alert evaluation
python alerting.py

# Start the dashboard
python app.py
```

## Application Pages

- `/` — Dashboard overview with summary cards and charts
- `/logs` — Searchable and filterable log records
- `/alerts` — Alert queue with severity and status management
- `/reports` — Compliance report generation and viewing

## Use Cases

This project is useful for:

- Security log analysis demos
- Student and research projects in cybersecurity
- SIEM and log pipeline learning
- Internal threat-monitoring prototypes
- Audit evidence and compliance reporting exercises

## Security and Compliance Note

The application is intended for educational, demonstration, and prototyping use. It is not a production-grade SIEM platform and does not replace the operational controls, monitoring, and governance required in a real enterprise environment.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome. You can improve the codebase by:

- refining detection logic
- expanding log parsing support
- improving UI and dashboard usability
- adding tests for edge cases and attack scenarios
- extending compliance reporting features

## Contact

For questions or collaboration opportunities, please reach out through the repository owner profile on GitHub.
