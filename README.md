# LogSentry — Centralized Log Management & Anomaly Detection

A mini log management platform inspired by enterprise SIEM tools (like ManageEngine EventLog Analyzer),
built to demonstrate the full log lifecycle: **collection → parsing/normalization → storage → analysis →
alerting → compliance reporting.**

Built as a self-contained Python/Flask app — no external infra (Elasticsearch/Kafka) required to run it,
but the architecture is designed to be swapped in later.

## Features

### Core
- **Multi-source log ingestion** — parses Linux `auth.log`-style syslog, JSON app logs, and Nginx access
  logs into one normalized schema.
- **Centralized storage** — SQLite by default (swap for Postgres via `DATABASE_URL`).
- **Searchable dashboard** — filter by source, severity, time range, free-text search.
- **Log statistics** — volume over time, top sources, severity breakdown (Chart.js).

### Advanced
- **ML-based anomaly detection** — an Isolation Forest model scores login/event patterns per source IP
  and flags outliers (e.g. abnormal failed-login bursts) that static thresholds would miss.
- **Rule-based + ML alerting engine** — brute-force detection (N failed logins within a time window),
  privilege-escalation correlation (failed login → sudo success from the same IP shortly after), and
  ML-flagged anomalies all feed one alert queue.
- **Multi-step attack correlation** — chains related events across time to detect attack sequences,
  not just single suspicious lines.
- **Compliance report generator** — generates an audit-ready HTML report (PCI DSS / GDPR / HIPAA-style
  sections: authentication events, privileged actions, data access, retention summary).
- **Synthetic log generator** — script to simulate realistic traffic + injected attack scenarios
  (brute force, privilege escalation) for demo purposes.

## Architecture

```
sample_logs/ (raw logs)
      │
      ▼
  ingest.py   ── parses + normalizes ──▶  SQLite (logs table)
      │
      ▼
anomaly_detection.py  (Isolation Forest over per-IP feature windows)
      │
      ▼
  alerting.py   ── rule engine + ML flags ──▶  SQLite (alerts table)
      │
      ▼
   app.py (Flask)  ──▶  Dashboard / Alerts / Reports (web UI)
      │
      ▼
compliance_report.py  ──▶  HTML compliance report
```

## Quickstart

```bash
# 1. Set up environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Generate sample logs (normal traffic + a simulated attack)
python log_generator.py --events 2000 --attack brute_force

# 3. Ingest logs into the database
python ingest.py

# 4. Run anomaly detection + alerting
python anomaly_detection.py
python alerting.py

# 5. Launch the dashboard
python app.py
# Visit http://localhost:5000
```

## Project structure

```
log-management-system/
├── app.py                  # Flask dashboard (routes, views)
├── models.py                # SQLite schema + DB helpers
├── log_generator.py         # Synthetic log generator (incl. attack simulation)
├── ingest.py                 # Parsing + normalization pipeline
├── anomaly_detection.py      # Isolation Forest anomaly scoring
├── alerting.py               # Rule engine + correlation + alert persistence
├── compliance_report.py      # HTML compliance report generator
├── templates/                # Jinja2 templates for the dashboard
├── static/                   # CSS/JS assets
├── sample_logs/              # Generated/raw log files live here
├── tests/                    # Unit tests for parsing & detection logic
└── requirements.txt
```

## Why these "advanced" features

A basic log viewer just displays lines. This project pushes further into what a real security
team needs:

| Feature | What it demonstrates |
|---|---|
| Isolation Forest anomaly detection | Applying ML to unsupervised outlier detection on operational data |
| Multi-step correlation engine | Modeling attacker behavior as *sequences*, not isolated events |
| Compliance report generator | Translating raw logs into audit-ready evidence |
| Synthetic attack simulation | Reproducible test data for validating detection logic |

## Tech stack

- **Backend:** Python, Flask
- **Storage:** SQLite (swappable for Postgres)
- **ML:** scikit-learn (Isolation Forest)
- **Frontend:** Jinja2 templates + Chart.js
- **Testing:** pytest

## Possible extensions

- Swap SQLite for Elasticsearch/OpenSearch for full-text log search at scale
- Stream ingestion via Kafka/Redis Streams instead of batch `ingest.py`
- Slack/email webhook integration in `alerting.py`
- LLM-powered natural-language query box ("show failed logins in the last hour")

## License

MIT — see [LICENSE](LICENSE).
