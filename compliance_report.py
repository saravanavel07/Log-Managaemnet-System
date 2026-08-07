"""
compliance_report.py — Generates an audit-ready HTML compliance report from
the logs/alerts database, structured around the kind of evidence auditors
for PCI DSS / HIPAA / GDPR / SOX typically ask for:

  - Authentication activity summary (logins, failures, lockout-worthy events)
  - Privileged action log (sudo / admin actions)
  - Security incidents and alerts raised in the period
  - Data retention summary
"""
import os
from datetime import datetime

from models import get_conn

REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")

TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>LogSentry Compliance Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 40px; color: #1a1a1a; background:#fafafa; }}
  h1 {{ border-bottom: 3px solid #2563eb; padding-bottom: 10px; }}
  h2 {{ margin-top: 40px; color: #2563eb; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 12px; background: white; }}
  th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; font-size: 14px; }}
  th {{ background: #2563eb; color: white; }}
  tr:nth-child(even) {{ background: #f2f6fc; }}
  .summary-cards {{ display: flex; gap: 16px; margin-top: 16px; }}
  .card {{ flex: 1; background: white; border: 1px solid #ddd; border-radius: 8px; padding: 16px; text-align:center; }}
  .card .num {{ font-size: 28px; font-weight: bold; color: #2563eb; }}
  .severity-CRITICAL {{ color: #b91c1c; font-weight: bold; }}
  .severity-HIGH {{ color: #c2410c; font-weight: bold; }}
  .severity-MEDIUM {{ color: #a16207; }}
  .severity-LOW {{ color: #4b5563; }}
  .meta {{ color: #666; font-size: 13px; }}
</style>
</head>
<body>
<h1>LogSentry — Security &amp; Compliance Report</h1>
<p class="meta">Generated: {generated_at} &nbsp;|&nbsp; Reporting window: full retained log history &nbsp;|&nbsp; Frameworks referenced: PCI DSS, HIPAA, GDPR, SOX (general controls)</p>

<div class="summary-cards">
  <div class="card"><div class="num">{total_logs}</div>Total Log Events</div>
  <div class="card"><div class="num">{total_auth}</div>Authentication Events</div>
  <div class="card"><div class="num">{total_alerts}</div>Security Alerts Raised</div>
  <div class="card"><div class="num">{open_alerts}</div>Open / Unresolved</div>
</div>

<h2>1. Authentication Activity Summary</h2>
<p>Covers user access control evidence relevant to PCI DSS Req. 8, HIPAA Access Control, and SOX logical access review.</p>
<table>
<tr><th>Metric</th><th>Count</th></tr>
<tr><td>Successful logins</td><td>{login_success}</td></tr>
<tr><td>Failed login attempts</td><td>{login_failed}</td></tr>
<tr><td>Distinct users observed</td><td>{distinct_users}</td></tr>
<tr><td>Distinct source IPs observed</td><td>{distinct_ips}</td></tr>
</table>

<h2>2. Privileged Actions Log</h2>
<p>Sudo / administrative command executions — relevant to least-privilege and change-control controls.</p>
<table>
<tr><th>Timestamp</th><th>User</th><th>Message</th></tr>
{sudo_rows}
</table>

<h2>3. Security Incidents &amp; Alerts</h2>
<p>All alerts raised by the rule engine and ML anomaly detector during the reporting period.</p>
<table>
<tr><th>Created</th><th>Severity</th><th>Type</th><th>Source IP</th><th>Description</th><th>Status</th></tr>
{alert_rows}
</table>

<h2>4. Data Retention Summary</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Earliest retained log</td><td>{earliest_log}</td></tr>
<tr><td>Latest retained log</td><td>{latest_log}</td></tr>
<tr><td>Retention policy (configured)</td><td>Demo default — 1 year recommended for audit trail per common regulatory guidance</td></tr>
</table>

<p class="meta" style="margin-top:40px;">This report was generated automatically by LogSentry for demonstration purposes and
is not a substitute for a formal compliance audit.</p>
</body>
</html>
"""


def build_report():
    with get_conn() as conn:
        total_logs = conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
        login_success = conn.execute("SELECT COUNT(*) c FROM logs WHERE event_type='login_success'").fetchone()["c"]
        login_failed = conn.execute("SELECT COUNT(*) c FROM logs WHERE event_type='login_failed'").fetchone()["c"]
        total_auth = login_success + login_failed
        distinct_users = conn.execute("SELECT COUNT(DISTINCT user) c FROM logs WHERE user IS NOT NULL").fetchone()["c"]
        distinct_ips = conn.execute("SELECT COUNT(DISTINCT ip_address) c FROM logs WHERE ip_address IS NOT NULL").fetchone()["c"]

        sudo_events = conn.execute(
            "SELECT timestamp, user, message FROM logs WHERE event_type='sudo' ORDER BY timestamp DESC LIMIT 50"
        ).fetchall()
        sudo_rows = "\n".join(
            f"<tr><td>{r['timestamp']}</td><td>{r['user']}</td><td>{r['message']}</td></tr>"
            for r in sudo_events
        ) or "<tr><td colspan='3'>No privileged actions recorded.</td></tr>"

        alerts = conn.execute(
            "SELECT created_at, severity, alert_type, source_ip, description, status FROM alerts "
            "ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
        total_alerts = len(alerts)
        open_alerts = sum(1 for a in alerts if a["status"] == "open")
        alert_rows = "\n".join(
            f"<tr><td>{a['created_at']}</td>"
            f"<td class='severity-{a['severity']}'>{a['severity']}</td>"
            f"<td>{a['alert_type']}</td><td>{a['source_ip'] or '-'}</td>"
            f"<td>{a['description']}</td><td>{a['status']}</td></tr>"
            for a in alerts
        ) or "<tr><td colspan='6'>No alerts raised in this period.</td></tr>"

        bounds = conn.execute("SELECT MIN(timestamp) mn, MAX(timestamp) mx FROM logs").fetchone()
        earliest_log = bounds["mn"] or "N/A"
        latest_log = bounds["mx"] or "N/A"

    html = TEMPLATE.format(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_logs=total_logs, total_auth=total_auth, total_alerts=total_alerts, open_alerts=open_alerts,
        login_success=login_success, login_failed=login_failed,
        distinct_users=distinct_users, distinct_ips=distinct_ips,
        sudo_rows=sudo_rows, alert_rows=alert_rows,
        earliest_log=earliest_log, latest_log=latest_log,
    )
    return html


def run():
    os.makedirs(REPORT_DIR, exist_ok=True)
    html = build_report()
    out_path = os.path.join(REPORT_DIR, f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    with open(out_path, "w") as f:
        f.write(html)
    print(f"Compliance report written to {out_path}")
    return out_path


if __name__ == "__main__":
    run()
