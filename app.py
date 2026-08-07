"""
app.py — LogSentry Flask dashboard.

Routes:
  /                dashboard overview (stats, severity breakdown, volume over time)
  /logs            searchable/filterable log table
  /alerts          alert queue (rule-based + ML), with acknowledge/resolve actions
  /reports         generate & view compliance reports
"""
import os
import json
from collections import Counter, defaultdict
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, jsonify

from models import get_conn, init_db
import compliance_report

app = Flask(__name__)
init_db()


@app.route("/")
def dashboard():
    with get_conn() as conn:
        total_logs = conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
        total_alerts = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
        open_alerts = conn.execute("SELECT COUNT(*) c FROM alerts WHERE status='open'").fetchone()["c"]
        critical_alerts = conn.execute(
            "SELECT COUNT(*) c FROM alerts WHERE severity='CRITICAL' AND status='open'"
        ).fetchone()["c"]

        severity_rows = conn.execute(
            "SELECT severity, COUNT(*) c FROM logs GROUP BY severity"
        ).fetchall()
        severity_counts = {r["severity"]: r["c"] for r in severity_rows}

        source_rows = conn.execute(
            "SELECT source, COUNT(*) c FROM logs GROUP BY source ORDER BY c DESC LIMIT 8"
        ).fetchall()

        recent_alerts = conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 8"
        ).fetchall()

        # volume over time, bucketed by hour (best-effort, sqlite string ops)
        vol_rows = conn.execute(
            "SELECT substr(timestamp,1,13) hour_bucket, COUNT(*) c FROM logs "
            "GROUP BY hour_bucket ORDER BY hour_bucket"
        ).fetchall()

    volume_labels = [r["hour_bucket"] for r in vol_rows]
    volume_values = [r["c"] for r in vol_rows]

    return render_template(
        "dashboard.html",
        total_logs=total_logs, total_alerts=total_alerts,
        open_alerts=open_alerts, critical_alerts=critical_alerts,
        severity_counts=severity_counts,
        source_rows=source_rows,
        recent_alerts=recent_alerts,
        volume_labels=json.dumps(volume_labels),
        volume_values=json.dumps(volume_values),
    )


@app.route("/logs")
def logs_view():
    source = request.args.get("source", "")
    severity = request.args.get("severity", "")
    q = request.args.get("q", "")
    page = max(1, int(request.args.get("page", 1)))
    per_page = 50

    where = []
    params = []
    if source:
        where.append("source = ?")
        params.append(source)
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if q:
        where.append("(message LIKE ? OR user LIKE ? OR ip_address LIKE ?)")
        like = f"%{q}%"
        params += [like, like, like]

    where_clause = f"WHERE {' AND '.join(where)}" if where else ""

    with get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) c FROM logs {where_clause}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM logs {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page],
        ).fetchall()
        sources = [r["source"] for r in conn.execute("SELECT DISTINCT source FROM logs").fetchall()]

    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template(
        "logs.html", logs=rows, sources=sources,
        source=source, severity=severity, q=q,
        page=page, total_pages=total_pages, total=total,
    )


@app.route("/alerts")
def alerts_view():
    status_filter = request.args.get("status", "")
    where = ""
    params = []
    if status_filter:
        where = "WHERE status = ?"
        params.append(status_filter)

    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY "
            "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, "
            "created_at DESC",
            params,
        ).fetchall()
        counts = conn.execute(
            "SELECT status, COUNT(*) c FROM alerts GROUP BY status"
        ).fetchall()
    status_counts = {r["status"]: r["c"] for r in counts}

    return render_template("alerts.html", alerts=rows, status_filter=status_filter, status_counts=status_counts)


@app.route("/alerts/<int:alert_id>/<action>", methods=["POST"])
def update_alert(alert_id, action):
    if action not in ("acknowledge", "resolve", "reopen"):
        return jsonify({"error": "invalid action"}), 400
    new_status = {"acknowledge": "acknowledged", "resolve": "resolved", "reopen": "open"}[action]
    with get_conn() as conn:
        conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id))
    return redirect(request.referrer or url_for("alerts_view"))


@app.route("/reports")
def reports_view():
    reports_dir = compliance_report.REPORT_DIR
    files = []
    if os.path.isdir(reports_dir):
        files = sorted(
            [f for f in os.listdir(reports_dir) if f.endswith(".html")],
            reverse=True,
        )
    return render_template("reports.html", files=files)


@app.route("/reports/generate", methods=["POST"])
def generate_report():
    compliance_report.run()
    return redirect(url_for("reports_view"))


@app.route("/reports/view/<path:filename>")
def view_report(filename):
    reports_dir = compliance_report.REPORT_DIR
    path = os.path.join(reports_dir, filename)
    if not os.path.abspath(path).startswith(os.path.abspath(reports_dir)):
        return "Not found", 404
    if not os.path.exists(path):
        return "Not found", 404
    with open(path) as f:
        return f.read()


if __name__ == "__main__":
    app.run(debug=True, port=5000)
