"""
ingest.py — Parses raw logs from sample_logs/ into the normalized `logs` table.

Supports three formats out of the box, mirroring the "universal log collection"
idea from real SIEM tools: each source has its own parser but they all emit the
same normalized record shape (timestamp, source, severity, event_type, ip,
user, message, raw).
"""
import json
import os
import re
from datetime import datetime

from models import get_conn, init_db, insert_log, clear_table

LOG_DIR = os.path.join(os.path.dirname(__file__), "sample_logs")
CURRENT_YEAR = datetime.now().year

AUTH_FAILED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
AUTH_SUCCESS_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)"
)
SUDO_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sudo:\s+(?P<user>\S+)\s+:"
)
ACCESS_RE = re.compile(
    r'^(?P<ip>[\d.]+)\s+-\s+-\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\d+)'
)


def parse_syslog_ts(ts_str):
    # e.g. "Aug  6 14:32:10" -> assume current year
    dt = datetime.strptime(f"{CURRENT_YEAR} {ts_str}", "%Y %b %d %H:%M:%S")
    return dt.isoformat()


def parse_auth_log(path):
    records = []
    if not os.path.exists(path):
        return records
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            m = AUTH_FAILED_RE.match(line)
            if m:
                records.append({
                    "timestamp": parse_syslog_ts(m.group("ts")),
                    "source": "auth", "severity": "WARNING", "event_type": "login_failed",
                    "ip_address": m.group("ip"), "user": m.group("user"),
                    "message": "Failed SSH login attempt", "raw": line,
                })
                continue
            m = AUTH_SUCCESS_RE.match(line)
            if m:
                records.append({
                    "timestamp": parse_syslog_ts(m.group("ts")),
                    "source": "auth", "severity": "INFO", "event_type": "login_success",
                    "ip_address": m.group("ip"), "user": m.group("user"),
                    "message": "Successful SSH login", "raw": line,
                })
                continue
            m = SUDO_RE.match(line)
            if m:
                records.append({
                    "timestamp": parse_syslog_ts(m.group("ts")),
                    "source": "auth", "severity": "CRITICAL", "event_type": "sudo",
                    "ip_address": None, "user": m.group("user"),
                    "message": "Privileged command executed via sudo", "raw": line,
                })
    return records


def parse_app_log(path):
    records = []
    if not os.path.exists(path):
        return records
    level_to_severity = {"INFO": "INFO", "WARNING": "WARNING", "ERROR": "ERROR"}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            records.append({
                "timestamp": obj.get("timestamp"),
                "source": obj.get("service", "app"),
                "severity": level_to_severity.get(obj.get("level"), "INFO"),
                "event_type": "app_event",
                "ip_address": None,
                "user": None,
                "message": obj.get("message"),
                "raw": line,
            })
    return records


def parse_access_log(path):
    records = []
    if not os.path.exists(path):
        return records
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            m = ACCESS_RE.match(line)
            if not m:
                continue
            status = int(m.group("status"))
            severity = "ERROR" if status >= 500 else ("WARNING" if status >= 400 else "INFO")
            try:
                ts = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z").isoformat()
            except ValueError:
                ts = datetime.now().isoformat()
            records.append({
                "timestamp": ts,
                "source": "nginx", "severity": severity, "event_type": "http_request",
                "ip_address": m.group("ip"), "user": None,
                "message": f'{m.group("method")} {m.group("path")} -> {status}',
                "raw": line,
            })
    return records


def run_ingest(reset=True):
    init_db()
    all_records = []
    all_records += parse_auth_log(os.path.join(LOG_DIR, "auth.log"))
    all_records += parse_app_log(os.path.join(LOG_DIR, "app.json"))
    all_records += parse_access_log(os.path.join(LOG_DIR, "access.log"))

    with get_conn() as conn:
        if reset:
            clear_table(conn, "logs")
        for r in all_records:
            insert_log(
                conn, r["timestamp"], r["source"], r["severity"], r["event_type"],
                r["ip_address"], r["user"], r["message"], r["raw"],
            )

    print(f"Ingested {len(all_records)} log records into the database.")
    return len(all_records)


if __name__ == "__main__":
    run_ingest()
