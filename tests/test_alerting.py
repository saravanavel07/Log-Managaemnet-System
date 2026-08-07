"""
tests/test_alerting.py — Integration-style tests for the rule engine, using
an isolated temp SQLite DB so tests don't touch the real dev database.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import models


def setup_temp_db(monkeypatch):
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    monkeypatch.setattr(models, "DB_PATH", tmp.name)
    models.init_db()
    return tmp.name


def test_brute_force_detection(monkeypatch):
    setup_temp_db(monkeypatch)
    import alerting

    base = datetime(2026, 8, 6, 12, 0, 0)
    with models.get_conn() as conn:
        for i in range(10):
            models.insert_log(
                conn, (base + timedelta(seconds=i * 3)).isoformat(), "auth", "WARNING",
                "login_failed", "185.220.101.47", "root", "Failed SSH login attempt", "raw",
            )

    with models.get_conn() as conn:
        count = alerting.detect_brute_force(conn)

    assert count == 1
    with models.get_conn() as conn:
        alerts = conn.execute("SELECT * FROM alerts WHERE alert_type='brute_force'").fetchall()
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "185.220.101.47"


def test_priv_escalation_detection(monkeypatch):
    setup_temp_db(monkeypatch)
    import alerting

    base = datetime(2026, 8, 6, 12, 0, 0)
    with models.get_conn() as conn:
        models.insert_log(conn, base.isoformat(), "auth", "WARNING", "login_failed",
                           "185.220.101.47", "svc_backup", "Failed SSH login attempt", "raw")
        models.insert_log(conn, (base + timedelta(seconds=30)).isoformat(), "auth", "INFO", "login_success",
                           "185.220.101.47", "svc_backup", "Successful SSH login", "raw")
        models.insert_log(conn, (base + timedelta(seconds=90)).isoformat(), "auth", "CRITICAL", "sudo",
                           None, "svc_backup", "Privileged command executed via sudo", "raw")

    with models.get_conn() as conn:
        count = alerting.detect_priv_escalation(conn)

    assert count == 1
    with models.get_conn() as conn:
        alerts = conn.execute("SELECT * FROM alerts WHERE alert_type='priv_escalation'").fetchall()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"


def test_no_false_positive_on_normal_traffic(monkeypatch):
    setup_temp_db(monkeypatch)
    import alerting

    base = datetime(2026, 8, 6, 12, 0, 0)
    with models.get_conn() as conn:
        # A couple of isolated failed logins, well under the threshold
        models.insert_log(conn, base.isoformat(), "auth", "WARNING", "login_failed",
                           "10.0.0.5", "alice", "Failed SSH login attempt", "raw")
        models.insert_log(conn, (base + timedelta(minutes=45)).isoformat(), "auth", "WARNING", "login_failed",
                           "10.0.0.5", "alice", "Failed SSH login attempt", "raw")

    with models.get_conn() as conn:
        bf_count = alerting.detect_brute_force(conn)
        pe_count = alerting.detect_priv_escalation(conn)

    assert bf_count == 0
    assert pe_count == 0
