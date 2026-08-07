"""
alerting.py — Rule-based detection + multi-step attack correlation.

Two detectors, on top of anomaly_detection.py's ML-based one:

1. Brute-force detector: N+ failed logins from the same IP within a short
   window, optionally followed by a success (higher severity).

2. Privilege-escalation correlator: chains events across time for the same
   IP — failed login -> successful login -> sudo — within a short window.
   This is the "multi-step attack correlation" piece: no single line looks
   very alarming, but the *sequence* does.
"""
from datetime import datetime, timedelta

from models import get_conn, insert_alert

BRUTE_FORCE_THRESHOLD = 8          # failed logins
BRUTE_FORCE_WINDOW_MIN = 15        # minutes
PRIV_ESC_WINDOW_MIN = 5            # minutes between failed->success->sudo


def _parse(ts):
    return datetime.fromisoformat(ts)


def detect_brute_force(conn):
    rows = conn.execute(
        "SELECT id, timestamp, ip_address, user FROM logs WHERE event_type='login_failed' "
        "AND ip_address IS NOT NULL ORDER BY ip_address, timestamp"
    ).fetchall()

    by_ip = {}
    for r in rows:
        by_ip.setdefault(r["ip_address"], []).append(r)

    success_rows = conn.execute(
        "SELECT id, timestamp, ip_address FROM logs WHERE event_type='login_success' "
        "AND ip_address IS NOT NULL"
    ).fetchall()
    success_by_ip = {}
    for r in success_rows:
        success_by_ip.setdefault(r["ip_address"], []).append(r)

    alerts_written = 0
    now = datetime.now().isoformat()

    for ip, events in by_ip.items():
        window_start_idx = 0
        for i in range(len(events)):
            while _parse(events[i]["timestamp"]) - _parse(events[window_start_idx]["timestamp"]) > timedelta(minutes=BRUTE_FORCE_WINDOW_MIN):
                window_start_idx += 1
            window = events[window_start_idx:i + 1]
            if len(window) >= BRUTE_FORCE_THRESHOLD:
                followed_by_success = any(
                    _parse(s["timestamp"]) > _parse(window[-1]["timestamp"])
                    and _parse(s["timestamp"]) - _parse(window[-1]["timestamp"]) < timedelta(minutes=5)
                    for s in success_by_ip.get(ip, [])
                )
                severity = "CRITICAL" if followed_by_success else "HIGH"
                desc = (
                    f"Brute-force pattern: {len(window)} failed logins from {ip} within "
                    f"{BRUTE_FORCE_WINDOW_MIN} minutes"
                    + (", followed by a successful login." if followed_by_success else ".")
                )
                related_ids = ",".join(str(e["id"]) for e in window)
                insert_alert(conn, now, severity, "brute_force", ip, desc, related_ids)
                alerts_written += 1
                break  # one alert per IP is enough for the demo dataset

    return alerts_written


def detect_priv_escalation(conn):
    """Detect failed_login -> login_success -> sudo chains from the same IP."""
    rows = conn.execute(
        "SELECT id, timestamp, ip_address, user, event_type FROM logs "
        "WHERE event_type IN ('login_failed','login_success') AND ip_address IS NOT NULL "
        "ORDER BY ip_address, timestamp"
    ).fetchall()
    sudo_rows = conn.execute(
        "SELECT id, timestamp, user FROM logs WHERE event_type='sudo' ORDER BY timestamp"
    ).fetchall()

    by_ip = {}
    for r in rows:
        by_ip.setdefault(r["ip_address"], []).append(r)

    alerts_written = 0
    now = datetime.now().isoformat()

    for ip, events in by_ip.items():
        for i in range(len(events) - 1):
            if events[i]["event_type"] != "login_failed":
                continue
            for j in range(i + 1, len(events)):
                gap = _parse(events[j]["timestamp"]) - _parse(events[i]["timestamp"])
                if gap > timedelta(minutes=PRIV_ESC_WINDOW_MIN):
                    break
                if events[j]["event_type"] == "login_success":
                    user = events[j]["user"]
                    success_ts = _parse(events[j]["timestamp"])
                    matching_sudo = [
                        s for s in sudo_rows
                        if s["user"] == user
                        and timedelta(0) <= (_parse(s["timestamp"]) - success_ts) <= timedelta(minutes=PRIV_ESC_WINDOW_MIN)
                    ]
                    if matching_sudo:
                        related = [events[i]["id"], events[j]["id"]] + [s["id"] for s in matching_sudo]
                        desc = (
                            f"Multi-step attack pattern: failed login, then successful login, then "
                            f"sudo — all from {ip} (user '{user}') within {PRIV_ESC_WINDOW_MIN} minutes. "
                            f"Classic credential-stuffing-then-escalate sequence."
                        )
                        insert_alert(
                            conn, now, "CRITICAL", "priv_escalation", ip, desc,
                            ",".join(str(x) for x in related),
                        )
                        alerts_written += 1
                    break  # move to next failed-login anchor

    return alerts_written


def run(reset=True):
    with get_conn() as conn:
        if reset:
            conn.execute("DELETE FROM alerts WHERE alert_type IN ('brute_force','priv_escalation')")
        bf = detect_brute_force(conn)
        pe = detect_priv_escalation(conn)
    print(f"Alerting complete: {bf} brute-force alert(s), {pe} privilege-escalation alert(s).")
    return bf + pe


if __name__ == "__main__":
    run()
