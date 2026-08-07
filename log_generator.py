"""
log_generator.py — Produces realistic synthetic logs for LogSentry to ingest.

Generates three raw log files under sample_logs/:
  - auth.log     (Linux-style SSH auth events)
  - app.json      (JSON application logs)
  - access.log     (Nginx-style access log)

Supports injecting an attack scenario so the detection pipeline has
something real to catch:
  --attack brute_force        Repeated failed logins from one IP, then a success
  --attack priv_escalation    Failed login -> success -> sudo from same IP quickly
  --attack none                Pure normal traffic (default)
"""
import argparse
import json
import os
import random
from datetime import datetime, timedelta

OUT_DIR = os.path.join(os.path.dirname(__file__), "sample_logs")

USERS = ["alice", "bob", "carol", "dave", "svc_backup", "root", "admin"]
NORMAL_IPS = [f"10.0.{random.randint(0,5)}.{i}" for i in range(2, 40)]
ATTACKER_IP = "185.220.101.47"  # looks like a plausible external scanning IP

HTTP_PATHS = ["/", "/login", "/api/users", "/dashboard", "/static/app.js", "/api/orders", "/health"]
HTTP_STATUSES = [200, 200, 200, 200, 301, 404, 500]


def rand_ts(base, spread_seconds=6 * 3600):
    return base + timedelta(seconds=random.randint(0, spread_seconds))


def gen_auth_events(n, base_time, attack):
    events = []
    for _ in range(n):
        ts = rand_ts(base_time)
        ip = random.choice(NORMAL_IPS)
        user = random.choice(USERS)
        success = random.random() > 0.08
        events.append({
            "ts": ts,
            "ip": ip,
            "user": user,
            "event_type": "login_success" if success else "login_failed",
            "severity": "INFO" if success else "WARNING",
        })

    if attack == "brute_force":
        attack_start = base_time + timedelta(hours=2)
        for i in range(25):
            events.append({
                "ts": attack_start + timedelta(seconds=i * 4),
                "ip": ATTACKER_IP,
                "user": "root",
                "event_type": "login_failed",
                "severity": "WARNING",
            })
        events.append({
            "ts": attack_start + timedelta(seconds=25 * 4 + 5),
            "ip": ATTACKER_IP,
            "user": "root",
            "event_type": "login_success",
            "severity": "CRITICAL",
        })

    if attack == "priv_escalation":
        attack_start = base_time + timedelta(hours=3)
        events.append({"ts": attack_start, "ip": ATTACKER_IP, "user": "svc_backup",
                        "event_type": "login_failed", "severity": "WARNING"})
        events.append({"ts": attack_start + timedelta(seconds=30), "ip": ATTACKER_IP, "user": "svc_backup",
                        "event_type": "login_success", "severity": "WARNING"})
        events.append({"ts": attack_start + timedelta(seconds=90), "ip": ATTACKER_IP, "user": "svc_backup",
                        "event_type": "sudo", "severity": "CRITICAL"})

    events.sort(key=lambda e: e["ts"])
    return events


def write_auth_log(events):
    path = os.path.join(OUT_DIR, "auth.log")
    with open(path, "w") as f:
        for e in events:
            ts = e["ts"].strftime("%b %d %H:%M:%S")
            host = "prod-web-01"
            if e["event_type"] == "login_failed":
                line = f"{ts} {host} sshd[{random.randint(1000,9999)}]: Failed password for {e['user']} from {e['ip']} port {random.randint(1024,65000)} ssh2"
            elif e["event_type"] == "login_success":
                line = f"{ts} {host} sshd[{random.randint(1000,9999)}]: Accepted password for {e['user']} from {e['ip']} port {random.randint(1024,65000)} ssh2"
            else:  # sudo
                line = f"{ts} {host} sudo: {e['user']} : TTY=pts/0 ; PWD=/home/{e['user']} ; USER=root ; COMMAND=/bin/bash"
            f.write(line + "\n")
    return path


def gen_app_events(n, base_time):
    levels = ["INFO"] * 7 + ["WARNING"] * 2 + ["ERROR"]
    messages = [
        "Request completed", "Cache miss for key", "DB connection pool exhausted retrying",
        "Background job finished", "Payment webhook received", "Rate limit threshold approached",
        "Unhandled exception in worker", "Scheduled task executed",
    ]
    events = []
    for _ in range(n):
        ts = rand_ts(base_time)
        events.append({
            "timestamp": ts.isoformat(),
            "level": random.choice(levels),
            "service": random.choice(["api", "worker", "billing", "auth-service"]),
            "message": random.choice(messages),
            "request_id": f"req-{random.randint(100000,999999)}",
        })
    events.sort(key=lambda e: e["timestamp"])
    return events


def write_app_log(events):
    path = os.path.join(OUT_DIR, "app.json")
    with open(path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    return path


def gen_access_events(n, base_time):
    events = []
    for _ in range(n):
        ts = rand_ts(base_time)
        events.append({
            "ts": ts,
            "ip": random.choice(NORMAL_IPS),
            "path": random.choice(HTTP_PATHS),
            "status": random.choice(HTTP_STATUSES),
            "size": random.randint(200, 15000),
        })
    events.sort(key=lambda e: e["ts"])
    return events


def write_access_log(events):
    path = os.path.join(OUT_DIR, "access.log")
    with open(path, "w") as f:
        for e in events:
            ts = e["ts"].strftime("%d/%b/%Y:%H:%M:%S +0000")
            line = f'{e["ip"]} - - [{ts}] "GET {e["path"]} HTTP/1.1" {e["status"]} {e["size"]}'
            f.write(line + "\n")
    return path


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic logs for LogSentry")
    parser.add_argument("--events", type=int, default=1500, help="Approx total normal events across all sources")
    parser.add_argument("--attack", choices=["none", "brute_force", "priv_escalation"], default="brute_force")
    args = parser.parse_args()

    os.makedirs(OUT_DIR, exist_ok=True)
    base_time = datetime.now() - timedelta(hours=6)

    per_source = max(50, args.events // 3)

    auth_events = gen_auth_events(per_source, base_time, args.attack)
    app_events = gen_app_events(per_source, base_time)
    access_events = gen_access_events(per_source, base_time)

    auth_path = write_auth_log(auth_events)
    app_path = write_app_log(app_events)
    access_path = write_access_log(access_events)

    print("Generated logs:")
    print(f"  {auth_path}  ({len(auth_events)} events)")
    print(f"  {app_path}   ({len(app_events)} events)")
    print(f"  {access_path} ({len(access_events)} events)")
    if args.attack != "none":
        print(f"\nInjected attack scenario: {args.attack} (source IP: {ATTACKER_IP})")


if __name__ == "__main__":
    main()
