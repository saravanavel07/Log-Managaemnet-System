"""
tests/test_ingest.py — Unit tests for log parsing logic.
Run with: pytest tests/
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ingest import parse_syslog_ts, AUTH_FAILED_RE, AUTH_SUCCESS_RE, SUDO_RE, ACCESS_RE


def test_auth_failed_regex_matches():
    line = "Aug  6 14:32:10 prod-web-01 sshd[4821]: Failed password for root from 185.220.101.47 port 51322 ssh2"
    m = AUTH_FAILED_RE.match(line)
    assert m is not None
    assert m.group("user") == "root"
    assert m.group("ip") == "185.220.101.47"


def test_auth_success_regex_matches():
    line = "Aug  6 14:33:15 prod-web-01 sshd[4822]: Accepted password for alice from 10.0.0.5 port 51400 ssh2"
    m = AUTH_SUCCESS_RE.match(line)
    assert m is not None
    assert m.group("user") == "alice"


def test_sudo_regex_matches():
    line = "Aug  6 14:34:00 prod-web-01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
    m = SUDO_RE.match(line)
    assert m is not None
    assert m.group("user") == "alice"


def test_access_log_regex_matches():
    line = '10.0.0.12 - - [06/Aug/2026:14:35:00 +0000] "GET /dashboard HTTP/1.1" 200 4321'
    m = ACCESS_RE.match(line)
    assert m is not None
    assert m.group("status") == "200"
    assert m.group("path") == "/dashboard"


def test_parse_syslog_ts_returns_iso_format():
    result = parse_syslog_ts("Aug  6 14:32:10")
    assert "T14:32:10" in result
