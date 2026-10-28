#!/usr/bin/env python3
"""Recent security events are private, bounded, durable and cursor-paginated."""
import argparse
import json
from pathlib import Path
import secrets
import sqlite3
import time

from integration import PASSWORD, ROOT, Suite


def run(s):
    for service in ("auth", "storage", "web", "admin"):
        s.start(service)
    admin, user = "events-admin@localhost", "events-user@localhost"
    for username in (admin, user):
        assert s.rpc("auth", op="create", username=username, password=PASSWORD, admin=username == admin)["ok"]
    status, headers, login = s.http("admin", "POST", "/api/login", {"username": admin, "password": PASSWORD})
    assert status == 200
    session = {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": login["csrf"]}

    def events(query="", headers=None):
        return s.http("admin", "GET", "/api/admin/security/events" + query, headers=session if headers is None else headers)

    assert not s.rpc("auth", op="security_events", actor=user)["ok"]
    assert events(headers={})[0] == 401
    status, _, initial = events()
    assert status == 200 and initial["events"] == [] and initial["next_cursor"] is None and not initial["has_more"]
    policy = s.rpc("auth", op="security_get", actor=admin)
    changed = dict(policy["policy"], failure_threshold=3, unknown_user_threshold=10)
    assert s.rpc("auth", op="security_policy_set", actor=admin, revision=policy["revision"], policy=changed)["ok"]
    ip = "192.0.2.41"
    attempted = "attempt-must-not-appear@localhost"
    for _ in range(3):
        s.rpc("auth", op="security_failure", peer_ip=ip, protocol="imap", username=attempted)
    assert s.rpc("auth", op="security_check", peer_ip=ip, protocol="imap")["code"] == "ip_banned"
    database = s.directory / "data/auth.sqlite3"
    with sqlite3.connect(database) as db:
        before_bans = db.execute("SELECT * FROM security_bans ORDER BY ip").fetchall()
        before_attempts = db.execute("SELECT * FROM security_attempts ORDER BY ip").fetchall()
    for _ in range(40):
        assert s.rpc("auth", op="security_check", peer_ip=ip, protocol="imap")["code"] == "ip_banned"
    blocked = events()[2]
    assert blocked["blocked_event_interval_seconds"] == 30
    assert sum(row["kind"] == "auth_blocked" and row["ip"] == ip and row["protocol"] == "imap" and row["reason"] == "ip_banned" for row in blocked["events"]) == 1
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT * FROM security_bans ORDER BY ip").fetchall() == before_bans
        assert db.execute("SELECT * FROM security_attempts ORDER BY ip").fetchall() == before_attempts
    assert s.rpc("auth", op="security_unban", actor=admin, ip=ip)["ok"]
    assert s.rpc("auth", op="security_ban", actor=admin, ip=ip, permanent=True, reason="Private manual note not echoed by event feed")["ok"]
    status, _, latest = events()
    assert status == 200
    rows = latest["events"]
    assert rows[0]["kind"] == "ip_banned" and rows[0]["reason"] == "administrator" and rows[0]["expires_at"] is None
    assert rows[0]["actor"] == admin
    automatic = next(row for row in rows if row["kind"] == "ip_banned" and row["reason"] == "failed_authentication_attempts")
    assert automatic["ip"] == ip and automatic["protocol"] == "imap" and automatic["failures"] == 3
    assert sum(row["kind"] == "auth_failure" for row in rows) == 3
    assert any(row["kind"] == "auth_blocked" for row in rows)
    assert any(row["kind"] == "policy_changed" for row in rows)
    assert any(row["kind"] == "ip_unbanned" for row in rows)
    assert [int(row["id"]) for row in rows] == sorted((int(row["id"]) for row in rows), reverse=True)
    serialized = json.dumps(rows)
    assert attempted not in serialized and PASSWORD not in serialized and "Private manual note" not in serialized
    first = events("?limit=3")[2]
    assert len(first["events"]) == 3 and first["has_more"] and first["next_cursor"]
    # New rows do not shift an older page or cause duplicates across cursors.
    assert s.rpc("auth", op="security_unban", actor=admin, ip=ip)["ok"]
    second = events("?limit=3&cursor=" + first["next_cursor"])[2]
    assert all(int(row["id"]) < int(first["events"][-1]["id"]) for row in second["events"])
    assert not ({row["id"] for row in first["events"]} & {row["id"] for row in second["events"]})
    for query in ("?limit=0", "?limit=101", "?limit=true", "?cursor=bad", "?cursor=e1:-1", "?cursor=e1:999999999999999999999999", "?extra=value"):
        assert events(query)[0] == 400, query
    for invalid in (True, 0, 101, "50"):
        assert not s.rpc("auth", op="security_events", actor=admin, limit=invalid)["ok"]
    reader = s.rpc("auth", op="api_key_create", username=admin, name="Events only", permissions=["security:read"])["key"]
    logger = s.rpc("auth", op="api_key_create", username=admin, name="Logs only", permissions=["logs:read"])["key"]
    writer = s.rpc("auth", op="api_key_create", username=admin, name="Security write", permissions=["security:write"])["key"]
    assert events(headers={"Authorization": "Bearer " + reader})[0] == 200
    assert events(headers={"Authorization": "Bearer " + logger})[0] == 403
    assert events(headers={"Authorization": "Bearer " + writer})[0] == 403
    assert s.http("web", "GET", "/api/admin/security/events", headers=session)[0] == 404
    # Expiry and AbuseIPDB activity produce safe summaries rather than raw logs.
    with sqlite3.connect(database) as db:
        db.execute("INSERT OR REPLACE INTO security_bans VALUES(?,?,?,'expiry fixture',0,0)", ("192.0.2.42", int(time.time()) - 20, int(time.time()) - 10))
    s.rpc("auth", op="security_get", actor=admin)
    assert any(row["kind"] == "ban_expired" and row["ip"] == "192.0.2.42" for row in events()[2]["events"])
    abuse = s.rpc("auth", op="abuseipdb_get", actor=admin)
    api_secret = "event-test-key-must-not-leak"
    assert s.rpc("auth", op="abuseipdb_settings", actor=admin, revision=abuse["revision"], settings={"api_key_env": "", "api_key": api_secret})["ok"]
    raw_evidence = "Never echo report comments into the event feed"
    result = s.rpc("auth", op="abuseipdb_action", actor=admin, endpoint="report", input={"ip": "8.8.8.8", "categories": [18], "comment": raw_evidence})
    assert not result["ok"] and result["code"] == "abuseipdb_not_configured"
    before_restart = events()[2]
    assert before_restart["events"][0]["kind"] == "abuseipdb_report" and before_restart["events"][0]["outcome"] == "error"
    serialized = json.dumps(before_restart)
    assert api_secret not in serialized and raw_evidence not in serialized
    saved_ids = [row["id"] for row in before_restart["events"]]
    s.stop("auth"); s.start("auth")
    assert [row["id"] for row in events()[2]["events"]] == saved_ids
    # Bulk fixture models a long-running server, then a real observation must
    # keep storage within the advertised retention cap.
    fixture = json.dumps({"kind": "auth_failure", "ip": "192.0.2.43", "protocol": "smtp", "outcome": "failed", "reason": "invalid_credentials"})
    with sqlite3.connect(database) as db:
        db.executemany("INSERT INTO security_events(time,event) VALUES(?,?)", [(int(time.time()), fixture)] * 10005)
    s.rpc("auth", op="security_failure", peer_ip="192.0.2.44", protocol="pop3", username=attempted)
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 10000
    bounded = events("?limit=100")[2]
    assert len(bounded["events"]) == 100 and bounded["retention_limit"] == 10000
    assert bounded["events"][0]["ip"] == "192.0.2.44"
    print("PASS recent security events: immediate structured records, scopes, cursor stability, expiry, secret redaction, retention and restart persistence", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("security-events-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    finally:
        suite.close()
