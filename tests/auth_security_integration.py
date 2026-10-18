#!/usr/bin/env python3
"""Durable cross-service IP login policy, canonical addresses, and concurrency."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import secrets
import sqlite3
import time

from integration import PASSWORD, ROOT, Suite


ADMIN = "security-admin@localhost"
USER = "security-user@localhost"


def view(s):
    result = s.rpc("auth", op="security_get", actor=ADMIN)
    assert result["ok"] and not result["restart_required"], result
    return result


def policy(s, **changes):
    current = view(s)
    result = s.rpc("auth", op="security_policy_set", actor=ADMIN,
                   revision=current["revision"], policy=dict(current["policy"], **changes))
    assert result["ok"], result
    return result


def failure(s, ip, username="absent@localhost", protocol="imap"):
    return s.rpc("auth", op="security_failure", peer_ip=ip, protocol=protocol, username=username)


def blocked(result, permanent=False):
    assert not result["ok"] and result["code"] == "ip_banned", result
    assert result["permanent"] is permanent, result
    if permanent:
        assert "retry_after" not in result and "administrator" in result["error"], result
    else:
        assert result["retry_after"] >= 1, result
    assert result.get("valid") is False, result


def run(s):
    s.start("auth")
    for username in (ADMIN, USER):
        assert s.rpc("auth", op="create", username=username, password=PASSWORD, admin=username == ADMIN)["ok"]
    initial = view(s)
    assert initial["policy"] == dict(enabled=True, window_seconds=300, failure_threshold=20,
                                     unknown_user_threshold=5, ban_seconds=900, allowlist=[]), initial
    assert initial["revision"] == 1 and initial["bans"] == []
    assert not s.rpc("auth", op="security_get", actor=USER)["ok"]
    assert not s.rpc("auth", op="security_unban", actor=USER, ip="192.0.2.1")["ok"]
    assert not s.rpc("auth", op="security_ban", actor=USER, ip="192.0.2.1", permanent=True)["ok"]
    for change in (dict(window_seconds=0), dict(failure_threshold=True), dict(allowlist=["0.0.0.0/33"]),
                   dict(allowlist=["example.com"]), dict(allowlist=["::1%eth0"]), dict(extra=True)):
        result = s.rpc("auth", op="security_policy_set", actor=ADMIN, revision=1,
                       policy=dict(initial["policy"], **change))
        assert result["code"] == "invalid_security_policy", result
    updated = policy(s, unknown_user_threshold=3, failure_threshold=5, ban_seconds=30)
    conflict = s.rpc("auth", op="security_policy_set", actor=ADMIN, revision=1, policy=initial["policy"])
    assert conflict["code"] == "security_policy_conflict" and conflict["revision"] == updated["revision"]
    assert policy(s)["revision"] == updated["revision"]  # unchanged save is idempotent

    ip = "192.0.2.10"
    assert failure(s, ip)["error"] == "invalid credentials"
    assert failure(s, "::ffff:192.0.2.10", protocol="smtp")["error"] == "invalid credentials"
    blocked(failure(s, ip, protocol="pop3"))
    banned = view(s)["bans"][0]
    assert banned["ip"] == ip and banned["unknown_failures"] == 3 and banned["failures"] == 3, banned
    assert banned["reason"] == "unknown_account_attempts" and banned["permanent"] is False
    blocked(s.rpc("auth", op="verify", peer_ip=ip, protocol="webmail", username=USER, password=PASSWORD))
    blocked(s.rpc("auth", op="api_key_verify", peer_ip=ip, protocol="api", key="invalid"))
    # A restart preserves both bans and the live policy without a DB version bump.
    s.stop("auth"); s.start("auth")
    blocked(s.rpc("auth", op="verify", peer_ip=ip, protocol="admin", username=ADMIN, password=PASSWORD))
    assert view(s)["policy"]["unknown_user_threshold"] == 3
    with sqlite3.connect(s.directory / "data/auth.sqlite3") as database:
        assert database.execute("PRAGMA user_version").fetchone()[0] == 4
    assert s.rpc("auth", op="verify", username=ADMIN, password=PASSWORD)["ok"]  # CLI recovery
    assert s.rpc("auth", op="security_unban", actor=ADMIN, ip="::ffff:192.0.2.10")["ok"]
    assert s.rpc("auth", op="verify", peer_ip=ip, protocol="imap", username=USER, password=PASSWORD)["ok"]
    print("PASS durable canonical cross-protocol bans, admin authorization, conflicts, and CLI recovery", flush=True)

    # Successful traffic cannot wash out unrelated failures on the same IP.
    assert not failure(s, ip)["ok"]
    assert s.rpc("auth", op="verify", peer_ip=ip, protocol="pop3", username=USER, password=PASSWORD)["ok"]
    assert not failure(s, ip, "different@localhost")["ok"]
    blocked(failure(s, ip, "third@localhost"))
    assert s.rpc("auth", op="security_unban", actor=ADMIN, ip=ip)["ok"]
    # Known usernames and invalid API keys aggregate in the same failure window.
    policy(s, unknown_user_threshold=8, failure_threshold=3)
    assert not failure(s, ip, USER)["ok"]
    assert s.rpc("auth", op="api_key_verify", peer_ip=ip, protocol="api", key="pp_" + "0" * 64)["valid"] is False
    blocked(s.rpc("auth", op="verify", peer_ip=ip, protocol="imap", username=USER, password="wrong password"))
    assert view(s)["bans"][0]["reason"] == "failed_authentication_attempts"
    anonymous_ip = "203.0.113.30"
    for _ in range(2):
        assert s.rpc("auth", op="security_failure", peer_ip=anonymous_ip, protocol="api")["error"] == "invalid credentials"
    with sqlite3.connect(s.directory / "data/auth.sqlite3") as database:
        assert database.execute("SELECT failures,unknown_failures FROM security_attempts WHERE ip=?", (anonymous_ip,)).fetchone() == (2, 0)
    blocked(s.rpc("auth", op="security_failure", peer_ip=anonymous_ip, protocol="api"))
    assert next(item for item in view(s)["bans"] if item["ip"] == anonymous_ip)["reason"] == "failed_authentication_attempts"
    print("PASS successes preserve failures and API-key/password failures aggregate", flush=True)

    # CIDR allowlist bypasses automatic protection, not explicit manual bans.
    policy(s, allowlist=["198.51.100.0/24", "2001:db8::/32", "203.0.113.7"])
    for address in ("198.51.100.23", "2001:0db8:0:0:0:0:0:7", "203.0.113.7"):
        for _ in range(9):
            result = failure(s, address)
            assert result.get("code") != "ip_banned", result
    assert s.rpc("auth", op="security_ban", actor=ADMIN, ip="2001:db8::7", seconds=2, reason="administrator test")["ok"]
    blocked(failure(s, "2001:0db8::7"))
    permanent_ip = "198.51.100.50"  # Explicit bans also override an automatic-ban allowlist.
    result = s.rpc("auth", op="security_ban", actor=ADMIN, ip="::ffff:" + permanent_ip,
                   permanent=True, reason="Permanent administrator test")
    assert result["ok"], result
    permanent_row = next(row for row in result["bans"] if row["ip"] == permanent_ip)
    assert permanent_row["permanent"] is True and permanent_row["expires_at"] is None, permanent_row
    time.sleep(2.1)
    assert failure(s, "2001:db8::7").get("code") != "ip_banned"
    assert any(row["ip"] == permanent_ip and row["permanent"] for row in view(s)["bans"])
    s.stop("auth"); s.start("auth")
    for protocol in ("webmail", "admin", "smtp", "imap", "pop3"):
        blocked(s.rpc("auth", op="verify", peer_ip=permanent_ip, protocol=protocol,
                      username=USER, password=PASSWORD), permanent=True)
    blocked(s.rpc("auth", op="api_key_verify", peer_ip=permanent_ip, protocol="api", key="invalid"), permanent=True)
    policy(s, enabled=False)
    blocked(failure(s, permanent_ip), permanent=True)
    policy(s, enabled=True)
    with sqlite3.connect(s.directory / "data/auth.sqlite3") as database:
        assert database.execute("SELECT expires_at FROM security_bans WHERE ip=?", (permanent_ip,)).fetchone() == (0,)
    for invalid in (dict(), dict(permanent=1), dict(permanent="true"), dict(permanent=None),
                    dict(permanent=True, seconds=60), dict(permanent=True, seconds=None),
                    dict(permanent=False), dict(seconds=0), dict(seconds=-1), dict(seconds=True),
                    dict(seconds=1.5), dict(seconds=604801), dict(seconds=2**64-1)):
        result = s.rpc("auth", op="security_ban", actor=ADMIN, ip=permanent_ip, **invalid)
        assert not result["ok"] and result["code"] == "invalid_security_policy", (invalid, result)
    blocked(failure(s, permanent_ip), permanent=True)  # Invalid edits cannot remove a permanent ban.
    assert s.rpc("auth", op="security_unban", actor=ADMIN, ip="::ffff:" + permanent_ip)["ok"]
    assert s.rpc("auth", op="verify", peer_ip=permanent_ip, protocol="imap", username=USER, password=PASSWORD)["ok"]
    # Editing either ban mode replaces the previous mode without stale expiry state.
    assert s.rpc("auth", op="security_ban", actor=ADMIN, ip=permanent_ip, permanent=False, seconds=60)["ok"]
    assert s.rpc("auth", op="security_ban", actor=ADMIN, ip=permanent_ip, permanent=True)["ok"]
    blocked(failure(s, permanent_ip), permanent=True)
    # Expiry uses integer Unix seconds; one second can elapse at the next
    # clock tick before the following RPC, especially on a Debug runner.
    assert s.rpc("auth", op="security_ban", actor=ADMIN, ip=permanent_ip, seconds=3)["ok"]
    blocked(failure(s, permanent_ip))
    time.sleep(3.1)
    assert s.rpc("auth", op="verify", peer_ip=permanent_ip, protocol="imap", username=USER, password=PASSWORD)["ok"]
    print("PASS permanent manual bans survive expiry sweeps/restarts, override allowlists, reject invalid edits, and recover by unban or timed replacement", flush=True)
    assert not s.rpc("auth", op="security_ban", actor=ADMIN, ip="127.0.0.1:25", seconds=2)["ok"]
    assert not s.rpc("auth", op="security_unban", actor=ADMIN, ip="not-an-IP")["ok"]
    status, _, result = s.http("auth", "POST", "/rpc", dict(op="verify", peer_ip="hostname", username=USER, password=PASSWORD),
                             {"Authorization": f"Bearer {s.token}"})
    assert status == 400, (status, result)
    print("PASS IPv4/IPv6 CIDR allowlist, manual override, expiry, and invalid addresses", flush=True)

    policy(s, allowlist=[], failure_threshold=20, unknown_user_threshold=4, ban_seconds=30)
    concurrent_ip = "203.0.113.20"
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: failure(s, concurrent_ip), range(24)))
    assert any(result.get("code") == "ip_banned" for result in results), results
    rows = [row for row in view(s)["bans"] if row["ip"] == concurrent_ip]
    assert len(rows) == 1 and rows[0]["unknown_failures"] == 4 and rows[0]["failures"] == 4, rows
    policy(s, unknown_user_threshold=20, failure_threshold=3)
    hash_ip = "203.0.113.24"
    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(lambda _: s.rpc("auth", op="verify", peer_ip=hash_ip, protocol="imap",
                                                   username=USER, password="Synthetic-wrong-password!"), range(6)))
    assert any(result.get("code") == "ip_banned" for result in results), results
    rows = [row for row in view(s)["bans"] if row["ip"] == hash_ip]
    assert len(rows) == 1 and rows[0]["failures"] == 3 and rows[0]["unknown_failures"] == 0, rows
    policy(s, unknown_user_threshold=4, failure_threshold=20)
    # Partial counters survive restart, not only completed bans.
    durable_ip = "203.0.113.21"
    for _ in range(3): assert failure(s, durable_ip).get("code") != "ip_banned"
    s.stop("auth"); s.start("auth")
    blocked(failure(s, durable_ip))
    # Malformed identities receive the same external error and count as unknown.
    malformed_ip = "203.0.113.22"
    for _ in range(3):
        assert failure(s, malformed_ip, "bad\r\nusername")["error"] == "invalid credentials"
    blocked(failure(s, malformed_ip, "bad\r\nusername"))
    policy(s, enabled=False)
    for _ in range(8): assert failure(s, "203.0.113.23").get("code") != "ip_banned"
    blocked(failure(s, concurrent_ip))  # disabling automatic bans preserves explicit current pool
    print("PASS atomic concurrent thresholds, durable counters, malformed identities, and disabled automatic policy", flush=True)

    # Fill this isolated fixture directly to test the fixed ban-pool bound
    # without producing 10,000 administrator API requests or audit events.
    s.stop("auth")
    with sqlite3.connect(s.directory / "data/auth.sqlite3") as database:
        database.execute("DELETE FROM security_bans")
        database.executemany("INSERT INTO security_bans VALUES(?,?,0,'capacity fixture',0,0)",
                             ((f"10.99.{index // 256}.{index % 256}", int(time.time())) for index in range(10000)))
    s.start("auth")
    assert len(view(s)["bans"]) == 10000
    result = s.rpc("auth", op="security_ban", actor=ADMIN, ip="192.0.2.250", permanent=True)
    assert not result["ok"] and result["field"] == "ip", result
    blocked(s.rpc("auth", op="verify", peer_ip="10.99.0.1", protocol="imap", username=USER, password=PASSWORD), permanent=True)
    # Updating a full pool's existing address does not consume another slot.
    result = s.rpc("auth", op="security_ban", actor=ADMIN, ip="10.99.0.1", seconds=3)
    assert result["ok"] and len(result["bans"]) == 10000, result
    time.sleep(3.1)
    result = s.rpc("auth", op="security_ban", actor=ADMIN, ip="192.0.2.250", permanent=True)
    assert result["ok"] and len(result["bans"]) == 10000, result
    assert s.rpc("auth", op="security_unban", actor=ADMIN, ip="192.0.2.250")["ok"]
    result = s.rpc("auth", op="security_ban", actor=ADMIN, ip="192.0.2.251", permanent=True)
    assert result["ok"] and len(result["bans"]) == 10000, result
    s.stop("auth")
    with sqlite3.connect(s.directory / "data/auth.sqlite3") as database:
        database.execute("DELETE FROM security_bans")
    s.start("auth")
    print("PASS permanent bans consume bounded pool capacity; replacement, timed expiry, and unban free usable capacity", flush=True)

    contents = (s.directory / "auth.log").read_text(errors="replace")
    for expected in ("ip=192.0.2.10", "protocol=imap", "protocol=smtp", "protocol=pop3", "login success", "login blocked",
                     "login IP banned", "login IP unbanned", "login ban expired", "login security policy changed", "ip=internal"):
        assert expected in contents, expected
    assert PASSWORD not in contents and s.token not in contents and "wrong password" not in contents
    assert "bad\r\nusername" not in contents and "bad??username" in contents
    with sqlite3.connect(s.directory / "data/auth.sqlite3") as database:
        assert database.execute("SELECT COUNT(*) FROM security_attempts").fetchone()[0] <= 10000
        assert database.execute("SELECT COUNT(*) FROM security_bans").fetchone()[0] <= 10000
    print("PASS bounded durable state and source IP audit without credentials or log injection", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("auth-security-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    finally:
        suite.close()
