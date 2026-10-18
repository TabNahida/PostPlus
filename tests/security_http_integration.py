#!/usr/bin/env python3
"""IP bans on real HTTP peers, administrator controls and API scopes."""
import argparse
import json
from pathlib import Path
import secrets
import time

from integration import PASSWORD, ROOT, Suite


def run(s):
    for service in ("auth", "storage", "web", "admin"):
        s.start(service)
    admin, user = "security-admin@localhost", "security-user@localhost"
    for username in (admin, user):
        assert s.rpc("auth", op="create", username=username, password=PASSWORD, admin=username == admin)["ok"]
    status, headers, login = s.http("admin", "POST", "/api/login", {"username": admin, "password": PASSWORD})
    assert status == 200, (status, login)
    session = {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": login["csrf"]}

    def request(method="GET", suffix="", body=None, headers=None):
        return s.http("admin", method, "/api/admin/security" + suffix, body, session if headers is None else headers)

    status, _, view = request()
    assert status == 200 and view["policy"]["enabled"] and view["policy"]["unknown_user_threshold"] == 5
    policy = {**view["policy"], "unknown_user_threshold": 3, "failure_threshold": 12, "ban_seconds": 60}
    status, _, current = request("PUT", "/policy", {"policy": policy, "revision": view["revision"]})
    assert status == 200 and not current["restart_required"]
    assert request("PUT", "/policy", {"policy": policy, "revision": view["revision"]})[0] == 409
    assert request("PUT", "/policy", {"policy": policy, "revision": current["revision"]}, {"Cookie": session["Cookie"]})[0] == 403
    assert request("POST", "/ban", {"ip": "bad address", "seconds": 60})[0] == 400
    assert request("POST", "/ban", {"ip": "192.0.2.99", "seconds": 60, "actor": admin})[0] == 400
    for body in ({"ip": "192.0.2.99", "permanent": "true"},
                 {"ip": "192.0.2.99", "permanent": True, "seconds": 60},
                 {"ip": "192.0.2.99", "permanent": False}):
        assert request("POST", "/ban", body)[0] == 400, body

    # Client-controlled JSON and forwarding headers cannot replace the socket peer.
    spoof = {"X-Forwarded-For": "198.51.100.77", "Forwarded": "for=203.0.113.8"}
    for index in range(3):
        status, headers, result = s.http("web", "POST", "/api/login", {
            "username": "missing@localhost", "password": "Synthetic-wrong-password!",
            "peer_ip": "198.51.100.77", "protocol": "admin"}, spoof)
        assert status == (429 if index == 2 else 401), (index, status, result)
    assert result["code"] == "ip_banned" and 1 <= result["retry_after"] <= 60
    assert int(headers["Retry-After"]) == result["retry_after"]
    status, _, result = s.http("admin", "POST", "/api/login", {"username": admin, "password": PASSWORD})
    assert status == 429, (status, result)
    status, _, view = request()
    assert status == 200, "An existing administrator session must remain available to recover/unban."
    ban = next(item for item in view["bans"] if item["ip"] == "127.0.0.1")
    assert ban["unknown_failures"] >= 3 and ban["expires_at"] > ban["banned_at"] and ban["permanent"] is False
    assert all(item["ip"] not in ("198.51.100.77", "203.0.113.8") for item in view["bans"])
    assert request("POST", "/unban", {"ip": "127.0.0.1"})[0] == 200

    readonly = s.rpc("auth", op="api_key_create", username=admin, name="Security view", permissions=["security:read"])["key"]
    writer = s.rpc("auth", op="api_key_create", username=admin, name="Security controls", permissions=["security:write"])["key"]
    ro, rw = {"Authorization": "Bearer " + readonly}, {"Authorization": "Bearer " + writer}
    assert request(headers=ro)[0] == 200
    assert request("POST", "/ban", {"ip": "192.0.2.99", "seconds": 60}, ro)[0] == 403
    assert request(headers=rw)[0] == 403
    assert request("POST", "/ban", {"ip": "192.0.2.99", "seconds": 60, "reason": "Synthetic admin ban"}, rw)[0] == 200
    assert request("POST", "/unban", {"ip": "192.0.2.99"}, rw)[0] == 200
    status, _, result = request("POST", "/ban", {"ip": "127.0.0.1", "permanent": True, "reason": "Permanent HTTP test"}, rw)
    assert status == 200, result
    ban = next(item for item in result["bans"] if item["ip"] == "127.0.0.1")
    assert ban["permanent"] is True and ban["expires_at"] is None, ban
    # Existing cookie sessions remain a recovery path; new passwords and API keys stay blocked.
    assert request()[0] == 200
    for service in ("web", "admin"):
        status, headers, result = s.http(service, "POST", "/api/login", {"username": admin, "password": PASSWORD})
        assert status == 429 and result["code"] == "ip_banned" and result["permanent"] is True, (status, result)
        assert "retry_after" not in result and "Retry-After" not in headers
    status, headers, result = request(headers=ro)
    assert status == 429 and result["permanent"] is True and "retry_after" not in result
    assert "Retry-After" not in headers
    s.stop("auth"); s.start("auth")
    status, headers, result = request(headers=rw)
    assert status == 429 and result["permanent"] is True and "Retry-After" not in headers
    assert request("POST", "/unban", {"ip": "127.0.0.1"})[0] == 200
    assert request(headers=ro)[0] == 200
    print("PASS permanent bans require explicit valid input, block passwords/API keys without a finite retry time, survive restart, and permit cookie-session recovery", flush=True)
    status, user_headers, _ = s.http("admin", "POST", "/api/login", {"username": user, "password": PASSWORD})
    assert status == 403
    status, user_headers, _ = s.http("web", "POST", "/api/login", {"username": user, "password": PASSWORD})
    assert status == 200
    assert s.http("web", "GET", "/api/admin/security", headers={"Cookie": user_headers["Set-Cookie"].split(";", 1)[0]})[0] == 404

    # Invalid API keys share the failure pool and are stopped before credentials can be checked.
    view = request()[2]
    policy = {**view["policy"], "failure_threshold": 2, "unknown_user_threshold": 10}
    assert request("PUT", "/policy", {"policy": policy, "revision": view["revision"]})[0] == 200
    for index in range(2):
        status, headers, result = request(headers={"Authorization": "Bearer " + "pp_" + "0" * 64})
        assert status == (429 if index == 1 else 401), (status, result)
    assert request(headers=ro)[0] == 429
    assert request("POST", "/unban", {"ip": "127.0.0.1"})[0] == 200
    assert request(headers=ro)[0] == 200
    # Missing/invalid bearer framing is counted too; log messages never contain supplied secrets.
    secret = "malformed-secret-never-log-041"
    for index in range(2):
        status, _, _ = request(headers={"Authorization": "Bearer " + secret})
        assert status == (429 if index == 1 else 401)
    assert request("POST", "/unban", {"ip": "127.0.0.1"})[0] == 200
    # Malformed logins still have an auditable socket source and share the pool.
    for index in range(2):
        status, _, result = s.http("web", "POST", "/api/login", {"username": user, "password": False})
        assert status == (429 if index else 400), (status, result)
    assert request("POST", "/unban", {"ip": "127.0.0.1"})[0] == 200
    logs = "\n".join(path.read_text(encoding="utf-8") for path in (s.directory / "data/logs").glob("auth.jsonl*"))
    assert "127.0.0.1" in logs and "webmail" in logs and "api" in logs
    for value in (PASSWORD, "Synthetic-wrong-password!", readonly, writer, secret):
        assert value not in logs, "Authentication logs exposed a credential"
    print("PASS HTTP socket IP attribution, shared bans, recovery session, policy revision/CSRF, scoped ban controls, API-key throttling and private audit logs", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("security-http-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    finally:
        suite.close()
