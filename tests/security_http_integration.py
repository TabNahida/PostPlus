#!/usr/bin/env python3
"""IP bans on real HTTP peers, administrator controls and API scopes."""
import argparse
import http.client
from pathlib import Path
import secrets
import socket

from integration import PASSWORD, ROOT, Suite


def assert_http_blocked(suite, service, headers=None):
    # A newly accepted banned peer must be dropped without waiting for HTTP
    # headers; cookies, API keys and forwarding headers cannot reach routing.
    with socket.create_connection(("127.0.0.1", suite.ports[service]), timeout=3) as sock:
        sock.settimeout(2)
        try:
            response = sock.recv(4096)
        except (ConnectionResetError, ConnectionAbortedError):
            response = b""
        assert response == b"", (service, response)
    try:
        result = suite.http(service, "GET", "/api/session", headers=headers)
    except TimeoutError:
        raise AssertionError((service, "Banned HTTP peer waited for a request timeout"))
    except (OSError, http.client.HTTPException):
        return
    raise AssertionError((service, "Banned HTTP peer reached the request handler", result))


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
    for service in ("web", "admin"):
        assert_http_blocked(s, service, {**session, **spoof})
    view = s.rpc("auth", op="security_get", actor=admin)
    ban = next(item for item in view["bans"] if item["ip"] == "127.0.0.1")
    assert ban["unknown_failures"] >= 3 and ban["expires_at"] > ban["banned_at"] and ban["permanent"] is False
    assert all(item["ip"] not in ("198.51.100.77", "203.0.113.8") for item in view["bans"])
    assert s.rpc("auth", op="security_unban", actor=admin, ip="127.0.0.1")["ok"]
    assert request()[0] == 200, "Existing cookies must remain valid after an administrative unban."

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
    # Connection admission happens before cookie/API-key processing. Recovery
    # from the same source must use the trusted internal RPC interface.
    for service in ("web", "admin"):
        assert_http_blocked(s, service, session)
    assert_http_blocked(s, "admin", ro)
    s.stop("auth"); s.start("auth")
    assert_http_blocked(s, "admin", rw)
    assert s.rpc("auth", op="security_unban", actor=admin, ip="127.0.0.1")["ok"]
    assert request(headers=ro)[0] == 200
    assert request()[0] == 200
    print("PASS permanent bans validate input and drop new HTTP connections before cookie/API-key processing, survive restart, and recover through trusted RPC", flush=True)
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
    assert_http_blocked(s, "admin", ro)
    assert s.rpc("auth", op="security_unban", actor=admin, ip="127.0.0.1")["ok"]
    assert request(headers=ro)[0] == 200
    # Missing/invalid bearer framing is counted too; log messages never contain supplied secrets.
    secret = "malformed-secret-never-log-041"
    for index in range(2):
        status, _, _ = request(headers={"Authorization": "Bearer " + secret})
        assert status == (429 if index == 1 else 401)
    assert_http_blocked(s, "admin", session)
    assert s.rpc("auth", op="security_unban", actor=admin, ip="127.0.0.1")["ok"]
    # Malformed logins still have an auditable socket source and share the pool.
    for index in range(2):
        status, _, result = s.http("web", "POST", "/api/login", {"username": user, "password": False})
        assert status == (429 if index else 400), (status, result)
    assert_http_blocked(s, "web")
    assert s.rpc("auth", op="security_unban", actor=admin, ip="127.0.0.1")["ok"]
    logs = "\n".join(path.read_text(encoding="utf-8") for path in (s.directory / "data/logs").glob("auth.jsonl*"))
    assert "127.0.0.1" in logs and "webmail" in logs and "api" in logs
    for value in (PASSWORD, "Synthetic-wrong-password!", readonly, writer, secret):
        assert value not in logs, "Authentication logs exposed a credential"
    print("PASS HTTP socket IP attribution, shared connection bans, trusted recovery, policy revision/CSRF, scoped ban controls, API-key throttling and private audit logs", flush=True)


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
