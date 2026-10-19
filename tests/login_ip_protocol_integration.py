#!/usr/bin/env python3
"""Cross-protocol, persistent source-IP protection at real TCP entry points."""
import argparse
import base64
import http.server
import json
from pathlib import Path
import secrets
import smtplib
import socket
import ssl
import threading
import time

from integration import PASSWORD, ROOT, Suite


USER = "security-owner@localhost"
WRONG = "security-wrong-password-never-log-this"
PUBLIC_LISTENERS = ("smtp", "submission", "smtps", "imap", "imaps", "pop3", "pop3s", "web", "admin")
TLS_LISTENERS = ("smtps", "imaps", "pop3s", "web", "admin")


def assert_closed(suite, name, payload=None, timeout=2):
    """A blocked peer gets no greeting/HTTP response, even without sending data."""
    with socket.create_connection(("127.0.0.1", suite.ports[name]), timeout=3) as sock:
        # Less than the configured protocol timeout: closing only after waiting
        # for a request/ClientHello does not satisfy the connection gate.
        sock.settimeout(timeout)
        try:
            if payload:
                sock.sendall(payload)
            data = sock.recv(4096)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            data = b""
        assert data == b"", (name, "Blocked TCP peer received protocol bytes", data)


def assert_tls_rejected(suite, name):
    context = ssl.create_default_context(cafile=str(ROOT / "tests/fixtures/localhost-test-only.crt"))
    with socket.create_connection(("127.0.0.1", suite.ports[name]), timeout=3) as sock:
        sock.settimeout(2)
        try:
            secured = context.wrap_socket(sock, server_hostname="localhost")
        except (ssl.SSLError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            return
        secured.close()
        raise AssertionError((name, "Blocked peer completed a TLS handshake"))


def assert_all_connections_blocked(suite):
    before = suite.rpc("auth", op="security_get", actor=USER)["bans"]
    for name in PUBLIC_LISTENERS:
        assert_closed(suite, name)
    for name in TLS_LISTENERS:
        assert_tls_rejected(suite, name)
    # A rejected SMTP peer cannot bypass the gate by pipelining unauthenticated
    # delivery, including bounce messages with an empty reverse path.
    queued = suite.rpc("storage", op="queue_list", limit=10)["jobs"]
    for sender in (b"remote@example.net", b""):
        assert_closed(suite, "smtp", b"EHLO attacker\r\nMAIL FROM:<" + sender + b">\r\nRCPT TO:<" + USER.encode() + b">\r\nDATA\r\nSubject: blocked\r\n\r\nbody\r\n.\r\n")
    assert suite.rpc("storage", op="queue_list", limit=10)["jobs"] == queued
    # Trusted RPC remains usable for recovery. Connection rejection must not
    # turn into additional authentication failures or extend an existing ban.
    after = suite.rpc("auth", op="security_get", actor=USER)["bans"]
    assert before == after, (before, after)


def assert_all_connections_allowed(suite):
    for name, greeting in (("smtp", b"220"), ("submission", b"220"), ("imap", b"* OK"), ("pop3", b"+OK")):
        sock, stream = connect(suite, name)
        try:
            assert stream.readline().startswith(greeting), name
        finally:
            stream.close()
            sock.close()
    for name in TLS_LISTENERS:
        sock, stream = connect(suite, name, encrypted=True)
        try:
            if name in ("web", "admin"):
                sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                assert stream.readline().startswith(b"HTTP/1.1 200"), name
            else:
                assert stream.readline().startswith(b"220" if name == "smtps" else b"* OK" if name == "imaps" else b"+OK"), name
        finally:
            stream.close()
            sock.close()


def unavailable_security_fails_closed(suite):
    suite.stop("auth")
    for name in PUBLIC_LISTENERS:
        # The auth RPC has a separate two-second deadline. Leave scheduler
        # tolerance while staying below the five-second protocol timeout.
        assert_closed(suite, name, timeout=4)

    class OldAuth(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.server.operations.append(request.get("op"))
            body = json.dumps(self.server.result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    class FixtureServer(http.server.ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = FixtureServer(("127.0.0.1", suite.ports["auth"]), OldAuth)
    server.operations = []
    server.result = {"ok": False, "error": "unknown operation"}
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
    worker.start()
    try:
        # A mixed-version or malformed auth reply must not accidentally treat a
        # truthy string or a missing explicit boolean success as permission.
        for result in ({"ok": False, "error": "unknown operation"}, {"ok": "true"}, {"valid": True}):
            server.result = result
            for name in ("smtp", "web"):
                assert_closed(suite, name)
        assert server.operations and set(server.operations) == {"security_check"}, server.operations
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        assert not worker.is_alive()
    suite.start("auth")
    assert_all_connections_allowed(suite)
    print("PASS public connections fail closed when auth is offline, old or malformed; recovery restores service without restarting listeners", flush=True)


def connect(suite, name, encrypted=False):
    sock = socket.create_connection(("127.0.0.1", suite.ports[name]), timeout=10)
    if encrypted:
        context = ssl.create_default_context(cafile=str(ROOT / "tests/fixtures/localhost-test-only.crt"))
        sock = context.wrap_socket(sock, server_hostname="localhost")
    return sock, sock.makefile("rb")


def imap_attempt(suite, username, password):
    sock, stream = connect(suite, "imap")
    try:
        assert stream.readline().startswith(b"* OK")
        sock.sendall(f'a LOGIN "{username}" "{password}"\r\n'.encode())
        response = stream.readline()
        assert response.startswith(b"a NO [AUTHENTICATIONFAILED]"), response
    finally:
        stream.close()
        sock.close()


def pop3_attempt(suite, username, password):
    sock, stream = connect(suite, "pop3")
    try:
        assert stream.readline().startswith(b"+OK")
        sock.sendall(f"USER {username}\r\n".encode())
        assert stream.readline().startswith(b"+OK")
        sock.sendall(f"PASS {password}\r\n".encode())
        response = stream.readline()
        assert response.startswith(b"-ERR [AUTH]"), response
    finally:
        stream.close()
        sock.close()


def smtp_attempt(suite, username, password, banned=False):
    connection = smtplib.SMTP("127.0.0.1", suite.ports["smtp"], local_hostname="localhost", timeout=10)
    with connection as client:
        client.ehlo()
        payload = base64.b64encode(f"\0{username}\0{password}".encode()).decode()
        code, response = client.docmd("AUTH", "PLAIN " + payload)
        assert code == (421 if banned else 535), code
        if banned:
            assert client.file.readline() == b""


def policy(suite, **changes):
    current = suite.rpc("auth", op="security_get", actor=USER)
    value = dict(current["policy"], **changes)
    result = suite.rpc("auth", op="security_policy_set", actor=USER, policy=value, revision=current["revision"])
    assert result["ok"], result
    return result


def unban(suite):
    result = suite.rpc("auth", op="security_unban", actor=USER, ip="127.0.0.1")
    assert result["ok"], result


def run(suite):
    suite.config.update(max_auth_attempts=20,
                        tls_certificate=str(ROOT / "tests/fixtures/localhost-test-only.crt"),
                        tls_private_key=str(ROOT / "tests/fixtures/localhost-test-only.key"))
    suite.save()
    for name in ("auth", "storage", "smtp", "imap", "pop3", "web", "admin"):
        suite.start(name)
    assert suite.rpc("auth", op="create", username=USER, password=PASSWORD, admin=True)["ok"]
    policy(suite, enabled=True, window_seconds=60, failure_threshold=10, unknown_user_threshold=3, ban_seconds=60, allowlist=[])
    assert_all_connections_allowed(suite)
    existing, existing_stream = connect(suite, "imap")
    assert existing_stream.readline().startswith(b"* OK")
    existing.sendall(f'a LOGIN "{USER}" "{PASSWORD}"\r\n'.encode())
    assert existing_stream.readline().startswith(b"a OK")

    # Every failure reconnects and uses a different protocol and nonexistent user.
    # The third one must reach the lower unknown-user threshold globally.
    imap_attempt(suite, "missing-imap@localhost", WRONG)
    pop3_attempt(suite, "missing-pop3@localhost", WRONG)
    smtp_attempt(suite, "missing-smtp@localhost", WRONG, banned=True)
    assert_all_connections_blocked(suite)
    try:
        existing.sendall(b"b NOOP\r\n")
        assert existing_stream.readline().startswith(b"b OK"), "An authenticated session was revoked by a later source-IP ban"
    finally:
        existing_stream.close()
        existing.close()
    print("PASS shared automatic bans close all nine public TCP listeners before banners, TLS or HTTP; established IMAP sessions remain usable", flush=True)

    suite.stop("auth")
    suite.start("auth")
    assert_all_connections_blocked(suite)
    unban(suite)
    assert_all_connections_allowed(suite)
    with smtplib.SMTP("127.0.0.1", suite.ports["smtp"], local_hostname="localhost", timeout=10) as client:
        client.ehlo()
        assert client.login(USER, PASSWORD)[0] == 235
    print("PASS bans survive auth-process restart, reject SMTP delivery and remain recoverable through trusted RPC; unban restores public connections", flush=True)

    # Known accounts need their own failure threshold; successful connections
    # cannot erase other failed password attempts from the same source.
    policy(suite, failure_threshold=3, unknown_user_threshold=3)
    imap_attempt(suite, USER, WRONG)
    with smtplib.SMTP("127.0.0.1", suite.ports["smtp"], local_hostname="localhost", timeout=10) as client:
        client.ehlo()
        assert client.login(USER, PASSWORD)[0] == 235
    pop3_attempt(suite, USER, WRONG)
    smtp_attempt(suite, USER, WRONG, banned=True)
    unban(suite)
    print("PASS known-account password guessing is blocked across protocol boundaries", flush=True)

    # Malformed authentication must not bypass accounting with a new connection.
    for protocol in ("imap", "pop3", "smtp"):
        sock, stream = connect(suite, protocol)
        try:
            greeting = stream.readline()
            if protocol == "imap":
                assert greeting.startswith(b"* OK")
                sock.sendall(b"x AUTHENTICATE PLAIN ***\r\n")
                assert stream.readline().startswith(b"x BAD")
            elif protocol == "pop3":
                assert greeting.startswith(b"+OK")
                sock.sendall(b"AUTH PLAIN ***\r\n")
                assert stream.readline().startswith(b"-ERR")
            else:
                assert greeting.startswith(b"220")
                sock.sendall(b"EHLO localhost\r\n")
                while stream.readline().startswith(b"250-"):
                    pass
                sock.sendall(b"AUTH PLAIN ***\r\n")
                assert stream.readline().startswith(b"421")
                assert stream.readline() == b""
        finally:
            stream.close()
            sock.close()
    assert_closed(suite, "imap")
    unban(suite)
    print("PASS malformed SASL attempts count toward the shared source-IP limit", flush=True)

    # Reject invalid USER values centrally too, without relying on PASS to arrive.
    policy(suite, failure_threshold=3, unknown_user_threshold=1)
    sock, stream = connect(suite, "pop3")
    try:
        assert stream.readline().startswith(b"+OK")
        sock.sendall(b"USER invalid-user-without-domain\r\n")
        assert stream.readline().startswith(b"-ERR [LOGIN-DELAY]")
        assert stream.readline() == b""
    finally:
        stream.close()
        sock.close()
    assert_closed(suite, "imap")
    unban(suite)
    print("PASS invalid usernames are logged and counted before POP3 PASS", flush=True)

    policy(suite, unknown_user_threshold=3, ban_seconds=1)
    imap_attempt(suite, "missing-expiry-1@localhost", WRONG)
    pop3_attempt(suite, "missing-expiry-2@localhost", WRONG)
    smtp_attempt(suite, "missing-expiry-3@localhost", WRONG, banned=True)
    time.sleep(1.1)
    assert_all_connections_allowed(suite)
    with smtplib.SMTP("127.0.0.1", suite.ports["smtp"], local_hostname="localhost", timeout=10) as client:
        client.ehlo()
        assert client.login(USER, PASSWORD)[0] == 235
    print("PASS temporary bans expire automatically and permit a correct password", flush=True)

    # Manual permanent bans share the same protocol boundary and survive restarts.
    result = suite.rpc("auth", op="security_ban", actor=USER, ip="127.0.0.1", permanent=True)
    assert result["ok"] and any(row["permanent"] and row["expires_at"] is None for row in result["bans"]), result
    suite.stop("auth"); suite.start("auth")
    assert_all_connections_blocked(suite)
    unban(suite)
    assert_all_connections_allowed(suite)
    with smtplib.SMTP("127.0.0.1", suite.ports["smtp"], local_hostname="localhost", timeout=10) as client:
        client.ehlo()
        assert client.login(USER, PASSWORD)[0] == 235
    print("PASS permanent bans persist across restart and reject all public connections and mail delivery until trusted administrative unban", flush=True)

    unavailable_security_fails_closed(suite)

    # Read durable structured logs as well as stdout: never store passwords,
    # service authorization tokens or complete SASL payloads in audit entries.
    log_paths = list(suite.directory.glob("*.log")) + list((suite.directory / "data/logs").glob("*.jsonl*"))
    logs = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in log_paths)
    assert WRONG not in logs and PASSWORD not in logs and suite.token not in logs
    assert "127.0.0.1" in logs
    assert "connection rejected ip=127.0.0.1 reason=ip_banned" in logs
    assert "connection rejected ip=127.0.0.1 reason=security_check_unavailable" in logs
    assert "unable to persist log entry" not in logs
    for protocol in ("imap", "pop3", "smtp"):
        assert "protocol=" + protocol in logs, protocol
    assert "missing-imap@localhost" in logs and "missing-pop3@localhost" in logs and "missing-smtp@localhost" in logs
    print("PASS authentication audit logs include source IP, protocol and attempted account without passwords or tokens", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("login-ip-protocols-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    except BaseException:
        print(f"Logs: {directory}", flush=True)
        raise
    finally:
        suite.close()


if __name__ == "__main__":
    main()
