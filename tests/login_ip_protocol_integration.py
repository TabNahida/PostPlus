#!/usr/bin/env python3
"""Cross-protocol, persistent source-IP authentication protection on real sockets."""
import argparse
import base64
from pathlib import Path
import secrets
import smtplib
import socket
import ssl
import time

from integration import PASSWORD, ROOT, Suite


USER = "security-owner@localhost"
WRONG = "security-wrong-password-never-log-this"


def connect(suite, name, encrypted=False):
    sock = socket.create_connection(("127.0.0.1", suite.ports[name]), timeout=10)
    if encrypted:
        context = ssl.create_default_context(cafile=str(ROOT / "tests/fixtures/localhost-test-only.crt"))
        sock = context.wrap_socket(sock, server_hostname="localhost")
    return sock, sock.makefile("rb")


def imap_attempt(suite, username, password, banned=False, encrypted=False, permanent=False):
    sock, stream = connect(suite, "imaps" if encrypted else "imap", encrypted)
    try:
        assert stream.readline().startswith(b"* OK")
        sock.sendall(f'a LOGIN "{username}" "{password}"\r\n'.encode())
        response = stream.readline()
        if banned:
            assert response.startswith(b"a NO [UNAVAILABLE]"), response
            if permanent:
                assert b"contact administrator" in response and b"try again later" not in response, response
            assert stream.readline().startswith(b"* BYE")
            assert stream.readline() == b""
        else:
            assert response.startswith(b"a NO [AUTHENTICATIONFAILED]"), response
    finally:
        stream.close()
        sock.close()


def pop3_attempt(suite, username, password, banned=False, encrypted=False, permanent=False):
    sock, stream = connect(suite, "pop3s" if encrypted else "pop3", encrypted)
    try:
        assert stream.readline().startswith(b"+OK")
        sock.sendall(f"USER {username}\r\n".encode())
        assert stream.readline().startswith(b"+OK")
        sock.sendall(f"PASS {password}\r\n".encode())
        response = stream.readline()
        assert response.startswith(b"-ERR [LOGIN-DELAY]" if banned else b"-ERR [AUTH]"), response
        if permanent:
            assert b"contact administrator" in response and b"try again later" not in response, response
        if banned:
            assert stream.readline() == b""
    finally:
        stream.close()
        sock.close()


def smtp_attempt(suite, username, password, banned=False, encrypted=False, permanent=False):
    if encrypted:
        context = ssl.create_default_context(cafile=str(ROOT / "tests/fixtures/localhost-test-only.crt"))
        connection = smtplib.SMTP_SSL("localhost", suite.ports["smtps"], local_hostname="localhost", context=context, timeout=10)
    else:
        connection = smtplib.SMTP("127.0.0.1", suite.ports["smtp"], local_hostname="localhost", timeout=10)
    with connection as client:
        client.ehlo()
        payload = base64.b64encode(f"\0{username}\0{password}".encode()).decode()
        code, response = client.docmd("AUTH", "PLAIN " + payload)
        assert code == (421 if banned else 535), code
        if permanent:
            assert b"contact administrator" in response and b"try again later" not in response, response
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
    for name in ("auth", "storage", "smtp", "imap", "pop3"):
        suite.start(name)
    assert suite.rpc("auth", op="create", username=USER, password=PASSWORD, admin=True)["ok"]
    policy(suite, enabled=True, window_seconds=60, failure_threshold=10, unknown_user_threshold=3, ban_seconds=60, allowlist=[])
    existing, existing_stream = connect(suite, "imap")
    assert existing_stream.readline().startswith(b"* OK")
    existing.sendall(f'a LOGIN "{USER}" "{PASSWORD}"\r\n'.encode())
    assert existing_stream.readline().startswith(b"a OK")

    # Every failure reconnects and uses a different protocol and nonexistent user.
    # The third one must reach the lower unknown-user threshold globally.
    imap_attempt(suite, "missing-imap@localhost", WRONG)
    pop3_attempt(suite, "missing-pop3@localhost", WRONG)
    smtp_attempt(suite, "missing-smtp@localhost", WRONG, banned=True)
    imap_attempt(suite, USER, PASSWORD, banned=True)
    pop3_attempt(suite, USER, PASSWORD, banned=True)
    # Encryption must retain the real socket source rather than bypass the ban.
    imap_attempt(suite, USER, PASSWORD, banned=True, encrypted=True)
    pop3_attempt(suite, USER, PASSWORD, banned=True, encrypted=True)
    smtp_attempt(suite, USER, PASSWORD, banned=True)
    smtp_attempt(suite, USER, PASSWORD, banned=True, encrypted=True)
    try:
        existing.sendall(b"b NOOP\r\n")
        assert existing_stream.readline().startswith(b"b OK"), "An authenticated session was revoked by a later source-IP ban"
    finally:
        existing_stream.close()
        existing.close()
    print("PASS unknown-user failures aggregate across SMTP, IMAP, POP3 and reconnects; a ban also blocks valid passwords over TLS", flush=True)

    suite.stop("auth")
    suite.start("auth")
    imap_attempt(suite, USER, PASSWORD, banned=True)
    # Internet delivery must keep working: a ban targets AUTH, not SMTP reception.
    with smtplib.SMTP("127.0.0.1", suite.ports["smtp"], local_hostname="localhost", timeout=10) as client:
        assert client.sendmail("remote@example.net", [USER], b"Subject: incoming while banned\r\n\r\nbody\r\n") == {}
    assert len(suite.rpc("storage", op="queue_list", limit=10)["jobs"]) == 1
    unban(suite)
    with smtplib.SMTP("127.0.0.1", suite.ports["smtp"], local_hostname="localhost", timeout=10) as client:
        client.ehlo()
        assert client.login(USER, PASSWORD)[0] == 235
    print("PASS bans survive auth-process restart, inbound SMTP remains available and administrative unban restores login", flush=True)

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
    imap_attempt(suite, USER, PASSWORD, banned=True)
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
    imap_attempt(suite, USER, PASSWORD, banned=True)
    unban(suite)
    print("PASS invalid usernames are logged and counted before POP3 PASS", flush=True)

    policy(suite, unknown_user_threshold=3, ban_seconds=1)
    imap_attempt(suite, "missing-expiry-1@localhost", WRONG)
    pop3_attempt(suite, "missing-expiry-2@localhost", WRONG)
    smtp_attempt(suite, "missing-expiry-3@localhost", WRONG, banned=True)
    time.sleep(1.1)
    with smtplib.SMTP("127.0.0.1", suite.ports["smtp"], local_hostname="localhost", timeout=10) as client:
        client.ehlo()
        assert client.login(USER, PASSWORD)[0] == 235
    print("PASS temporary bans expire automatically and permit a correct password", flush=True)

    # Manual permanent bans share the same protocol boundary and survive restarts.
    result = suite.rpc("auth", op="security_ban", actor=USER, ip="127.0.0.1", permanent=True)
    assert result["ok"] and any(row["permanent"] and row["expires_at"] is None for row in result["bans"]), result
    suite.stop("auth"); suite.start("auth")
    for encrypted in (False, True):
        imap_attempt(suite, USER, PASSWORD, banned=True, encrypted=encrypted, permanent=True)
        pop3_attempt(suite, USER, PASSWORD, banned=True, encrypted=encrypted, permanent=True)
        smtp_attempt(suite, USER, PASSWORD, banned=True, encrypted=encrypted, permanent=True)
    with smtplib.SMTP("127.0.0.1", suite.ports["smtp"], local_hostname="localhost", timeout=10) as client:
        assert client.sendmail("remote@example.net", [USER], b"Subject: incoming while permanently banned\r\n\r\nbody\r\n") == {}
    unban(suite)
    with smtplib.SMTP("127.0.0.1", suite.ports["smtp"], local_hostname="localhost", timeout=10) as client:
        client.ehlo()
        assert client.login(USER, PASSWORD)[0] == 235
    print("PASS permanent bans block valid logins across SMTP/IMAP/POP3 and TLS, preserve inbound mail, and recover after unban", flush=True)

    # Read durable structured logs as well as stdout: never store passwords,
    # service authorization tokens or complete SASL payloads in audit entries.
    log_paths = list(suite.directory.glob("*.log")) + list((suite.directory / "data/logs").glob("*.jsonl*"))
    logs = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in log_paths)
    assert WRONG not in logs and PASSWORD not in logs and suite.token not in logs
    assert "127.0.0.1" in logs
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
