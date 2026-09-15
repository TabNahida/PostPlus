#!/usr/bin/env python3
"""Real-process HTTP framing, request-budget and graceful-stop regressions."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import threading
import time
import traceback

from integration import PASSWORD, ROOT, Suite


def receive_closed(sock, maximum=65536):
    """Require a complete response and graceful EOF, including on Windows."""
    chunks = []
    size = 0
    while True:
        chunk = sock.recv(8192)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        assert size <= maximum, "unexpectedly large HTTP error response"
        chunks.append(chunk)


def parse_response(wire):
    head, separator, body = wire.partition(b"\r\n\r\n")
    assert separator, f"incomplete HTTP response: {wire!r}"
    lines = head.split(b"\r\n")
    version, code, _ = lines[0].split(b" ", 2)
    assert version == b"HTTP/1.1", lines[0]
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        assert separator, line
        headers[name.lower()] = value.strip()
    assert int(headers[b"content-length"]) == len(body), "truncated HTTP body"
    assert headers[b"connection"].lower() == b"close", headers
    return int(code), headers, json.loads(body)


def raw_request(suite, service, request):
    with socket.create_connection(("127.0.0.1", suite.ports[service]), timeout=5) as sock:
        sock.sendall(request)
        # Do not half-close the client: these rejections must happen even when
        # the sender leaves its advertised request body unfinished.
        return parse_response(receive_closed(sock))


def request_bytes(path, body=b"", headers=(), method="POST"):
    lines = [f"{method} {path} HTTP/1.1", "Host: localhost", "Content-Type: application/json"]
    lines.extend(headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


def healthy(suite):
    status, _, result = suite.http("web", "GET", "/health")
    assert status == 200 and result == {"ok": True, "service": "web"}, (status, result)
    assert suite.children["web"].poll() is None, "web process exited"


def small_unauthorized_bodies(suite):
    # Cross the first 4 KiB socket read but remain inside the bounded 8 KiB
    # rejection drain. A close with these bytes unread used to reset the
    # connection on Windows and discard its 401 response.
    payload = json.dumps({"op": "list", "padding": "x" * 6000}).encode()
    for service, path in (("auth", "/rpc"), ("web", "/api/send")):
        for _ in range(3):
            status, _, result = raw_request(suite, service, request_bytes(
                path, payload, (f"Content-Length: {len(payload)}",)))
            assert status == 401 and result["ok"] is False, (service, status, result)
    healthy(suite)
    print("PASS small unauthorized RPC/Web bodies return complete 401 responses without TCP resets", flush=True)


def early_body_limits(suite, cookie, csrf):
    # Send headers only. Neither test allocates or uploads the claimed body.
    enormous = 1 << 40
    status, _, result = raw_request(suite, "web", request_bytes(
        "/api/send", headers=(f"Content-Length: {enormous}",)))
    assert status == 401 and result["ok"] is False, (status, result)
    status, _, result = raw_request(suite, "web", request_bytes(
        "/api/send", headers=(f"Cookie: {cookie}", f"Content-Length: {enormous}")))
    assert status == 403 and result["ok"] is False, (status, result)
    status, _, result = raw_request(suite, "web", request_bytes(
        "/api/login", headers=("Content-Length: 16385",)))
    assert status == 413 and result["ok"] is False, (status, result)
    # GET and DELETE never accept a request body, even for a signed-in user.
    for method, path, extra in (
        ("GET", "/health", ()),
        ("DELETE", "/api/messages/test-id", (f"Cookie: {cookie}", f"X-CSRF-Token: {csrf}")),
    ):
        status, _, result = raw_request(suite, "web", request_bytes(
            path, headers=(*extra, "Content-Length: 1"), method=method))
        assert status == 413 and result["ok"] is False, (method, status, result)
    healthy(suite)
    print("PASS authentication/CSRF precede large compose bodies; login/GET/DELETE body budgets enforced", flush=True)


def invalid_framing(suite):
    # An implementation that silently accepts these headers would wait for
    # the missing 50-byte body. It must instead return a complete 400 now.
    cases = (
        ("Content-Length: 50", "content-length: 50"),
        ("Content-Length: 50", "Content-Length: 51"),
        ("Content-Length: 50", "Transfer-Encoding: chunked"),
        ("Content-Length: 50", "Transfer-Encoding: identity"),
    )
    for headers in cases:
        status, _, result = raw_request(suite, "web", request_bytes("/api/login", headers=headers))
        assert status == 400 and result["ok"] is False, (headers, status, result)
    healthy(suite)
    print("PASS duplicate Content-Length and unsupported Transfer-Encoding rejected with 400", flush=True)


def json_depth(suite, username):
    def login_payload(array_depth):
        # Root object adds one level. Valid credentials ensure the >64 case
        # cannot pass merely because an unrelated field validation returns 400.
        credentials = json.dumps({"username": username, "password": PASSWORD,
                                  "quoted": "[" * 100 + '\\"{}]' * 100})
        return (credentials[:-1] + ',"extra":' + "[" * array_depth + "0" + "]" * array_depth + "}").encode()

    for array_depth, expected in ((63, 200), (64, 400), (100, 400)):
        payload = login_payload(array_depth)
        status, _, result = raw_request(suite, "web", request_bytes(
            "/api/login", payload, (f"Content-Length: {len(payload)}",)))
        assert status == expected, (array_depth, status, result)
        assert result["ok"] is (expected == 200), result
    healthy(suite)
    print("PASS JSON depth 64 accepted, deeper nesting rejected with 400, quoted brackets ignored", flush=True)


def slow_headers(suite):
    timeout = suite.config["timeout_seconds"]
    assert timeout == 2
    stop = threading.Event()
    sent = []
    with socket.create_connection(("127.0.0.1", suite.ports["web"]), timeout=4) as sock:
        start = time.monotonic()
        sock.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n")

        def trickle():
            index = 0
            while not stop.wait(0.3):
                try:
                    sock.sendall(f"X-Trickle-{index}: test\r\n".encode())
                    sent.append(time.monotonic())
                    index += 1
                except OSError:
                    return

        writer = threading.Thread(target=trickle, daemon=True)
        writer.start()
        try:
            healthy(suite)  # A slow client must not monopolize the listener.
            sock.settimeout(max(0.1, 4 - (time.monotonic() - start)))
            response = receive_closed(sock)
            elapsed = time.monotonic() - start
            assert len(sent) >= 2, "the request closed before exercising repeated header reads"
            assert elapsed < 4, f"HTTP headers reset the whole-request timeout: {elapsed:.2f}s"
            if response:
                status, _, result = parse_response(response)
                assert status in (400, 408, 503) and result["ok"] is False, (status, result)
        finally:
            stop.set()
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            writer.join(timeout=2)
            assert not writer.is_alive(), "slow-header test writer did not stop"
    healthy(suite)
    print(f"PASS continuously trickled HTTP headers close within the total request budget ({elapsed:.2f}s)", flush=True)


def graceful_stop(suite):
    if os.name == "nt":
        print("SKIP active-session SIGTERM regression on Windows (terminate uses TerminateProcess)", flush=True)
        return
    suite.start("smtp")
    child = suite.children["smtp"]
    stop = threading.Event()
    with socket.create_connection(("127.0.0.1", suite.ports["smtp"]), timeout=3) as sock:
        stream = sock.makefile("rb")
        assert stream.readline().startswith(b"220")
        sock.sendall(b"NOOP\r\n")
        assert stream.readline().startswith(b"250")

        def keep_active():
            while not stop.is_set():
                try:
                    sock.sendall(b"NOOP\r\n")
                    if not stream.readline().startswith(b"250"):
                        return
                except OSError:
                    return
                stop.wait(0.15)

        writer = threading.Thread(target=keep_active, daemon=True)
        writer.start()
        try:
            # Keep sending valid NOOPs throughout shutdown, so a missing
            # shutdown cancellation cannot accidentally pass via idle timeout.
            child.send_signal(signal.SIGTERM)
            try:
                code = child.wait(timeout=4)
            except subprocess.TimeoutExpired as error:
                raise AssertionError("active SMTP NOOP session prevented SIGTERM shutdown") from error
            assert code == 0, f"SMTP did not stop gracefully: exit {code}"
        finally:
            stop.set()
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            writer.join(timeout=2)
            stream.close()
            assert not writer.is_alive(), "SMTP keepalive test writer did not stop"
    healthy(suite)
    print("PASS SIGTERM exits while an SMTP client continually sends NOOP", flush=True)


def run(suite):
    suite.config.update(timeout_seconds=2)
    suite.save()
    suite.start("auth")
    suite.start("web")
    username = "http-security@localhost"
    assert suite.rpc("auth", op="create", username=username, password=PASSWORD)["ok"]
    status, headers, login = suite.http("web", "POST", "/api/login", {"username": username, "password": PASSWORD})
    assert status == 200, (status, login)
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    healthy(suite)
    small_unauthorized_bodies(suite)
    early_body_limits(suite, cookie, login["csrf"])
    invalid_framing(suite)
    json_depth(suite, username)
    slow_headers(suite)
    graceful_stop(suite)
    healthy(suite)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True, type=Path)
    args = parser.parse_args()
    directory = (ROOT / "build/test-runs" / f"http-security-{secrets.token_hex(6)}").resolve()
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
        print("All HTTP security tests passed", flush=True)
    except BaseException:
        print(f"Logs: {directory}", flush=True)
        traceback.print_exc()
        raise
    finally:
        suite.close()


if __name__ == "__main__":
    main()
