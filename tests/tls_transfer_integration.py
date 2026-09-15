#!/usr/bin/env python3
"""TLS protocol and smarthost integration; Python standard library, loopback only."""
import argparse
import base64
import http.client
import imaplib
import json
import os
from pathlib import Path
import poplib
import secrets
import smtplib
import socket
import ssl
import threading
import time
import traceback

from integration import PASSWORD, ROOT, Suite

CERTIFICATE = ROOT / "tests/fixtures/localhost-test-only.crt"
PRIVATE_KEY = ROOT / "tests/fixtures/localhost-test-only.key"


def client_context():
    context = ssl.create_default_context(cafile=str(CERTIFICATE))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def https(suite, method, path, body=None, headers=None):
    connection = http.client.HTTPSConnection("localhost", suite.ports["web"],
                                             context=client_context(), timeout=10)
    try:
        payload = None if body is None else json.dumps(body)
        connection.request(method, path, payload, {"Content-Type": "application/json", **(headers or {})})
        response = connection.getresponse()
        content = response.read()
        result = json.loads(content) if "json" in response.getheader("Content-Type", "") else content
        return response.status, dict(response.getheaders()), result
    finally:
        connection.close()


def smtp_reply(stream):
    lines = []
    while True:
        line = stream.readline(8192)
        assert line and len(line) < 8192, "incomplete SMTP reply"
        lines.append(line)
        if len(line) < 4 or line[3:4] != b"-":
            return b"".join(lines)


def plaintext_after_starttls_is_fatal(suite):
    with socket.create_connection(("127.0.0.1", suite.ports["smtp"]), timeout=5) as connection:
        connection.settimeout(3)
        stream = connection.makefile("rb")
        try:
            assert smtp_reply(stream).startswith(b"220 ")
            connection.sendall(b"EHLO localhost\r\n")
            assert b"STARTTLS" in smtp_reply(stream)
            connection.sendall(b"STARTTLS\r\n")
            assert smtp_reply(stream).startswith(b"220 ")
            connection.sendall(b"AUTH PLAIN invalid-plaintext\r\n")
            received = b""
            while True:
                try:
                    chunk = connection.recv(4096)
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                received += chunk
                assert len(received) < 16384
            assert b"235 " not in received and b"334 " not in received
        finally:
            stream.close()


def check_protocol_tls(suite):
    alice, bob = "alice@localhost", "bob@localhost"
    for name in ("auth", "storage", "filter", "smtp", "pop3", "imap", "web"):
        suite.start(name)
    for username in (alice, bob):
        assert suite.rpc("auth", op="create", username=username, password=PASSWORD, admin=username == alice)["ok"]
    raw = b"From: alice@localhost\r\nTo: bob@localhost\r\nSubject: TLS delivery\r\n\r\nTLS mail\r\n.dot\r\n"
    with smtplib.SMTP("localhost", suite.ports["smtp"], local_hostname="localhost", timeout=10) as client:
        client.ehlo()
        assert client.has_extn("starttls") and not client.has_extn("auth")
        credentials = base64.b64encode(b"\0" + alice.encode() + b"\0" + PASSWORD.encode()).decode()
        assert client.docmd("AUTH", "PLAIN " + credentials)[0] == 538
        assert client.starttls(context=client_context())[0] == 220
        client.ehlo()
        assert client.has_extn("auth") and not client.has_extn("starttls")
        assert client.login(alice, PASSWORD)[0] == 235
        assert client.sendmail(alice, [bob], raw) == {}
    suite.start("delivery")
    suite.wait_mail(bob, 1)

    client = poplib.POP3("localhost", suite.ports["pop3"], timeout=10)
    try:
        assert "STLS" in client.capa() and "USER" not in client.capa()
        try:
            client.user(bob)
            raise AssertionError("POP3 accepted a username over plaintext")
        except poplib.error_proto:
            pass
        client.stls(context=client_context())
        client.user(bob)
        client.pass_(PASSWORD)
        assert client.stat()[0] == 1
        assert b"\r\n".join(client.retr(1)[1]) + b"\r\n" == raw
        client.quit()
    finally:
        client.close()

    client = imaplib.IMAP4("localhost", suite.ports["imap"], timeout=10)
    try:
        assert "STARTTLS" in client.capabilities and "LOGINDISABLED" in client.capabilities
        try:
            client.login(bob, PASSWORD)
            raise AssertionError("IMAP accepted plaintext LOGIN")
        except imaplib.IMAP4.error:
            pass
        assert client.starttls(ssl_context=client_context())[0] == "OK"
        assert "LOGINDISABLED" not in client.capabilities
        assert client.login(bob, PASSWORD)[0] == "OK"
        assert client.select("INBOX")[1] == [b"1"]
        assert client.fetch("1", "(BODY.PEEK[])")[0] == "OK"
        client.logout()
    finally:
        try:
            client.shutdown()
        except OSError:
            pass
    status, headers, login = https(suite, "POST", "/api/login", {"username": bob, "password": PASSWORD})
    assert status == 200, login
    assert "; Secure" in headers["Set-Cookie"] and "; HttpOnly" in headers["Set-Cookie"]
    cookie = {"Cookie": headers["Set-Cookie"].split(";", 1)[0]}
    assert https(suite, "GET", "/api/messages", headers=cookie)[0] == 200
    try:
        suite.http("web", "GET", "/api/messages", headers=cookie)
        raise AssertionError("HTTPS listener accepted a plaintext HTTP request")
    except (OSError, http.client.HTTPException):
        pass
    plaintext_after_starttls_is_fatal(suite)
    suite.stop("delivery")
    print("PASS SMTP STARTTLS/AUTH, POP3 STLS, IMAP STARTTLS, HTTPS and downgrade rejection", flush=True)


class SMTPMock:
    """A loopback-only submission peer; records wire data without logging secrets."""
    def __init__(self, *, starttls=True, final_status=250, rcpt_status=250, reply_delay=0):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.starttls = starttls
        self.final_status = final_status
        self.rcpt_status = rcpt_status
        self.reply_delay = reply_delay
        self.stopped = threading.Event()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(str(CERTIFICATE), str(PRIVATE_KEY))
        self.messages = []
        self.envelopes = []
        self.authenticated = []
        self.failures = []
        self.reply_times = []
        self.tls_failures = 0
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except (TimeoutError, OSError):
                continue
            try:
                self.session(connection)
            except ssl.SSLError:
                self.tls_failures += 1  # An untrusted certificate test expects this.
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, EOFError):
                # Transaction deadlines may close the peer between any two
                # replies or partway through DATA; this is expected test input.
                pass
            except Exception as error:
                self.failures.append(error)

    def send_reply(self, connection, reply):
        if self.stopped.wait(self.reply_delay):
            raise EOFError("test smarthost stopping")
        connection.sendall(reply)
        self.reply_times.append((time.monotonic(), reply[:3].decode("ascii")))

    def session(self, connection):
        stream = None
        try:
            connection.settimeout(8)
            stream = connection.makefile("rb")
            self.send_reply(connection, b"220 localhost PostPlus test-only smarthost\r\n")
            encrypted = False
            sender = recipient = None
            while not self.stopped.is_set():
                line = stream.readline(8192)
                if not line:
                    return
                assert line.endswith(b"\r\n") and len(line) < 8192
                command = line.split(b" ", 1)[0].strip().upper()
                if command == b"EHLO":
                    if encrypted:
                        self.send_reply(connection, b"250-localhost\r\n250 AUTH PLAIN\r\n")
                    elif self.starttls:
                        self.send_reply(connection, b"250-localhost\r\n250 STARTTLS\r\n")
                    else:
                        self.send_reply(connection, b"250 localhost\r\n")
                elif command == b"STARTTLS":
                    assert self.starttls and not encrypted
                    self.send_reply(connection, b"220 Begin TLS\r\n")
                    stream.close()
                    stream = None
                    connection = self.context.wrap_socket(connection, server_side=True)
                    stream = connection.makefile("rb")
                    encrypted = True
                elif command == b"AUTH":
                    assert encrypted, "credentials reached the upstream before TLS"
                    fields = line.strip().split(b" ")
                    assert fields[:2] == [b"AUTH", b"PLAIN"]
                    assert base64.b64decode(fields[2], validate=True) == b"\0upstream-user\0upstream-test-secret"
                    self.authenticated.append(True)
                    self.send_reply(connection, b"235 Authenticated\r\n")
                elif command == b"MAIL":
                    assert encrypted and self.authenticated
                    sender = line.strip()
                    self.send_reply(connection, b"250 Sender accepted\r\n")
                elif command == b"RCPT":
                    assert sender is not None
                    recipient = line.strip()
                    self.send_reply(connection, f"{self.rcpt_status} Recipient accepted\r\n".encode())
                elif command == b"DATA":
                    assert recipient is not None
                    self.send_reply(connection, b"354 Send message\r\n")
                    raw = wire = b""
                    while True:
                        data = stream.readline(131072)
                        if not data:
                            return
                        if data == b".\r\n":
                            break
                        wire += data
                        raw += data[1:] if data.startswith(b"..") else data
                    self.messages.append((raw, wire))
                    self.envelopes.append((sender, recipient))
                    self.send_reply(connection, f"{self.final_status} Test-only upstream result\r\n".encode())
                elif command == b"QUIT":
                    self.send_reply(connection, b"221 Bye\r\n")
                    return
                else:
                    raise AssertionError("unexpected command to test smarthost")
        finally:
            if stream is not None:
                stream.close()
            connection.close()

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(timeout=10)
        assert not self.thread.is_alive(), "test smarthost did not stop"
        assert not self.failures, self.failures


def configure_transfer(suite, mock, *, trusted=True, host="localhost"):
    suite.stop("transfer")
    suite.config.update(smarthost_host=host, smarthost_port=mock.port,
                        smarthost_tls="starttls", smarthost_username="upstream-user",
                        smarthost_password_env="POSTPLUS_TLS_TEST_SMARTHOST_PASSWORD")
    suite.env["POSTPLUS_TLS_TEST_SMARTHOST_PASSWORD"] = "upstream-test-secret"
    if trusted:
        suite.env["SSL_CERT_FILE"] = str(CERTIFICATE)
    else:
        # A missing test-local CA file prevents inheriting an ambient SSL_CERT_FILE.
        suite.env["SSL_CERT_FILE"] = str(suite.directory / "missing-ca.pem")
    suite.save()
    suite.start("transfer")


def check_transfer(suite):
    raw = b"From: alice@localhost\r\nTo: external@example.test\r\nSubject: Smarthost test\r\n\r\n.leading dot\r\n..two dots\r\n"
    request = dict(op="send", sender="alice@localhost", recipient="external@example.test", raw=raw)
    mock = SMTPMock()
    try:
        configure_transfer(suite, mock)
        assert suite.rpc("transfer", **request)["ok"]
        assert mock.messages[-1][0] == raw
        assert b"\r\n..leading dot\r\n...two dots\r\n" in mock.messages[-1][1]
        assert mock.envelopes[-1] == (b"MAIL FROM:<alice@localhost>", b"RCPT TO:<external@example.test>")
        assert mock.authenticated
        mock.rcpt_status = 251
        forwarded = suite.rpc("transfer", **request)
        assert forwarded["ok"], ("RCPT 251 must allow DATA delivery", forwarded)
        assert len(mock.messages) == 2 and mock.messages[-1][0] == raw
    finally:
        mock.close()
    for mode in ("untrusted", "no_starttls"):
        mock = SMTPMock(starttls=mode != "no_starttls")
        try:
            configure_transfer(suite, mock, trusted=mode != "untrusted")
            assert not suite.rpc("transfer", **request)["ok"]
            assert not mock.messages and not mock.authenticated
        finally:
            mock.close()
    print("PASS verified smarthost STARTTLS/AUTH, RCPT 250/251, dot stuffing, untrusted certificate and TLS downgrade rejection", flush=True)

    mock = SMTPMock(final_status=451)
    try:
        configure_transfer(suite, mock)
        assert suite.rpc("storage", op="enqueue", sender="alice@localhost", recipients=["external@example.test"], raw=raw)["ok"]
        suite.start("delivery")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            jobs = suite.rpc("storage", op="queue_inspect")["jobs"]
            if len(jobs) == 1 and jobs[0]["attempts"] >= 1:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("upstream rejection was not scheduled for retry")
        assert jobs[0]["state"] == "pending" and jobs[0]["next_attempt"] > time.time() - 1
        assert mock.messages and mock.messages[0][0] == raw
        mock.final_status = 250
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if suite.rpc("storage", op="stats")["queued"] == 0:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("durable upstream retry did not complete")
        assert len(mock.messages) >= 2 and mock.messages[-1][0] == raw
        print("PASS failed upstream delivery retained and successfully retried", flush=True)
    finally:
        suite.stop("delivery")
        mock.close()


def check_transfer_transaction_deadline(suite):
    # Nine replies each take 0.55 seconds: every individual I/O operation fits
    # inside timeout_seconds=2, but the complete SMTP transaction takes about 5
    # seconds. A generous transaction budget must succeed; a 3-second budget
    # must fail even though no individual reply reaches its operation timeout.
    operation_timeout, transaction_timeout = 2, 3
    reply_delay = 0.55
    assert reply_delay < operation_timeout < transaction_timeout < 9 * reply_delay
    raw = (b"From: alice@localhost\r\nTo: delayed@example.test\r\n"
           b"Subject: Whole-transaction deadline\r\n\r\nPreserve this queued mail.\r\n")
    request = dict(op="send", sender="alice@localhost", recipient="delayed@example.test", raw=raw)
    original_timeout = suite.config["timeout_seconds"]
    original_budget = suite.config.get("smarthost_timeout_seconds", 30)
    mock = SMTPMock(reply_delay=reply_delay)
    try:
        suite.config.update(timeout_seconds=operation_timeout, smarthost_timeout_seconds=10)
        # A numeric address avoids localhost IPv6-to-IPv4 fallback latency on
        # Windows; the fixture certificate includes this loopback IP SAN.
        configure_transfer(suite, mock, host="127.0.0.1")
        started = time.monotonic()
        result = suite.rpc("transfer", **request)
        successful_elapsed = time.monotonic() - started
        assert result["ok"], ("individually timely replies should succeed with a sufficient total budget",
                              result, successful_elapsed,
                              [(round(instant - started, 2), status) for instant, status in mock.reply_times])
        assert successful_elapsed > transaction_timeout
        assert len(mock.messages) == 1 and mock.messages[0][0] == raw
    finally:
        mock.close()

    mock = SMTPMock(reply_delay=reply_delay)
    try:
        suite.config["smarthost_timeout_seconds"] = transaction_timeout
        configure_transfer(suite, mock, host="127.0.0.1")
        started = time.monotonic()
        result = suite.rpc("transfer", **request)
        failed_elapsed = time.monotonic() - started
        assert not result["ok"], "SMTP transaction exceeded its total deadline but was accepted"
        assert "timed out" in result.get("error", "").lower(), result
        assert transaction_timeout - 0.25 <= failed_elapsed < transaction_timeout + 2, failed_elapsed
        assert not mock.messages, "timed out transaction unexpectedly reached DATA acceptance"

        # Exercise the delivery process too: its internal RPC deadline must
        # leave time for transfer to report its own deadline and persist retry.
        assert suite.rpc("storage", op="enqueue", sender=request["sender"],
                         recipients=[request["recipient"]], raw=raw)["ok"]
        suite.start("delivery")
        deadline = time.monotonic() + transaction_timeout + 10
        while time.monotonic() < deadline:
            jobs = suite.rpc("storage", op="queue_inspect")["jobs"]
            if len(jobs) == 1 and jobs[0]["attempts"] >= 1:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("whole-transaction timeout did not persist a delivery retry")
        suite.stop("delivery")
        job = jobs[0]
        assert job["state"] == "pending" and job["size"] == len(raw)
        assert job["sender"] == request["sender"] and job["recipient"] == request["recipient"]
        assert suite.rpc("storage", op="stats")["queued"] == 1
        assert not mock.messages

        # Persisted retry metadata and the original body must survive restarting
        # storage. Wait for the normal retry timestamp instead of editing its DB.
        suite.stop("storage")
        suite.start("storage")
        persisted = suite.rpc("storage", op="queue_inspect")["jobs"]
        assert len(persisted) == 1 and persisted[0]["id"] == job["id"]
        assert persisted[0]["attempts"] == job["attempts"]
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            due = suite.rpc("storage", op="queue_list", limit=1)["jobs"]
            if due:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("timed out message did not become eligible for retry")
        assert due[0]["id"] == job["id"] and due[0]["raw"] == raw
        print(f"PASS SMTP whole-transaction deadline ({successful_elapsed:.2f}s success with sufficient budget, "
              f"{failed_elapsed:.2f}s failure with {transaction_timeout}s budget), durable retry and body preservation", flush=True)
    finally:
        suite.stop("delivery")
        mock.close()
        suite.config.update(timeout_seconds=original_timeout, smarthost_timeout_seconds=original_budget)
        suite.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build")
    args = parser.parse_args()
    directory = (args.build_dir / "test-runs" / ("tls-" + secrets.token_hex(6))).resolve()
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    suite.config.update(allow_insecure_auth=False, tls_certificate=str(CERTIFICATE), tls_private_key=str(PRIVATE_KEY))
    suite.save()
    try:
        check_protocol_tls(suite)
        check_transfer(suite)
        check_transfer_transaction_deadline(suite)
        print("All TLS and smarthost integration tests passed", flush=True)
    except BaseException:
        print(f"Logs: {directory}", flush=True)
        traceback.print_exc()
        raise
    finally:
        suite.close()


if __name__ == "__main__":
    main()
