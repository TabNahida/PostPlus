#!/usr/bin/env python3
"""Real protocol framing, state isolation and authentication-boundary regressions."""
import argparse
import base64
import imaplib
import os
from pathlib import Path
import poplib
import secrets
import select
import smtplib
import socket
import subprocess
import time
import traceback

from integration import PASSWORD, ROOT, Suite


def rejected_imap(client, method, *args):
    try:
        status, _ = method(*args)
        assert status in ("BAD", "NO"), status
    except imaplib.IMAP4.error:
        pass
    # Rejection must preserve framing so a subsequent NOOP still succeeds.
    assert client.noop()[0] == "OK"


def run(s):
    s.config.update(max_auth_attempts=3, max_recipients=2)
    s.save()
    for name in ("auth", "storage", "smtp", "pop3", "imap"):
        s.start(name)
    alice, bob, charlie, delta = [f"{name}@localhost" for name in ("alice", "bob", "charlie", "delta")]
    for user in (alice, bob, charlie, delta):
        assert s.rpc("auth", op="create", username=user, password=PASSWORD)["ok"]

    with smtplib.SMTP("127.0.0.1", s.ports["smtp"], local_hostname="localhost", timeout=10) as client:
        client.ehlo()
        for invalid, code in (("MAIL FROM:garbage", 501), ("MAIL FROM:<alice@localhost> SIZE=65537", 552),
                              ("MAIL FROM:<alice@localhost> SIZE=garbage", 555)):
            assert client.mail(alice)[0] == 250
            assert client.rcpt(bob)[0] == 250
            assert client.docmd(invalid)[0] == code
            assert client.docmd("DATA")[0] == 503
            assert client.rcpt(charlie)[0] == 503
        assert client.mail(alice)[0] == 250
        assert client.rcpt(bob)[0] == 250
        assert client.rcpt(charlie)[0] == 250
        assert client.rcpt(delta)[0] == 452
        client.rset()
        assert client.mail(alice)[0] == 250
        assert client.rcpt(charlie)[0] == 250
        assert client.data(b"Subject: no recipient leakage\r\n\r\nbody\r\n")[0] == 250
        jobs = s.rpc("storage", op="queue_list", limit=100)["jobs"]
        assert len(jobs) == 1 and jobs[0]["recipient"] == charlie, jobs
        # RFC 5321's 1,000-octet line limit excludes the extra transparency dot.
        legal = b"Subject: maximum line\r\n\r\n." + b"x" * 997 + b"\r\n"
        assert client.mail(alice)[0] == 250 and client.rcpt(bob)[0] == 250
        assert client.data(legal)[0] == 250
        jobs = s.rpc("storage", op="queue_list", limit=100)["jobs"]
        assert any(job["raw"] == legal for job in jobs)
        assert client.mail(alice)[0] == 250 and client.rcpt(bob)[0] == 250
        assert client.data(b"Subject: too long\r\n\r\n" + b"x" * 999 + b"\r\n")[0] == 552
        assert client.docmd("DATA")[0] == 503
        assert client.mail(alice)[0] == 250 and client.rcpt(bob)[0] == 250
        assert client.data(b"Subject: too large\r\n\r\n" + (b"x" * 998 + b"\r\n") * 66)[0] == 552
        assert len(s.rpc("storage", op="queue_list", limit=100)["jobs"]) == 2
        assert client.docmd("AUTH", "PLAIN ***")[0] == 501
        assert client.noop()[0] == 250
    print("PASS SMTP invalid-MAIL reset, recipient cap, byte/line limits and authentication framing", flush=True)

    raw = (b"From: alice@localhost\r\nTo: bob@localhost\r\nSubject: security test\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(b"needle in decoded body\r\n") + b"\r\n")
    for index in range(3):
        assert s.rpc("storage", op="deliver", username=bob, delivery_id=f"security-{index}", raw=raw)["ok"]
    box = s.rpc("storage", op="list", username=bob)
    uids = [str(message["uid"]) for message in box["messages"]]
    with imaplib.IMAP4("127.0.0.1", s.ports["imap"], timeout=10) as client:
        client.login(bob, PASSWORD)
        assert client.select()[1] == [b"3"]
        assert client.uid("search", None, "UID", f"{uids[-1]}:{uids[0]}")[1] == [" ".join(uids).encode()]
        # A reversed range including * includes the final UID, even if the other end exceeds it.
        assert client.uid("search", None, "UID", "4294967295:*")[1] == [uids[-1].encode()]
        assert client.search(None, "BODY", "needle")[1] == [b"1 2 3"]
        assert client.search(None, "OR", "SEEN", "NOT", "DELETED")[1] == [b"1 2 3"]
        for bad in ("0", "1,", "1::3", "4294967296", "1:0", "1,,2"):
            rejected_imap(client, client.uid, "fetch", bad, "(FLAGS)")
            rejected_imap(client, client.uid, "search", None, "UID", bad)
        for bad in ("(BODYSTRUCTURE)", "(BODY[99])", "(BODY[]<0.0>)", "(FLAGS UNKNOWN)", "(ALL)"):
            rejected_imap(client, client.fetch, "1", bad)
        assert client.fetch("1", "(BODY.PEEK[HEADER.FIELDS (SUBJECT)] BODY.PEEK[TEXT]<0.5>)")[0] == "OK"
        assert not s.rpc("storage", op="list", username=bob)["messages"][0]["seen"]
        status, fetch = client.fetch("1", "(BODY[])")
        assert status == "OK" and any(b"FLAGS (\\Seen)" in item for item in fetch if isinstance(item, bytes)), fetch
        assert client.select("INBOX", readonly=True)[0] == "OK"
        rejected_imap(client, client.store, "2", "+FLAGS", "(\\Seen)")
        assert client.fetch("2", "(BODY[])")[0] == "OK"
        assert not s.rpc("storage", op="list", username=bob)["messages"][1]["seen"]
        assert client.close()[0] == "OK"
        assert client.select()[0] == "OK"
        rejected_imap(client, client.store, "1", "+FLAGS", "(\\Flagged)")
        assert client.uid("store", f"{uids[-1]}:{uids[0]}", "+FLAGS.SILENT", "(\\Deleted)")[0] == "OK"
        assert client.expunge()[0] == "OK"
        assert client.uid("search", None, "ALL")[1] == [b""]
        assert client.uid("fetch", "*", "(FLAGS)")[0] == "OK"
    print("PASS IMAP UID ranges, malformed requests, MIME search, PEEK/Seen, EXAMINE and empty mailboxes", flush=True)

    # Synchronizing literals exercise the actual stream parser, including zero-length literals.
    with socket.create_connection(("127.0.0.1", s.ports["imap"]), timeout=10) as sock:
        stream = sock.makefile("rb")
        assert stream.readline().startswith(b"* OK")
        sock.sendall(b"a LOGIN {" + str(len(alice)).encode() + b"}\r\n")
        assert stream.readline().startswith(b"+")
        sock.sendall(alice.encode() + b" {" + str(len(PASSWORD)).encode() + b"}\r\n")
        assert stream.readline().startswith(b"+")
        sock.sendall(PASSWORD.encode() + b"\r\n")
        assert stream.readline().startswith(b"a OK")
        sock.sendall(b"b LIST {0}\r\n")
        assert stream.readline().startswith(b"+")
        sock.sendall(b' "INBOX"\r\n')
        assert stream.readline().startswith(b"* LIST")
        assert stream.readline().startswith(b"b OK")
        sock.sendall(b"c LOGIN {99999999999999999999}\r\n")
        assert stream.readline().startswith(b"* BYE")
        assert stream.readline() == b""
        stream.close()
    with socket.create_connection(("127.0.0.1", s.ports["smtp"]), timeout=10) as sock:
        stream = sock.makefile("rb")
        assert stream.readline().startswith(b"220")
        sock.sendall(b"NOOP\nQUIT\r\n")
        assert stream.readline() == b""
        stream.close()
    print("PASS literal continuations, zero/oversized literal handling and LF-smuggling rejection", flush=True)

    with smtplib.SMTP("127.0.0.1", s.ports["smtp"], local_hostname="localhost", timeout=10) as client:
        client.ehlo()
        for index in range(3):
            encoded = base64.b64encode(f"\0missing-smtp-{index}@localhost\0wrong-password".encode()).decode()
            assert client.docmd("AUTH", "PLAIN " + encoded)[0] == (421 if index == 2 else 535)
        try:
            client.noop()
            raise AssertionError("SMTP failed-auth limit left connection open")
        except smtplib.SMTPServerDisconnected:
            pass
    client = poplib.POP3("127.0.0.1", s.ports["pop3"], timeout=10)
    try:
        for index in range(3):
            client.user(f"missing-pop3-{index}@localhost")
            try:
                client.pass_("wrong-password")
                raise AssertionError("POP3 accepted invalid credentials")
            except poplib.error_proto as error:
                if index == 2:
                    assert b"LOGIN-DELAY" in error.args[0]
        assert client.file.readline() == b""
    finally:
        client.close()
    with socket.create_connection(("127.0.0.1", s.ports["imap"]), timeout=10) as sock:
        stream = sock.makefile("rb")
        assert stream.readline().startswith(b"* OK")
        for index in range(3):
            sock.sendall(f"a{index} LOGIN missing-imap-{index}@localhost wrong-password\r\n".encode())
            assert stream.readline().startswith(f"a{index} NO".encode())
        assert stream.readline().startswith(b"* BYE")
        assert stream.readline() == b""
        stream.close()
    print("PASS SMTP, POP3 and IMAP failed-auth connection limits", flush=True)


def data_deadline(s):
    s.config.update(timeout_seconds=2, smtp_data_timeout_seconds=1)
    s.save()
    for name in ("auth", "storage", "smtp"):
        s.start(name)
    recipient = "deadline@localhost"
    assert s.rpc("auth", op="create", username=recipient, password=PASSWORD)["ok"]
    with smtplib.SMTP("127.0.0.1", s.ports["smtp"], local_hostname="localhost", timeout=5) as client:
        client.ehlo()
        assert client.mail("sender@localhost")[0] == 250
        assert client.rcpt(recipient)[0] == 250
        assert client.docmd("DATA")[0] == 354
        started = time.monotonic()
        closed = False
        lines = 0
        while time.monotonic() - started < 3:
            try:
                client.sock.sendall(b"small valid line\r\n")
                lines += 1
                ready, _, _ = select.select([client.sock], [], [], 0.1)
                if ready:
                    assert client.sock.recv(1024) == b"", "DATA expiry must close without accepting mail"
                    closed = True
                    break
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                closed = True
                break
        assert closed and lines >= 3, (closed, lines, time.monotonic() - started)
        client.close()
    assert s.rpc("storage", op="queue_list", limit=100)["jobs"] == []
    # A complete DATA exchange clears the absolute deadline for subsequent commands.
    with smtplib.SMTP("127.0.0.1", s.ports["smtp"], local_hostname="localhost", timeout=5) as client:
        client.ehlo()
        assert client.sendmail("sender@localhost", [recipient], b"Subject: complete\r\n\r\nbody\r\n") == {}
        time.sleep(1.2)
        assert client.noop()[0] == 250
    assert len(s.rpc("storage", op="queue_list", limit=100)["jobs"]) == 1
    s.stop("smtp")
    binary = s.binaries / ("postplus-smtp.exe" if os.name == "nt" else "postplus-smtp")
    for invalid in (0, 3601, 1.5, "120"):
        s.config["smtp_data_timeout_seconds"] = invalid
        s.save()
        result = subprocess.run([str(binary), "--config", str(s.path)], env=s.env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        assert result.returncode != 0 and b"smtp_data_timeout_seconds" in result.stdout, (invalid, result.stdout)
    print("PASS SMTP whole-DATA deadline, no partial enqueue, deadline reset and configuration bounds", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True, type=Path)
    args = parser.parse_args()
    directory = (ROOT / "build/test-runs" / f"protocol-security-{secrets.token_hex(6)}").resolve()
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    except BaseException:
        print(f"Logs: {directory}", flush=True)
        traceback.print_exc()
        raise
    finally:
        suite.close()
    deadline_directory = directory / "data-deadline"
    deadline_directory.mkdir()
    suite = Suite(args.bin_dir.resolve(), deadline_directory)
    try:
        data_deadline(suite)
    except BaseException:
        print(f"Logs: {deadline_directory}", flush=True)
        traceback.print_exc()
        raise
    finally:
        suite.close()
    print("All protocol security tests passed", flush=True)


if __name__ == "__main__":
    main()
