#!/usr/bin/env python3
"""Offline POP3 client authorization, stable maildrop and transaction checks."""
import argparse
import base64
from contextlib import closing
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
import poplib
import secrets
import socket
import ssl
import sqlite3
import time

from integration import PASSWORD, ROOT, Suite

USER = "pop-reader@localhost"
EMPTY = "pop-empty@localhost"
MIME_USER = "pop-mime@localhost"
OCTET_USER = "pop-octets@localhost"


def context():
    value = ssl.create_default_context(cafile=str(ROOT / "tests/fixtures/localhost-test-only.crt"))
    value.minimum_version = ssl.TLSVersion.TLSv1_2
    return value


def encoded(value):
    return base64.b64encode(value.encode()).decode()


def plain(user=USER, password=PASSWORD, identity=""):
    return encoded(f"{identity}\0{user}\0{password}")


def failure(function, contains=None):
    try:
        function()
    except poplib.error_proto as error:
        if contains:
            assert contains in error.args[0], (contains, error.args[0])
        return
    raise AssertionError("POP3 unexpectedly accepted an invalid command or credentials")


def encrypted(suite, implicit=True):
    if implicit:
        return poplib.POP3_SSL("localhost", suite.ports["pop3s"], context=context(), timeout=10)
    client = poplib.POP3("localhost", suite.ports["pop3"], timeout=10)
    assert "STLS" in client.capa()
    client.stls(context=context())
    return client


def authenticate(client, mechanism="PLAIN", initial=True, user=USER, identity=""):
    if mechanism == "USER":
        client.user(user)
        assert client.pass_(PASSWORD).startswith(b"+OK")
    elif mechanism == "PLAIN":
        response = client._shortcmd("AUTH PLAIN" + (" " + plain(user, identity=identity) if initial else ""))
        if not initial:
            assert response == b"+ "
            response = client._shortcmd(plain(user, identity=identity))
        assert response.startswith(b"+OK")
    else:
        response = client._shortcmd("AUTH LOGIN" + (" " + encoded(user) if initial else ""))
        if not initial:
            assert response == b"+ VXNlcm5hbWU6"
            response = client._shortcmd(encoded(user))
        assert response == b"+ UGFzc3dvcmQ6"
        assert client._shortcmd(encoded(PASSWORD)).startswith(b"+OK")


def wait_unlock(client):
    for _ in range(50):
        client.user(USER)
        try:
            client.pass_(PASSWORD)
            return
        except poplib.error_proto as error:
            assert b"IN-USE" in error.args[0], error.args[0]
            time.sleep(0.02)
    raise AssertionError("Disconnected POP3 transaction retained its maildrop lease")


def buffered_tls_commands(suite):
    """Coalesce TLS 1.3 Finished/application records and split a later record."""
    with socket.create_connection(("localhost", suite.ports["pop3"]), timeout=5) as wire:
        # Avoid a buffered file: it could consume ciphertext following STLS.
        def clear_line():
            line = bytearray()
            while not line.endswith(b"\r\n"):
                value = wire.recv(1)
                assert value, "POP3 closed before TLS"
                line.extend(value)
            return bytes(line)
        assert clear_line().startswith(b"+OK")
        wire.sendall(b"STLS\r\n")
        assert clear_line().startswith(b"+OK")
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = context().wrap_bio(incoming, outgoing, server_hostname="localhost")
        def flush():
            while outgoing.pending:
                wire.sendall(outgoing.read())
        while True:
            try:
                client.do_handshake()
                break
            except ssl.SSLWantReadError:
                flush()
                data = wire.recv(65536)
                assert data, "POP3 closed during TLS handshake"
                incoming.write(data)
        assert client.version() == "TLSv1.3"
        # Keep Finished in outgoing until the first application command is
        # appended, making one server handshake read consume both TLS records.
        assert outgoing.pending
        client.write(("AUTH PLAIN " + plain() + "\r\n").encode())
        flush()
        pending = bytearray()
        def reply():
            while b"\r\n" not in pending:
                try:
                    pending.extend(client.read(65536))
                except ssl.SSLWantReadError:
                    flush()
                    data = wire.recv(65536)
                    assert data, "POP3 TLS connection closed"
                    incoming.write(data)
            line, _, remainder = pending.partition(b"\r\n")
            pending[:] = remainder
            return bytes(line)
        assert reply().startswith(b"+OK"), "Buffered TLS authentication was not processed"
        for _ in range(3):
            client.write(b"NOOP\r\n")
        flush()
        for _ in range(3):
            assert reply() == b"+OK", "Buffered application record was stranded"
        client.write(b"NOOP\r\n")
        fragment = outgoing.read()
        wire.sendall(fragment[:3])
        time.sleep(1.3)  # Cross one readiness poll with an incomplete TLS record.
        wire.sendall(fragment[3:])
        assert reply() == b"+OK", "Polling cancellation lost a partial TLS record"
        client.write(b"QUIT\r\n")
        flush()
        assert reply().startswith(b"+OK")
    print("PASS POP3 coalesced TLS handshake/commands, buffered records and partial-record polling", flush=True)


def mime_messages(suite):
    """A client must be able to render RETR, not merely list a maildrop."""
    assert suite.rpc("auth", op="create", username=MIME_USER, password=PASSWORD)["ok"]
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = "\u53d1\u4ef6\u4eba <sender@localhost>"
    message["To"] = MIME_USER
    message["Subject"] = "\u624b\u673a\u5ba2\u6237\u7aef\uff1a\u6b63\u6587\u4e0e\u9644\u4ef6 " + "folded header " * 8
    message["Date"] = "Fri, 16 Oct 2026 10:00:00 +0000"
    message["Message-ID"] = "<pop-mime-fixture@localhost>"
    message.set_content("\u6b63\u6587\u4fe1\u606f\r\n.first\r\n..second\r\n", cte="quoted-printable")
    message.add_alternative('<html><body><p>HTML \u6b63\u6587</p><img src="cid:logo"></body></html>',
                            subtype="html", cte="base64")
    image = b"\x89PNG\r\n\x1a\n\0\xffbinary-image"
    message.get_payload()[1].add_related(image, maintype="image", subtype="png", cid="<logo>")
    attachment = b"\0\x01\x02\xff\r\n.\r\nattachment-bytes"
    message.add_attachment(attachment, maintype="application", subtype="octet-stream", filename="\u62a5\u544a.bin")
    forwarded = EmailMessage(policy=policy.SMTP)
    forwarded["From"] = "original@localhost"
    forwarded["To"] = MIME_USER
    forwarded["Subject"] = "Forwarded message"
    forwarded.set_content("Embedded message body.\n")
    message.add_attachment(forwarded, filename="forwarded.eml")
    raw = message.as_bytes()
    assert suite.rpc("storage", op="deliver", username=MIME_USER, raw=raw, delivery_id="pop3-mime-fixture")["ok"]
    for implicit in (True, False):
        with closing(encrypted(suite, implicit)) as client:
            authenticate(client, user=MIME_USER)
            assert client.stat() == (1, len(raw))
            assert client.list(1).split()[1:] == [b"1", str(len(raw)).encode()]
            header_bytes = b"\r\n".join(client.top(1, 0)[1]) + b"\r\n"
            headers = BytesParser(policy=policy.default).parsebytes(header_bytes)
            assert str(headers["Subject"]) == str(message["Subject"])
            assert headers["From"].addresses[0].display_name == "\u53d1\u4ef6\u4eba"
            assert headers["Message-ID"] == message["Message-ID"]
            retrieved = b"\r\n".join(client.retr(1)[1]) + b"\r\n"
            assert retrieved == raw, "POP3 damaged a MIME boundary, encoding, header fold or dot-prefixed line"
            parsed = BytesParser(policy=policy.default).parsebytes(retrieved)
            assert not any(part.defects for part in parsed.walk())
            assert parsed.get_body(preferencelist=("plain",)).get_content() == "\u6b63\u6587\u4fe1\u606f\r\n.first\r\n..second\r\n"
            assert "HTML \u6b63\u6587" in parsed.get_body(preferencelist=("html",)).get_content()
            assert next(part for part in parsed.walk() if part.get("Content-ID") == "<logo>").get_payload(decode=True) == image
            attachments = {part.get_filename(): part for part in parsed.iter_attachments()}
            assert attachments["\u62a5\u544a.bin"].get_payload(decode=True) == attachment
            assert attachments["forwarded.eml"].get_payload()[0].get_content().strip() == "Embedded message body."
            client.quit()
    print("PASS POP3 renderable MIME: folded encoded headers, text/HTML, inline image, Unicode attachment and forwarded message over TLS and STLS", flush=True)


def canonical_octets(suite):
    assert suite.rpc("auth", op="create", username=OCTET_USER, password=PASSWORD)["ok"]
    # API import and IMAP APPEND preserve the supplied bytes. POP3 uses CRLF
    # and terminates the final line, so stored bytes are not its octet count.
    messages = [b"Subject: LF import\n\n.first\nlast", b"Subject: Missing final CRLF\r\n\r\nbody",
                b"Subject: Mixed newlines\n\r\n..first\r\nlast\n"]
    expected = [value.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n") for value in messages]
    expected = [value if value.endswith(b"\r\n") else value + b"\r\n" for value in expected]
    for raw in messages:
        assert suite.rpc("storage", op="append", username=OCTET_USER, folder="INBOX", raw=raw)["ok"]
    database = Path(suite.config["data_dir"]) / "storage.sqlite3"
    # An upgraded installation has no POP3 size side table. Startup must add
    # it without rewriting existing mail or scanning bodies for normal lists.
    suite.stop("storage")
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE message_pop3")
    suite.start("storage")
    ordinary = suite.rpc("storage", op="list", username=OCTET_USER, folder="INBOX")["messages"]
    assert [item["size"] for item in ordinary] == list(map(len, messages))
    assert all("pop3_size" not in item for item in ordinary)
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (2,)
        assert connection.execute("SELECT COUNT(*) FROM message_pop3 p JOIN messages m ON m.id=p.id WHERE m.username=?", (OCTET_USER,)).fetchone()[0] == 0
    for implicit in (True, False):
        with closing(encrypted(suite, implicit)) as client:
            authenticate(client, user=OCTET_USER)
            assert client.stat() == (len(messages), sum(map(len, expected)))
            assert [row.split() for row in client.list()[1]] == [
                [str(index).encode(), str(len(value)).encode()] for index, value in enumerate(expected, 1)]
            for index, value in enumerate(expected, 1):
                assert client.list(index).split()[1:] == [str(index).encode(), str(len(value)).encode()]
                retrieved = b"\r\n".join(client.retr(index)[1]) + b"\r\n"
                assert retrieved == value and len(retrieved) == len(value)
            client.dele(1)
            assert client.stat() == (len(messages) - 1, sum(map(len, expected[1:])))
            client.rset()
            client.quit()
    with sqlite3.connect(database) as connection:
        assert [row[0] for row in connection.execute("SELECT p.octets FROM message_pop3 p JOIN messages m ON m.id=p.id WHERE m.username=? ORDER BY m.uid", (OCTET_USER,))] == list(map(len, expected))
        assert connection.execute("SELECT COUNT(*) FROM message_pop3 p JOIN messages m ON m.id=p.id WHERE m.username<>?", (OCTET_USER,)).fetchone()[0] == 0
    # Replacing a draft can keep its ID and stored length while changing its
    # POP3 size. Moving it to INBOX must update a stale source UID in the cache.
    first = b"Subject: draft\n\nbody"
    second = b"Subject: draft\r\n\r\nxx"
    assert len(first) == len(second)
    draft = suite.rpc("storage", op="draft_save", username=OCTET_USER, raw=first)
    assert draft["ok"]
    saved = suite.rpc("storage", op="draft_save", username=OCTET_USER, id=draft["id"], uid=draft["uid"], raw=second)
    assert saved["ok"] and saved["uid"] != draft["uid"]
    moved = suite.rpc("storage", op="copy", username=OCTET_USER, source_folder="Drafts", folder="INBOX", move=True,
                      ids=[saved["id"]], expected_uids={saved["id"]: saved["uid"]})
    assert moved["ok"]
    listed = suite.rpc("storage", op="list", username=OCTET_USER, folder="INBOX", include_pop3_size=True)["messages"]
    assert listed[-1]["id"] == saved["id"] and listed[-1]["pop3_size"] == len(second) + 2
    assert suite.rpc("storage", op="delete", username=OCTET_USER, ids=[saved["id"]], permanent=True,
                     folder="INBOX", expected_uids={saved["id"]: listed[-1]["uid"]})["ok"]
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM message_pop3 WHERE id=?", (saved["id"],)).fetchone()[0] == 0
    print("PASS POP3 LIST/STAT octets match CRLF-normalized RETR including imported LF and unterminated final lines", flush=True)
    print("PASS POP3 size cache: lazy legacy backfill, draft replacement, folder move and deletion cleanup", flush=True)


def run(suite):
    suite.config.update(tls_certificate=str(ROOT / "tests/fixtures/localhost-test-only.crt"),
                        tls_private_key=str(ROOT / "tests/fixtures/localhost-test-only.key"),
                        allow_insecure_auth=False, max_connections=16, max_auth_attempts=3, timeout_seconds=2)
    suite.save()
    for service in ("auth", "storage", "pop3"):
        suite.start(service)
    for username in (USER, EMPTY):
        assert suite.rpc("auth", op="create", username=username, password=PASSWORD)["ok"]
    messages = [
        b"From: sender@localhost\r\nTo: pop-reader@localhost\r\nSubject: First\r\n\r\n.first\r\n..second\r\nlast\r\n",
        b"From: sender@localhost\r\nTo: pop-reader@localhost\r\nSubject: Second\r\n\r\nUTF-8: \xe4\xb8\xad\xe6\x96\x87\r\n",
    ]
    for index, raw in enumerate(messages):
        assert suite.rpc("storage", op="deliver", username=USER, raw=raw, delivery_id=f"pop3-fixture-{index}")["ok"]

    with closing(poplib.POP3("localhost", suite.ports["pop3"], timeout=10)) as client:
        capabilities = client.capa()
        assert "STLS" in capabilities and "SASL" not in capabilities and "USER" not in capabilities
        failure(lambda: client.user(USER), b"TLS required")
        failure(lambda: client._shortcmd("AUTH PLAIN " + plain()), b"TLS required")
        client.stls(context=context())
        capabilities = client.capa()
        assert capabilities["SASL"] == ["PLAIN", "LOGIN"] and "USER" in capabilities and "STLS" not in capabilities
        authenticate(client, "PLAIN")
        assert client.stat() == (2, sum(map(len, messages)))
        client.quit()
    print("PASS POP3 STLS discovers SASL only after encryption and authenticates a real mailbox", flush=True)
    buffered_tls_commands(suite)

    expected_uidls = None
    for mechanism, initial, implicit in (("PLAIN", True, True), ("PLAIN", False, False), ("LOGIN", True, True),
                                         ("LOGIN", False, False), ("USER", True, True)):
        with closing(encrypted(suite, implicit)) as client:
            assert client.capa()["SASL"] == ["PLAIN", "LOGIN"]
            authenticate(client, mechanism, initial)
            assert client.stat() == (2, sum(map(len, messages)))
            listed = [row.split() for row in client.list()[1]]
            assert listed == [[str(index + 1).encode(), str(len(raw)).encode()] for index, raw in enumerate(messages)]
            uidls = client.uidl()[1]
            assert len(uidls) == 2 and uidls[0] != uidls[1]
            if expected_uidls is None:
                expected_uidls = uidls
            assert uidls == expected_uidls, "UIDL changed after reconnect or another authentication mechanism"
            for index, raw in enumerate(messages, 1):
                assert client.list(index).split()[1:] == [str(index).encode(), str(len(raw)).encode()]
                assert client.uidl(index).split()[1:] == uidls[index - 1].split()
                assert b"\r\n".join(client.retr(index)[1]) + b"\r\n" == raw
                assert b"\r\n".join(client.top(index, 0)[1]) + b"\r\n" == raw.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
            assert b"\r\n".join(client.top(1, 1)[1]) + b"\r\n" == messages[0].split(b"..second", 1)[0]
            assert "SASL" not in client.capa() and "USER" not in client.capa()
            failure(lambda: client._shortcmd("AUTH PLAIN " + plain()))
            # RFC 2449 pipelining: clients can queue independent transaction
            # commands and receive their replies in the same order.
            client.sock.sendall(b"STAT\r\nUIDL 1\r\nNOOP\r\n")
            assert client._getresp().split()[1:] == [b"2", str(sum(map(len, messages))).encode()]
            assert client._getresp().split()[1:] == uidls[0].split()
            assert client._getresp() == b"+OK"
            for command in ("CAPA extra", "STAT extra", "NOOP extra", "RSET extra", "QUIT extra", "RETR 0", "LIST 3", "UIDL -1", "TOP 1 -1", "DELE 1 2"):
                failure(lambda command=command: client._shortcmd(command))
            client.quit()
    print("PASS POP3 PLAIN/LOGIN initial and challenge flows, USER/PASS, persistent UIDL, LIST/RETR/TOP/dot unstuffing and pipelined commands", flush=True)

    with closing(encrypted(suite)) as client:
        authenticate(client, user=EMPTY)
        assert client.stat() == (0, 0) and client.list()[1] == [] and client.uidl()[1] == []
        failure(lambda: client.retr(1))
        client.quit()
    with closing(encrypted(suite)) as client:
        # Cancellation must not consume failed-password attempts or leave the
        # parser in a SASL continuation state.
        for _ in range(4):
            assert client._shortcmd("AUTH PLAIN") == b"+ "
            failure(lambda: client._shortcmd("*"), b"canceled")
        assert client._shortcmd("AUTH LOGIN") == b"+ VXNlcm5hbWU6"
        assert client._shortcmd(encoded(USER)) == b"+ UGFzc3dvcmQ6"
        failure(lambda: client._shortcmd("*"), b"canceled")
        authenticate(client, identity=USER.upper())
        client.quit()
    with closing(encrypted(suite)) as client:
        for command in ("AUTH PLAIN " + plain(identity=EMPTY), "AUTH PLAIN invalid-base64", "AUTH LOGIN " + encoded(USER)):
            if command.startswith("AUTH LOGIN"):
                assert client._shortcmd(command) == b"+ UGFzc3dvcmQ6"
                command = encoded("wrong-password")
            failure(lambda command=command: client._shortcmd(command))
        assert client.file.readline() == b"", "Failed SASL attempts did not close the connection"
    print("PASS POP3 empty maildrop, SASL cancellation/resynchronization, authorization identity and shared failed-auth limit", flush=True)

    first = encrypted(suite)
    authenticate(first, "USER")
    with closing(encrypted(suite, False)) as second:
        failure(lambda: authenticate(second), b"IN-USE")
        # A different maildrop remains usable while this user is locked.
        authenticate(second, user=EMPTY)
        second.quit()
    first.dele(1)
    assert first.stat()[0] == 1 and len(first.list()[1]) == 1 and len(first.uidl()[1]) == 1
    failure(lambda: first.retr(1))
    failure(lambda: first.dele(1))
    first.rset()
    assert first.stat()[0] == 2
    first.dele(1)
    first.close()  # Disconnect cannot commit deferred deletion.
    with closing(encrypted(suite)) as client:
        wait_unlock(client)
        assert client.stat()[0] == 2 and client.uidl()[1] == expected_uidls
        newest = b"Subject: Delivered during POP3 transaction\r\n\r\nnew\r\n"
        assert suite.rpc("storage", op="deliver", username=USER, raw=newest, delivery_id="pop3-fixture-live")["ok"]
        assert client.stat()[0] == 2, "New delivery renumbered an active transaction"
        client.dele(1)
        client.quit()  # Only a successful QUIT commits the deletion.
    with closing(encrypted(suite)) as client:
        wait_unlock(client)
        assert client.stat()[0] == 2
        assert client.uidl()[1][0].split()[1] == expected_uidls[1].split()[1]
        assert b"\r\n".join(client.retr(1)[1]) + b"\r\n" == messages[1]
        assert b"\r\n".join(client.retr(2)[1]) + b"\r\n" == newest
        client.quit()
    print("PASS POP3 cross-listener maildrop locks, disconnect rollback, RSET, QUIT commit and stable snapshot during concurrent delivery", flush=True)
    with closing(encrypted(suite)) as client:
        authenticate(client)
        client.dele(1)
        time.sleep(suite.config["timeout_seconds"] + 0.3)
        assert client.noop() == b"+OK", "Idle mail reader was closed by the short per-command timeout"
        assert client.stat()[0] == 1
        client.rset()
        client.quit()
    with closing(encrypted(suite)) as client:
        authenticate(client)
        client.dele(1)
        # Resetting credentials invalidates the established transaction without
        # letting its pending deletions remove mail under the new credentials.
        assert suite.rpc("auth", op="change_password", username=USER, password=PASSWORD)["ok"]
        failure(client.noop, b"credentials changed")
        assert client.file.readline() == b""
    with closing(encrypted(suite)) as client:
        wait_unlock(client)
        assert client.stat()[0] == 2
        client.quit()
    print("PASS POP3 idle reader survives the short command deadline; credential rotation closes the transaction, rolls back deletion and releases its lock", flush=True)
    mime_messages(suite)
    canonical_octets(suite)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("pop3-clients-" + secrets.token_hex(6))
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
