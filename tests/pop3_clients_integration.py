#!/usr/bin/env python3
"""Offline POP3 client authorization, stable maildrop and transaction checks."""
import argparse
import base64
from contextlib import closing
from pathlib import Path
import poplib
import secrets
import ssl
import time

from integration import PASSWORD, ROOT, Suite

USER = "pop-reader@localhost"
EMPTY = "pop-empty@localhost"


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
