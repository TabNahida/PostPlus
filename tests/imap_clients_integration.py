#!/usr/bin/env python3
"""IMAP wire compatibility for Outlook/Thunderbird-style encrypted clients."""
import argparse
import base64
from contextlib import closing
import imaplib
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import time

from integration import PASSWORD, ROOT, Suite
from mail_clients_integration import context, literal, wait_tls


def modified_utf7(value):
    result, pending = [], []

    def flush():
        if pending:
            encoded = base64.b64encode("".join(pending).encode("utf-16-be")).decode().rstrip("=").replace("/", ",")
            result.append("&" + encoded + "-")
            pending.clear()

    for char in value:
        if 32 <= ord(char) <= 126:
            flush()
            result.append("&-" if char == "&" else char)
        else:
            pending.append(char)
    flush()
    return "".join(result)


def mailbox(value):
    return '"' + modified_utf7(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def authenticated(suite,user):
    client=imaplib.IMAP4_SSL("localhost",suite.ports["imaps"],ssl_context=context(),timeout=10)
    try:
        client.login(user,PASSWORD)
        return client
    except BaseException:
        client.shutdown()
        raise


class Wire:
    def __init__(self, suite, encrypted=True):
        self.sock = socket.create_connection(("localhost", suite.ports["imaps" if encrypted else "imap"]), timeout=10)
        if encrypted:
            self.sock = context().wrap_socket(self.sock, server_hostname="localhost")
        self.reader = self.sock.makefile("rb")
        self.greeting = self.line()
        assert self.greeting.startswith(b"* OK"), self.greeting

    def close(self):
        self.reader.close()
        self.sock.close()

    def line(self):
        value = self.reader.readline(100000)
        assert value.endswith(b"\r\n"), value
        return value

    def send(self, value):
        self.sock.sendall(value if isinstance(value, bytes) else value.encode())

    def response(self, tag, status=b"OK"):
        result = []
        while True:
            line = self.line()
            result.append(line)
            match = re.search(rb"\{(\d+)\}\r\n$", line)
            if match:
                result.append(self.reader.read(int(match[1])))
            if line.startswith(tag.encode() + b" "):
                assert line.split()[1] == status, result
                return b"".join(result)

    def command(self, tag, command, status=b"OK"):
        self.send(tag + " " + command + "\r\n")
        return self.response(tag, status)

    def login(self, user):
        return self.command("login", 'LOGIN "' + user + '" "' + PASSWORD + '"')


class RecordWire(Wire):
    """A verified TLS peer that can withhold the tail of an encrypted record."""
    def __init__(self, suite, version):
        self.sock = socket.create_connection(("127.0.0.1", suite.ports["imaps"]), timeout=10)
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        configuration = context()
        configuration.minimum_version = configuration.maximum_version = version
        self.tls = configuration.wrap_bio(self.incoming, self.outgoing, server_hostname="localhost")
        self.pending = bytearray()
        self.reader = self
        try:
            while True:
                try:
                    self.tls.do_handshake()
                    self.flush()
                    break
                except ssl.SSLWantReadError:
                    self.flush()
                    self.receive()
            assert self.line().startswith(b"* OK")
        except BaseException:
            self.sock.close()
            raise

    def close(self):
        self.sock.close()

    def flush(self):
        while self.outgoing.pending:
            self.sock.sendall(self.outgoing.read())

    def receive(self):
        encrypted = self.sock.recv(65536)
        assert encrypted, "TLS peer closed while a record was incomplete"
        self.incoming.write(encrypted)

    def fill(self):
        while True:
            try:
                plain = self.tls.read(65536)
                assert plain, "TLS peer closed"
                self.pending.extend(plain)
                return
            except ssl.SSLWantReadError:
                self.flush()
                self.receive()

    def read(self, count):
        while len(self.pending) < count:
            self.fill()
        result = bytes(self.pending[:count])
        del self.pending[:count]
        return result

    def line(self):
        while b"\r\n" not in self.pending:
            assert len(self.pending) < 100000, "oversized IMAP response"
            self.fill()
        return self.read(self.pending.index(b"\r\n") + 2)

    def send(self, value):
        value = value if isinstance(value, bytes) else value.encode()
        assert self.tls.write(value) == len(value)
        self.flush()

    def split_record(self, value):
        assert not self.outgoing.pending
        assert self.tls.write(value) == len(value)
        encrypted = self.outgoing.read()
        assert len(encrypted) > 6 and encrypted[0] == 23, "expected TLS application record"
        # Include a complete record header, but withhold its final byte. The
        # server must process a poll timeout with a partial record buffered.
        self.sock.sendall(encrypted[:-1])
        return encrypted[-1:]


def run(s):
    s.config.update(tls_certificate=str(ROOT / "tests/fixtures/localhost-test-only.crt"),
                    tls_private_key=str(ROOT / "tests/fixtures/localhost-test-only.key"),
                    allow_insecure_auth=False, max_connections=24, timeout_seconds=2,
                    max_mailbox_messages=1000)
    s.save()
    for service in ("auth", "storage", "imap"):
        s.start(service)
    wait_tls(s, "imaps")
    user = "imap-client@localhost"
    assert s.rpc("auth", op="create", username=user, password=PASSWORD)["ok"]

    with closing(Wire(s, encrypted=False)) as wire:
        assert b"LOGINDISABLED" in wire.greeting and b"STARTTLS" in wire.greeting
        wire.command("bad", 'LOGIN "' + user + '" "' + PASSWORD + '"', b"NO")
        wire.command("tls", "STARTTLS")
        wire.reader.close()
        wire.sock = context().wrap_socket(wire.sock, server_hostname="localhost")
        wire.reader = wire.sock.makefile("rb")
        assert b"AUTH=LOGIN" in wire.command("cap", "CAPABILITY")
        wire.send("cancel AUTHENTICATE LOGIN\r\n")
        assert wire.line().startswith(b"+ ")
        wire.send("*\r\n")
        wire.response("cancel", b"BAD")
        wire.command("encoding", "AUTHENTICATE LOGIN !!!", b"BAD")
        wire.send("auth AUTHENTICATE LOGIN\r\n")
        assert wire.line() == b"+ VXNlcm5hbWU6\r\n"
        wire.send(base64.b64encode(user.encode()) + b"\r\n")
        assert wire.line() == b"+ UGFzc3dvcmQ6\r\n"
        wire.send(base64.b64encode(PASSWORD.encode()) + b"\r\n")
        assert b"CAPABILITY" in wire.response("auth")
        assert b'(("" "/")) NIL NIL' in wire.command("namespace", "NAMESPACE")
        # A TLS application record containing DONE and the next command must
        # preserve framing, including in authenticated/non-selected state.
        wire.send("idle IDLE\r\n")
        assert wire.line().startswith(b"+ ")
        wire.send("DONE\r\npipeline NOOP\r\n")
        wire.response("idle")
        wire.response("pipeline")
        wire.command("bye", "LOGOUT")
    for mechanism, initial in (("LOGIN", True), ("PLAIN", False), ("PLAIN", True)):
        with closing(Wire(s)) as wire:
            payload = user.encode() if mechanism == "LOGIN" else f"\0{user}\0{PASSWORD}".encode()
            encoded = base64.b64encode(payload)
            wire.send(b"auth AUTHENTICATE " + mechanism.encode() + (b" " + encoded if initial else b"") + b"\r\n")
            if not initial:
                assert wire.line().startswith(b"+")
                wire.send(encoded + b"\r\n")
            if mechanism == "LOGIN":
                assert wire.line().startswith(b"+")
                wire.send(base64.b64encode(PASSWORD.encode()) + b"\r\n")
            wire.response("auth")
    print("PASS IMAP implicit TLS/STARTTLS, SASL LOGIN/PLAIN initial and continuation, cancellation and TLS-only authentication", flush=True)

    first_raw = (b"From: Sender <sender@example.net>\r\nTo: imap-client@localhost\r\n"
                 b"Date: Sun, 11 Oct 2026 23:59:00 -1100\r\nMessage-ID: <outlook-sync@localhost>\r\n"
                 b"Subject: Outlook synchronization\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nMessage body.\r\n")
    second_raw = first_raw.replace(b"Outlook synchronization", b"Thunderbird synchronization")
    for date, raw in (("12-Oct-2026 08:00:00 +0000", first_raw), ("14-Oct-2026 08:00:00 +0000", second_raw)):
        with imaplib.IMAP4_SSL("localhost", s.ports["imaps"], ssl_context=context(), timeout=10) as client:
            client.login(user, PASSWORD)
            assert client.append("INBOX", None, '"' + date + '"', raw)[0] == "OK"
    with closing(Wire(s)) as wire:
        wire.command("id", 'ID ("name" "Microsoft Outlook" "version" "compatibility-test")')
        wire.login(user)
        wire.command("ns", "NAMESPACE")
        listing = wire.command("list", 'LIST "" "*" RETURN (SPECIAL-USE SUBSCRIBED CHILDREN)')
        assert all(flag in listing for flag in (b"\\Sent", b"\\Drafts", b"\\Trash", b"\\Junk")), listing
        assert b"2 EXISTS" in wire.command("select", 'SELECT "INBOX"')
        assert b"* SEARCH 2\r\n" in wire.command("search", "UID SEARCH SINCE 13-Oct-2026")
        fetch = wire.command("fetch", "UID FETCH 1:* (UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (DATE FROM TO SUBJECT MESSAGE-ID CONTENT-TYPE)])")
        assert b"Outlook synchronization" in fetch and b"BODYSTRUCTURE" in fetch and b"RFC822.SIZE" in fetch, fetch
    with imaplib.IMAP4_SSL("localhost", s.ports["imaps"], ssl_context=context(), timeout=10) as client:
        client.login(user, PASSWORD)
        assert client.select("inbox")[1] == [b"2"]
        assert client.uid("search", None, "BEFORE", "13-Oct-2026")[1] == [b"1"]
        assert client.uid("search", None, "ON", "14-Oct-2026")[1] == [b"2"]
        assert client.uid("search", None, "SENTON", "11-Oct-2026")[1] == [b"1 2"]
        assert client.uid("search", None, "SENTBEFORE", "12-Oct-2026")[1] == [b"1 2"]
        assert client.uid("search", None, "SENTSINCE", "12-Oct-2026")[1] == [b""]
        assert client.uid("search", None, '(OR (SINCE 13-Oct-2026 SUBJECT "Thunderbird") (NOT SINCE 13-Oct-2026))')[1] == [b"1 2"]
        assert literal(client.uid("fetch", "1", "(BODY.PEEK[])")[1]) == first_raw
        assert all(not item["seen"] for item in s.rpc("storage", op="list", username=user)["messages"])
        time.sleep(3)
        assert client.noop()[0] == "OK", "authenticated client incorrectly inherited the short line timeout"
    print("PASS Outlook/Thunderbird-style ID/NAMESPACE/LIST, date and nested SEARCH, header/body synchronization and authenticated idle timeout", flush=True)

    nested, renamed = "Projects/测试😀&/Child", "Renamed/测试😀&/Child"
    with imaplib.IMAP4_SSL("localhost", s.ports["imaps"], ssl_context=context(), timeout=10) as client:
        client.login(user, PASSWORD)
        assert client.create(mailbox(nested))[0] == "OK"
        assert client.create(mailbox("CaseFolder"))[0] == "OK"
        assert client.create(mailbox("casefolder"))[0] == "OK"
        assert client.subscribe(mailbox(nested))[0] == "OK"
        listing = b" ".join(client.list('""', '"%"')[1])
        assert b'"Projects"' in listing and b"\\Noselect" in listing and modified_utf7(nested).encode() not in listing
        assert modified_utf7(nested).encode() in b" ".join(client.lsub('""', '"*"')[1])
        parent_lsub=b" ".join(client.lsub('""', '"%"')[1])
        assert b'"Projects"' in parent_lsub and b"\\Noselect" in parent_lsub,parent_lsub
        with closing(Wire(s)) as wire:
            wire.login(user)
            recursive=wire.command("recursive", 'LIST (SUBSCRIBED RECURSIVEMATCH) "" "%" RETURN (CHILDREN)')
            assert b'"Projects" (CHILDINFO ("SUBSCRIBED"))' in recursive,recursive
        assert client.append(mailbox(nested), r"(\Seen \Answered $Label1)", None, first_raw)[0] == "OK"
        assert client.select(mailbox(nested))[1] == [b"1"]
        original = s.rpc("storage", op="list", username=user, folder=nested)
        original_uid = str(original["messages"][0]["uid"])
        assert client.rename(mailbox("Projects"), mailbox("Renamed"))[0] == "OK"
        assert client.uid("search", None, "ALL")[1] == [original_uid.encode()]
        renamed_box = s.rpc("storage", op="list", username=user, folder=renamed)
        assert renamed_box["messages"][0]["uid"] == original["messages"][0]["uid"]
        assert client.uid("copy", original_uid, "Archive")[0] == "OK"
        assert client.uid("move", original_uid, "Trash")[0] == "OK"
        assert client.uid("search", None, "ALL")[1] == [b""]
        assert client.unselect()[0] == "OK"
        assert client.delete(mailbox(renamed))[0] == "OK"
        assert client.unsubscribe(mailbox("CaseFolder"))[0] == "OK"
        assert client.create(mailbox("Sent/Work"))[0]=="OK"
        assert client.select(mailbox("sent/Work"))[1]==[b"0"]
        assert client.rename(mailbox("sent/Work"),mailbox("archive/Work"))[0]=="OK"
        assert client.noop()[0]=="OK"
        assert client.delete(mailbox("archive/Work"))[0]=="NO"
        assert client.unselect()[0]=="OK"
        assert client.delete(mailbox("Archive/Work"))[0]=="OK"
        assert client.select("INBOX")[0] == "OK"
        assert client.uid("store", "1", "+FLAGS.SILENT", r"(\Deleted $Label1 $label1 Work)")[0] == "OK"
        assert client.uid("search", None, "KEYWORD", "$label1")[1] == [b"1"]
        assert client.uid("search", None, "UNKEYWORD", "$LABEL1")[1] == [b"2"]
    s.stop("storage")
    s.start("storage")
    with imaplib.IMAP4_SSL("localhost", s.ports["imaps"], ssl_context=context(), timeout=10) as client:
        client.login(user, PASSWORD)
        subscriptions=b" ".join(client.lsub('""', '"*"')[1])
        assert b'"casefolder"' in subscriptions and b'"CaseFolder"' not in subscriptions, subscriptions
        assert client.select("INBOX", readonly=True)[1] == [b"2"]
        flag_data = b" ".join(client.uid("fetch", "1", "(FLAGS)")[1])
        assert all(flag in flag_data for flag in (b"\\Deleted", b"$Label1", b"Work")), flag_data
        assert client.uid("store", "1", "+FLAGS", r"(\Seen)")[0] == "NO"
        assert client.select("INBOX")[0] == "OK"
        assert client.uid("store", "1", "-FLAGS", "($LABEL1)")[0] == "OK"
        assert client.uid("search", None, "KEYWORD", "$Label1")[1] == [b""]
        assert client.uid("expunge", "1")[0] == "OK"
        assert client.uid("search", None, "ALL")[1] == [b"2"]
        assert client.select("Archive")[1] == [b"1"]
        assert b"$Label1" in b" ".join(client.fetch("1", "FLAGS")[1])
        # FLAGS replaces keywords as well as standard flags.
        assert client.store("1", "FLAGS", r"(\Seen Final)")[0] == "OK"
        assert client.search(None, "KEYWORD", "Final")[1] == [b"1"]
        assert client.search(None, "KEYWORD", "$Label1")[1] == [b""]
    print("PASS UTF-7 Chinese/emoji/& hierarchical folders, case-sensitive custom names, rename/copy/move, persistent subscriptions/Deleted/keywords and read-only mailboxes", flush=True)

    # Independent clients retain their own sequence snapshots. A later STORE
    # from a stale snapshot must merge flags atomically, and EXPUNGE must check
    # the database's current Deleted value before permanently removing mail.
    with authenticated(s,user) as first, authenticated(s,user) as second:
        first.select("INBOX")
        second.select("INBOX")
        assert first.uid("store", "2", "+FLAGS.SILENT", r"(\Deleted \Flagged First)")[0] == "OK"
        assert second.uid("store", "2", "+FLAGS.SILENT", r"(\Seen Second)")[0] == "OK"
        state=s.rpc("storage", op="list", username=user)["messages"][0]
        assert state["deleted"] and state["flagged"] and state["seen"] and set(state["keywords"])=={"First","Second"},state
        assert second.uid("store", "2", "-FLAGS.SILENT", r"(\Deleted First)")[0] == "OK"
        assert first.expunge()[0] == "OK"
        assert len(s.rpc("storage", op="list", username=user)["messages"]) == 1
        state=s.rpc("storage", op="list", username=user)["messages"][0]
        assert not state["deleted"] and state["flagged"] and state["seen"] and state["keywords"]==["Second"],state
        assert first.uid("search", None, "UNDELETED")[1]==[b"2"]
        assert second.uid("store", "2", "+FLAGS.SILENT", r"(\Deleted)")[0]=="OK"
        assert first.expunge()[0]=="OK"
        assert not s.rpc("storage",op="list",username=user)["messages"]
    print("PASS concurrent STORE merges flags/keywords and stale EXPUNGE preserves another client's unmarked message", flush=True)

    recent_user="imap-recent@localhost"
    assert s.rpc("auth",op="create",username=recent_user,password=PASSWORD)["ok"]
    assert s.rpc("storage",op="append",username=recent_user,folder="INBOX",raw=first_raw)["ok"]
    with authenticated(s,recent_user) as first, authenticated(s,recent_user) as second:
        assert b"RECENT 1" in first.status("INBOX","(RECENT)")[1][0]
        assert first.select("INBOX",readonly=True)[0]=="OK"
        assert first.search(None,"RECENT")[1]==[b"1"]
        assert s.rpc("storage",op="list",username=recent_user)["messages"][0]["recent"]
        assert first.select("INBOX")[0]=="OK"
        assert first.search(None,"NEW")[1]==[b"1"]
        assert not s.rpc("storage",op="list",username=recent_user)["messages"][0]["recent"]
        assert second.select("INBOX")[0]=="OK"
        assert second.search(None,"RECENT")[1]==[b""]
        assert second.search(None,"OLD")[1]==[b"1"]
        assert first.noop()[0]=="OK"
        assert first.search(None,"RECENT")[1]==[b"1"]
        assert b"\\Recent" in b" ".join(first.fetch("1","(FLAGS)")[1])
        assert b"\\Recent" not in b" ".join(second.fetch("1","(FLAGS)")[1])
        assert first.fetch("1","(BODY[])")[0]=="OK"
        assert first.search(None,"NEW")[1]==[b""]
        assert first.search(None,"RECENT")[1]==[b"1"]
        assert first.select("INBOX")[0]=="OK"
        assert first.search(None,"RECENT")[1]==[b""]
        assert s.rpc("storage",op="append",username=recent_user,folder="INBOX",raw=second_raw)["ok"]
        assert first.noop()[0]=="OK"
        assert first.search(None,"RECENT")[1]==[b"2"]
        assert second.noop()[0]=="OK"
        assert second.search(None,"RECENT")[1]==[b""]
    print("PASS durable Recent claiming, read-only EXAMINE, per-session flags/NEW/OLD, and one-reader claims across concurrent clients",flush=True)
    for idle in (False,True):
        assert s.rpc("storage",op="folder_create",username=recent_user,folder="Disappearing")["ok"]
        with closing(Wire(s)) as wire:
            wire.login(recent_user)
            wire.command("select",'SELECT "Disappearing"')
            if idle:
                wire.send("idle IDLE\r\n")
                assert wire.line().startswith(b"+")
                assert s.rpc("storage",op="folder_rename",username=recent_user,folder="Disappearing",target="Moved")["ok"]
            else:
                assert s.rpc("storage",op="folder_delete",username=recent_user,folder="Disappearing")["ok"]
                wire.send("noop NOOP\r\n")
            gone=wire.line();assert gone==b"* BYE Selected mailbox unavailable; reconnect\r\n",gone
    print("PASS another client's selected-folder deletion/rename closes the stale selected connection and IDLE cleanly",flush=True)

    idle_user = "imap-idle@localhost"
    assert s.rpc("auth", op="create", username=idle_user, password=PASSWORD)["ok"]
    with closing(Wire(s)) as wire:
        wire.login(idle_user)
        wire.command("select", "SELECT INBOX")
        wire.send("idle IDLE\r\n")
        assert wire.line().startswith(b"+ ")
        time.sleep(3)
        added = s.rpc("storage", op="append", username=idle_user, folder="INBOX", raw=first_raw)
        assert added["ok"], added
        assert wire.line() == b"* 1 EXISTS\r\n"
        assert wire.line() == b"* 1 RECENT\r\n"
        message = s.rpc("storage", op="list", username=idle_user)["messages"][0]
        assert s.rpc("storage", op="flags", username=idle_user, id=message["id"], uid=message["uid"], seen=True)["ok"]
        flags=wire.line();assert b"FLAGS (" in flags and b"\\Seen" in flags,flags
        assert s.rpc("storage", op="delete", username=idle_user, ids=[message["id"]], permanent=True)["ok"]
        assert wire.line() == b"* 1 EXPUNGE\r\n"
        assert wire.line() == b"* 0 EXISTS\r\n"
        assert wire.line() == b"* 0 RECENT\r\n"
        wire.send("DONE\r\nnext NOOP\r\n")
        wire.response("idle")
        wire.response("next")
        small = b"Subject: non-sync append\r\n\r\nbody\r\n"
        wire.send(b'append APPEND INBOX (\\Deleted Marker) {' + str(len(small)).encode() + b'+}\r\n' + small + b'\r\nnoop NOOP\r\n')
        wire.response("append")
        wire.response("noop")
        # A mailbox name can itself be a non-synchronizing command literal.
        wire.send(b"literal CREATE {12+}\r\nLiteral Name\r\n")
        wire.response("literal")
        wire.command("selectlit", 'SELECT "Literal Name"')
        wire.send("last IDLE\r\n")
        assert wire.line().startswith(b"+ ")
        assert s.rpc("auth", op="change_password", username=idle_user, password=PASSWORD + "changed")["ok"]
        assert wire.line() == b"* BYE Account credentials changed\r\n"
    print("PASS TLS IDLE EXISTS/FLAGS/EXPUNGE, DONE+next command in one record, credential revocation, LITERAL- APPEND and mailbox framing", flush=True)
    for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        partial_user = f"partial-{version.value}@localhost"
        assert s.rpc("auth", op="create", username=partial_user, password=PASSWORD)["ok"]
        with closing(RecordWire(s, version)) as wire:
            wire.login(partial_user)
            wire.command("select", "SELECT INBOX")
            wire.send("idle IDLE\r\n")
            assert wire.line().startswith(b"+ ")
            tail = wire.split_record(b"DONE\r\nnext NOOP\r\n")
            added = s.rpc("storage", op="append", username=partial_user, folder="INBOX", raw=first_raw)
            assert added["ok"], added
            # A notification must arrive while the client still withholds the
            # record tail: completion requires surviving the TLS input poll.
            assert wire.line() == b"* 1 EXISTS\r\n"
            assert wire.line() == b"* 1 RECENT\r\n"
            wire.sock.sendall(tail)
            wire.response("idle")
            wire.response("next")
    print("PASS TLS 1.2/1.3 partial records survive IDLE poll expiry, allow server notifications and preserve DONE plus the next command", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    arguments = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("imap-clients-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(arguments.bin_dir.resolve(), directory)
    try:
        run(suite)
    finally:
        suite.close()
