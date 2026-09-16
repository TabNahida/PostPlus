#!/usr/bin/env python3
"""Real-process folder migration, per-user quota and atomic Sent/draft checks."""
import argparse
import concurrent.futures
import contextlib
import http.client
import imaplib
import json
from pathlib import Path
import poplib
import sqlite3
import tempfile

from storage_integration import Services, free_port


RAW = "From: alice@localhost\r\nTo: bob@localhost\r\nSubject: Folder test\r\n\r\nPersistent body\r\n"
OWNER = "alice@localhost"


def seed_v1(directory):
    """Use the prior released schema, not the new server's schema generator."""
    data = directory / "data"
    data.mkdir()
    with contextlib.closing(sqlite3.connect(data / "storage.sqlite3")) as database:
        database.executescript("""
            CREATE TABLE mailboxes(username TEXT PRIMARY KEY,uidvalidity INTEGER NOT NULL,uidnext INTEGER NOT NULL);
            CREATE TABLE messages(id TEXT PRIMARY KEY,username TEXT NOT NULL REFERENCES mailboxes(username),
                uid INTEGER NOT NULL,raw BLOB NOT NULL,size INTEGER NOT NULL,seen INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,UNIQUE(username,uid));
            CREATE TABLE deliveries(username TEXT NOT NULL,delivery_id TEXT NOT NULL,message_id TEXT NOT NULL,
                PRIMARY KEY(username,delivery_id));
            CREATE TABLE queue(id TEXT PRIMARY KEY,submission_id TEXT NOT NULL,sender TEXT NOT NULL,recipient TEXT NOT NULL,
                raw BLOB NOT NULL,size INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL,
                created_at INTEGER NOT NULL,state TEXT NOT NULL DEFAULT 'pending',last_error TEXT NOT NULL DEFAULT '');
            PRAGMA user_version=1;
        """)
        database.execute("INSERT INTO mailboxes VALUES(?,12345,8)", (OWNER,))
        database.execute("INSERT INTO messages VALUES('legacy',?,7,?,?,0,1700000000)", (OWNER, RAW.encode(), len(RAW)))
        database.execute("INSERT INTO deliveries VALUES(?,'legacy-job','legacy')", (OWNER,))
        database.commit()


def checks(services):
    rpc = lambda op, **fields: services.rpc("storage", op, **fields)
    listing = lambda name="INBOX", user=OWNER: rpc("list", username=user, folder=name)
    usage = lambda: rpc("quota_get", username=OWNER)
    old = listing()
    assert old["uidvalidity"] == 12345 and old["uidnext"] == 8
    assert old["messages"][0]["uid"] == 7 and old["messages"][0]["folder"] == "INBOX"
    assert rpc("get", username=OWNER, id="legacy")["raw"] == RAW
    summary = rpc("list", username=OWNER, include_envelope=True)["messages"][0]
    assert summary["to"] == "bob@localhost"
    folders = rpc("folders", username=OWNER)
    assert [item["name"] for item in folders["folders"]] == ["INBOX", "Sent", "Trash", "Drafts", "Junk", "Archive"]
    assert folders["usage"]["bytes"] == len(RAW) and folders["usage"]["messages"] == 1
    assert folders["folders"][0]["unseen"] == 1
    assert not rpc("list", username=OWNER, folder="unsupported")["ok"]
    assert not rpc("move", username=OWNER, ids=["legacy"], folder="../../Sent")["ok"]
    assert len(listing()["messages"]) == 1
    assert rpc("move", username="bob@localhost", ids=["legacy"], folder="Archive")["ok"]
    assert len(listing()["messages"]) == 1
    for target in ("Archive", "Junk", "INBOX"):
        before = rpc("get", username=OWNER, id="legacy")
        assert rpc("move", username=OWNER, ids=["legacy"], folder=target)["ok"]
        after = rpc("get", username=OWNER, id="legacy")
        assert after["folder"] == target and after["uid"] > before["uid"]
        assert listing(target)["uidvalidity"] == 12345
        assert usage()["bytes"] == len(RAW)
    # Default deletion is recoverable and still consumes capacity.
    assert rpc("delete", username=OWNER, ids=["legacy"])["ok"]
    assert not listing()["messages"] and len(listing("Trash")["messages"]) == 1
    assert usage()["bytes"] == len(RAW)
    assert rpc("deliver", username=OWNER, raw=RAW, delivery_id="legacy-job")["id"] == "legacy"
    assert not listing()["messages"]
    assert rpc("move", username=OWNER, ids=["legacy"], folder="INBOX")["ok"]

    # Persist limits beyond signed int32 and reject values before conversion.
    huge = 5 * 1024 ** 3
    assert rpc("quota_set", username=OWNER, max_bytes=huge, max_messages=2)["max_bytes"] == huge
    for invalid in (-1, 0, 1.5, "1024", True, 2 ** 63, 2 ** 64 - 1):
        assert not rpc("quota_set", username=OWNER, max_bytes=invalid)["ok"]
    assert usage()["max_bytes"] == huge
    assert rpc("quota_set", username=OWNER, max_bytes=len(RAW), max_messages=1)["ok"]
    assert not rpc("deliver", username=OWNER, raw=RAW, delivery_id="over-quota")["ok"]
    assert not rpc("draft_save", username=OWNER, raw=RAW)["ok"]
    assert not rpc("enqueue", sender=OWNER, sent_username=OWNER, recipients=["bob@localhost"], raw=RAW)["ok"]
    assert rpc("stats")["queued"] == 0 and usage()["messages"] == 1
    # Another user inherits global capacity independently of this override.
    other = rpc("deliver", username="bob@localhost", raw=RAW, delivery_id="other-user")
    assert other["ok"]
    assert rpc("quota_get", username="bob@localhost")["quota_bytes"] is None
    assert rpc("quota_set", username=OWNER, max_bytes=None, max_messages=None)["ok"]
    assert usage()["quota_bytes"] is None

    # Draft replacement consumes only its current bytes and rotates its IMAP UID.
    draft = rpc("draft_save", username=OWNER, raw=RAW)
    assert draft["ok"] and draft["folder"] == "Drafts"
    replacement = RAW + "edited\r\n"
    changed = rpc("draft_save", username=OWNER, id=draft["id"], uid=draft["uid"], raw=replacement)
    assert changed["id"] == draft["id"] and changed["uid"] > draft["uid"]
    assert usage()["bytes"] == len(RAW) + len(replacement)
    assert not rpc("draft_save", username=OWNER, id=draft["id"], uid=draft["uid"], raw=RAW)["ok"]
    assert not rpc("get", username=OWNER, id=draft["id"], uid=draft["uid"])["ok"]
    assert not rpc("draft_save", username="bob@localhost", id=draft["id"], raw=RAW)["ok"]
    assert not rpc("draft_save", username=OWNER, id="legacy", raw=RAW)["ok"]
    # A lowered quota permits draft reductions and moves, but blocks growth.
    assert rpc("quota_set", username=OWNER, max_bytes=1)["ok"]
    assert not rpc("draft_save", username=OWNER, id=draft["id"], raw=replacement + "more")["ok"]
    assert rpc("draft_save", username=OWNER, id=draft["id"], raw=RAW)["ok"]
    assert rpc("move", username=OWNER, ids=["legacy"], folder="Archive")["ok"]
    assert rpc("quota_set", username=OWNER, max_bytes=None)["ok"]

    submission = dict(sender=OWNER, sent_username=OWNER, recipients=["bob@localhost", "bob@localhost"],
                      raw=RAW, draft_id=draft["id"], submission_id="stable-send")
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(lambda _: rpc("enqueue", **submission), range(6)))
    assert all(item["ok"] for item in results), results
    assert len({item["id"] for item in results}) == 1
    assert all(item["sent_id"] == draft["id"] for item in results)
    assert not listing("Drafts")["messages"] and len(listing("Sent")["messages"]) == 1
    assert usage()["messages"] == 2 and usage()["bytes"] == len(RAW) * 2
    assert rpc("stats")["queued"] == 1
    assert not rpc("enqueue", **dict(submission, raw=RAW + "different"))["ok"]
    assert not rpc("enqueue", **dict(submission, submission_id="second-send"))["ok"]
    assert rpc("stats")["queued"] == 1
    for job in rpc("queue_inspect")["jobs"]:
        assert rpc("queue_finish", id=job["id"])["ok"]
    assert rpc("delete", username=OWNER, ids=[draft["id"]], permanent=True)["ok"]
    # Durable receipts must survive delivery completion, Sent deletion and restart.
    services.stop("storage")
    services.start("storage")
    retry = rpc("enqueue", **submission)
    assert retry["ok"] and retry["duplicate"] and retry["id"] == results[0]["id"]
    assert rpc("stats")["queued"] == 0 and not listing("Sent")["messages"]
    assert listing("Archive")["uidvalidity"] == 12345

    # Queue rejection is atomic with Sent and draft changes.
    services.stop("storage")
    services.config["max_queue_messages"] = 1
    services.config["max_mailbox_bytes"] = huge
    services.config["max_queue_bytes"] = huge
    services.start("storage")
    assert usage()["max_bytes"] == huge
    blocking = rpc("enqueue", sender="", recipients=["bob@localhost"], raw=RAW)
    assert blocking["ok"]
    held = rpc("draft_save", username=OWNER, raw=RAW)
    blocked = dict(sender=OWNER, sent_username=OWNER, recipients=["bob@localhost"], raw=RAW,
                   draft_id=held["id"], submission_id="queue-full-send")
    assert not rpc("enqueue", **blocked)["ok"]
    assert len(listing("Drafts")["messages"]) == 1 and not listing("Sent")["messages"]
    for job in rpc("queue_inspect")["jobs"]:
        rpc("queue_finish", id=job["id"])
    # Force a real database failure after draft->Sent has been written but
    # before the queue insert completes. The transaction must roll back both.
    before_failure = listing("Drafts")
    with contextlib.closing(sqlite3.connect(services.directory / "data" / "storage.sqlite3")) as database:
        database.execute("CREATE TRIGGER fail_enqueue BEFORE INSERT ON queue BEGIN SELECT RAISE(ABORT, 'injected failure'); END")
        database.commit()
    connection = http.client.HTTPConnection("127.0.0.1", services.ports["storage"], timeout=10)
    try:
        connection.request("POST", "/rpc", json.dumps(dict(op="enqueue", **blocked)),
                           {"Authorization": "Bearer " + services.token, "Content-Type": "application/json"})
        failed = connection.getresponse()
        assert failed.status == 503 and not json.loads(failed.read())["ok"]
    finally:
        connection.close()
        with contextlib.closing(sqlite3.connect(services.directory / "data" / "storage.sqlite3")) as database:
            database.execute("DROP TRIGGER fail_enqueue")
            database.commit()
    assert listing("Drafts") == before_failure
    assert not listing("Sent")["messages"] and rpc("stats")["queued"] == 0
    assert rpc("enqueue", **blocked)["ok"]
    assert not listing("Drafts")["messages"] and len(listing("Sent")["messages"]) == 1
    for job in rpc("queue_inspect")["jobs"]:
        rpc("queue_finish", id=job["id"])

    # Protocol reads share the same six folders; inspection must not mark Seen.
    password = "folder-protocol-test-123!"
    assert services.rpc("auth", "create", username=OWNER, password=password)["ok"]
    services.config["allow_insecure_auth"] = True
    for protocol in ("imap", "pop3"):
        services.ports[protocol] = free_port()
        services.start(protocol)
    client = imaplib.IMAP4("127.0.0.1", services.ports["imap"], timeout=10)
    try:
        assert client.login(OWNER, password)[0] == "OK"
        result = client.list()
        assert result[0] == "OK" and len(result[1]) == 6, result
        assert client.select("Sent", readonly=True)[1] == [b"1"]
        assert client.uid("fetch", "1:*", "(UID BODY.PEEK[])")[0] == "OK"
        assert client.status("Archive", "(MESSAGES UIDNEXT UIDVALIDITY)")[0] == "OK"
        assert client.select("Archive")[1] == [b"1"]
        legacy = rpc("get", username=OWNER, id="legacy")
        assert not legacy["seen"]
        assert client.uid("fetch", str(legacy["uid"]), "(BODY.PEEK[])")[0] == "OK"
        assert not rpc("get", username=OWNER, id="legacy")["seen"]
        assert client.store("1", "+FLAGS", "(\\Deleted)")[0] == "OK"
        # Concurrent web moves must protect messages from old protocol snapshots.
        assert rpc("move", username=OWNER, ids=["legacy"], folder="INBOX")["ok"]
        assert client.expunge()[0] == "OK"
        assert rpc("get", username=OWNER, id="legacy")["folder"] == "INBOX"
        assert client.select("Drafts")[1] == [b"0"]
        live = rpc("draft_save", username=OWNER, raw=RAW)
        client.noop()
        assert client.search(None, "ALL")[1] == [b"1"]
        rpc("draft_save", username=OWNER, id=live["id"], raw=RAW + "next")
        client.noop()
        assert client.search(None, "ALL")[1] == [b"1"]
        assert client.untagged_responses.get("EXPUNGE"), "draft rewrite did not expunge prior UID"
    finally:
        client.logout()
    pop = poplib.POP3("127.0.0.1", services.ports["pop3"], timeout=10)
    try:
        pop.user(OWNER)
        pop.pass_(password)
        assert pop.stat()[0] == 1, "POP3 must only enumerate INBOX"
        pop.dele(1)
        assert rpc("move", username=OWNER, ids=["legacy"], folder="Archive")["ok"]
        pop.quit()
        assert rpc("get", username=OWNER, id="legacy")["folder"] == "Archive"
    finally:
        pop.close()
    services.stop("storage")
    with contextlib.closing(sqlite3.connect(services.directory / "data" / "storage.sqlite3")) as database:
        assert database.execute("PRAGMA user_version").fetchone()[0] == 2
        assert database.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", required=True, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="postplus-folders-") as temporary:
        directory = Path(temporary)
        seed_v1(directory)
        services = Services(args.bin_dir.resolve(), directory)
        try:
            services.start("auth")
            services.start("storage")
            checks(services)
        finally:
            services.close()
    print("Folder migration, quota isolation, atomic Sent/draft retries and IMAP/POP3 folder checks passed.")


if __name__ == "__main__":
    main()
