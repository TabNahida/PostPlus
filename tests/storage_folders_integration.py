#!/usr/bin/env python3
"""Offline v2 storage migration, custom mailbox and persistent flag regressions."""
import argparse
import concurrent.futures
import contextlib
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile

from integration import decode_wire, encode_wire
from storage_integration import Services


OWNER = "alice@localhost"
RAW = b"From: alice@localhost\r\nTo: bob@localhost\r\nSubject: Folder fixture\r\n\r\nBinary byte: \xff\r\n"
TABLES = ("messages", "mailboxes", "deliveries", "queue", "submissions",
          "submission_deliveries", "forwarding_rules", "queue_routes", "deleted_mailboxes")


def seed_v2(directory):
    """Keep the released schema explicit so new schema generation cannot mask migration bugs."""
    data = directory / "data"
    data.mkdir()
    with contextlib.closing(sqlite3.connect(data / "storage.sqlite3")) as database:
        database.executescript("""
            CREATE TABLE mailboxes(username TEXT PRIMARY KEY,uidvalidity INTEGER NOT NULL CHECK(uidvalidity>0),
                uidnext INTEGER NOT NULL CHECK(uidnext>0),quota_bytes INTEGER CHECK(quota_bytes>0),
                quota_messages INTEGER CHECK(quota_messages>0));
            CREATE TABLE messages(id TEXT PRIMARY KEY,username TEXT NOT NULL REFERENCES mailboxes(username),
                uid INTEGER NOT NULL CHECK(uid>0),raw BLOB NOT NULL,size INTEGER NOT NULL,
                seen INTEGER NOT NULL DEFAULT 0 CHECK(seen IN(0,1)),created_at INTEGER NOT NULL,
                folder TEXT NOT NULL DEFAULT 'INBOX' CHECK(folder IN('INBOX','Sent','Trash','Drafts','Junk','Archive')),
                UNIQUE(username,uid));
            CREATE INDEX messages_folder ON messages(username,folder,uid);
            CREATE TABLE message_flags(id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
                answered INTEGER NOT NULL DEFAULT 0 CHECK(answered IN(0,1)),
                flagged INTEGER NOT NULL DEFAULT 0 CHECK(flagged IN(0,1)),
                draft INTEGER NOT NULL DEFAULT 0 CHECK(draft IN(0,1)));
            CREATE TABLE deliveries(username TEXT NOT NULL,delivery_id TEXT NOT NULL,message_id TEXT NOT NULL,
                PRIMARY KEY(username,delivery_id));
            CREATE TABLE queue(id TEXT PRIMARY KEY,submission_id TEXT NOT NULL,sender TEXT NOT NULL,
                recipient TEXT NOT NULL,raw BLOB NOT NULL,size INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt INTEGER NOT NULL,created_at INTEGER NOT NULL,
                state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN('pending','quarantined')),
                last_error TEXT NOT NULL DEFAULT '');
            CREATE INDEX queue_due ON queue(state,next_attempt,created_at);
            CREATE TABLE submissions(username TEXT NOT NULL,request_id TEXT NOT NULL,fingerprint TEXT NOT NULL,
                submission_id TEXT NOT NULL,sent_id TEXT NOT NULL,PRIMARY KEY(username,request_id));
            CREATE TABLE forwarding_rules(id INTEGER PRIMARY KEY AUTOINCREMENT,domain TEXT NOT NULL,
                pattern TEXT NOT NULL,destination TEXT NOT NULL,created_at INTEGER NOT NULL,UNIQUE(domain,pattern));
            CREATE TABLE queue_routes(queue_id TEXT PRIMARY KEY,recipient TEXT NOT NULL,destination TEXT NOT NULL,
                rule_id INTEGER,pattern TEXT NOT NULL DEFAULT '');
            CREATE TABLE submission_deliveries(username TEXT NOT NULL,submission_id TEXT NOT NULL,
                message_id TEXT NOT NULL,PRIMARY KEY(username,submission_id));
            CREATE TABLE deleted_mailboxes(username TEXT PRIMARY KEY);
            PRAGMA user_version=2;
        """)
        database.execute("INSERT INTO mailboxes VALUES(?,12345,9,1048576,100)", (OWNER,))
        for identifier, uid, folder in (("legacy", 7, "INBOX"), ("sent", 8, "Sent")):
            database.execute("INSERT INTO messages VALUES(?,?,?,?,?,1,1700000000,?)",
                             (identifier, OWNER, uid, RAW, len(RAW), folder))
            database.execute("INSERT INTO message_flags VALUES(?,1,1,0)", (identifier,))
        database.execute("INSERT INTO deliveries VALUES(?,'legacy-job','legacy')", (OWNER,))
        database.execute("INSERT INTO submission_deliveries VALUES(?,'legacy-delivery','legacy')", (OWNER,))
        database.execute("INSERT INTO submissions VALUES(?,'legacy-send','fixture-fingerprint','submission','sent')", (OWNER,))
        database.execute("INSERT INTO queue VALUES('queued','submission',?,'bob@localhost',?,?,2,1700000100,1700000000,'pending','retry')",
                         (OWNER, RAW, len(RAW)))
        database.execute("INSERT INTO forwarding_rules VALUES(1,'localhost','sales-*',?,1700000000)", (OWNER,))
        database.execute("INSERT INTO queue_routes VALUES('queued','sales-test@localhost',?,1,'sales-*')", (OWNER,))
        database.execute("INSERT INTO deleted_mailboxes VALUES('removed@localhost')")
        database.commit()


def snapshot(path):
    with contextlib.closing(sqlite3.connect(path)) as database:
        return {table: database.execute("SELECT * FROM " + table + " ORDER BY 1").fetchall() for table in TABLES}


def rpc(services, op, **fields):
    connection = http.client.HTTPConnection("127.0.0.1", services.ports["storage"], timeout=15)
    try:
        connection.request("POST", "/rpc", json.dumps(encode_wire(dict(op=op, username=OWNER, **fields))),
                           {"Content-Type": "application/json", "Authorization": "Bearer " + services.token})
        response = connection.getresponse()
        result = decode_wire(json.loads(response.read()))
        assert response.status in (200, 400, 413), (response.status, result)
        return result
    finally:
        connection.close()


def checks(services):
    def ok(op, **fields):
        result = rpc(services, op, **fields)
        assert result["ok"], (op, result)
        return result

    database_path = services.directory / "data/storage.sqlite3"
    before = snapshot(database_path)
    services.start("storage")
    assert snapshot(database_path) == before, "migration changed persisted mail, quota, queue or receipt rows"
    with contextlib.closing(sqlite3.connect(database_path)) as database:
        assert database.execute("PRAGMA user_version").fetchone() == (2,)
        assert not database.execute("PRAGMA foreign_key_check").fetchall()
        assert database.execute("SELECT id,answered,flagged,draft,deleted,keywords FROM message_flags ORDER BY id").fetchall() == [
            ("legacy", 1, 1, 0, 0, "[]"), ("sent", 1, 1, 0, 0, "[]")]
    assert ok("get", id="legacy")["raw"] == RAW
    assert ok("list")["uidvalidity"] == 12345 and ok("list")["uidnext"] == 9
    assert not any(item["recent"] for item in ok("list")["messages"]), "migration marked historical mail Recent"
    assert ok("deliver", raw=RAW, delivery_id="legacy-job")["duplicate"]
    assert ok("deliver", raw=RAW, delivery_id="replayed-job", submission_id="legacy-delivery")["duplicate"]

    folder = "Projects/旅行/2026"
    ok("folder_create", folder=folder)
    catalog = {item["name"]: item for item in ok("folder_catalog")["folders"]}
    assert not catalog["Projects"]["selectable"] and not catalog["Projects/旅行"]["selectable"]
    assert not catalog["Projects"]["subscribed"] and catalog[folder]["subscribed"]
    ok("folder_create", folder="Projects")
    assert not rpc(services, "folder_create", folder="Projects")["ok"]
    for invalid in ("", "../bad", "A//B", "/A", "A/", "A\x7fB", "A/../B", "A/" * 16 + "B"):
        assert not rpc(services, "folder_create", folder=invalid)["ok"], invalid
    message = ok("append", folder=folder, raw=RAW, flagged=True, deleted=True, keywords=["$label1", "Tag", "tag"])
    listed = ok("list", folder=folder)["messages"][0]
    assert listed["deleted"] and listed["keywords"] == ["$label1", "Tag"] and listed["flagged"] and listed["recent"]
    assert ok("list", folder=folder)["messages"][0]["recent"], "read-only discovery consumed Recent"
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        claims = list(executor.map(lambda _: ok("list", folder=folder, claim_recent=True), range(2)))
    assert sum(item["recent"] for claim in claims for item in claim["messages"]) == 1
    assert not ok("list", folder=folder)["messages"][0]["recent"]
    assert not rpc(services, "append", folder="Missing", raw=RAW)["ok"]
    for invalid in (["bad keyword"], ["\\Seen"], ["bad]"], ["x"] * 65, "invalid"):
        assert not rpc(services, "flags", id=message["id"], keywords=invalid)["ok"]
    assert ok("list", folder=folder)["messages"][0]["keywords"] == ["$label1", "Tag"]
    # Two clients can add unrelated flags from stale snapshots without replacing
    # each other's current values, and keyword matching is case insensitive.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        updates = list(executor.map(lambda fields: ok("flags", id=message["id"], uid=message["uid"],
                                                      flags_operation="add", **fields),
                                    ({"answered": True, "keywords": ["Client-A"]},
                                     {"seen": True, "keywords": ["Client-B"]})))
    actual = ok("list", folder=folder)["messages"][0]
    assert actual["answered"] and actual["seen"] and actual["flagged"] and actual["deleted"]
    assert {item.lower() for item in actual["keywords"]} == {"$label1", "tag", "client-a", "client-b"}
    assert all("flags" in update for update in updates)
    changed = ok("flags", id=message["id"], flags_operation="remove", answered=True, keywords=["CLIENT-A"])["flags"]
    assert not changed["answered"] and changed["seen"] and changed["flagged"] and changed["deleted"]
    assert "Client-A" not in changed["keywords"] and "Client-B" in changed["keywords"]
    ok("flags", id=message["id"], deleted=False, keywords=["$Junk"])
    ok("folder_subscribe", folder=folder, subscribed=False)
    ok("folder_subscribe", folder="Sent", subscribed=False)
    copied = ok("copy", folder="Archive", source_folder=folder, ids=[message["id"]])
    archived = next(item for item in ok("list", folder="Archive")["messages"] if item["uid"] == copied["mappings"][0]["uid"])
    assert archived["flagged"] and not archived["deleted"] and archived["keywords"] == ["$Junk"]
    original_usage = ok("quota_get")
    ok("folder_rename", folder="Projects", target="工作")
    renamed = "工作/旅行/2026"
    after = ok("list", folder=renamed)["messages"][0]
    assert after["id"] == message["id"] and after["uid"] == message["uid"] and after["keywords"] == ["$Junk"]
    assert ok("quota_get") == original_usage
    assert not rpc(services, "folder_rename", folder="工作", target="工作/loop")["ok"]
    assert not rpc(services, "folder_rename", folder="工作", target="Archive")["ok"]
    assert ok("get", id=message["id"], folder=renamed)["raw"] == RAW
    assert len(ok("folders")["folders"]) == 8  # Six system, selectable parent and leaf.
    services.stop("storage")
    services.start("storage")
    catalog = {item["name"]: item for item in ok("folder_catalog")["folders"]}
    assert not catalog["Sent"]["subscribed"] and not catalog[renamed]["subscribed"]
    assert ok("list", folder=renamed)["messages"][0]["keywords"] == ["$Junk"]
    assert not ok("list", folder=renamed)["messages"][0]["recent"], "claim watermark was lost on restart/rename"
    ok("folder_delete", folder="工作")
    catalog = {item["name"]: item for item in ok("folder_catalog")["folders"]}
    assert not catalog["工作"]["selectable"] and catalog[renamed]["selectable"]
    assert not rpc(services, "folder_delete", folder="INBOX")["ok"]
    ok("folder_delete", folder=renamed)
    assert not rpc(services, "get", id=message["id"])["ok"]
    assert not any(item["name"].startswith("工作") for item in ok("folder_catalog")["folders"])
    assert ok("quota_get")["messages"] == original_usage["messages"] - 1
    ok("folder_create", folder=renamed)
    assert ok("append", folder=renamed, raw=RAW)["uid"] > message["uid"]

    # Inject a failure after one subtree row has moved, proving DDL-independent
    # rename writes are atomic and do not leave orphaned parent/catalog rows.
    before = snapshot(database_path)
    before_catalog = ok("folder_catalog")
    with contextlib.closing(sqlite3.connect(database_path)) as database:
        database.executescript("CREATE TRIGGER fail_folder_rename BEFORE UPDATE OF name ON mailbox_folders "
                               "WHEN OLD.name='工作/旅行' BEGIN SELECT RAISE(ABORT,'injected rename failure'); END;")
    try:
        connection = http.client.HTTPConnection("127.0.0.1", services.ports["storage"], timeout=10)
        try:
            connection.request("POST", "/rpc", json.dumps(dict(op="folder_rename", username=OWNER, folder="工作", target="Rollback")),
                               {"Content-Type": "application/json", "Authorization": "Bearer " + services.token})
            response = connection.getresponse()
            assert response.status == 503 and not json.loads(response.read())["ok"]
        finally:
            connection.close()
    finally:
        with contextlib.closing(sqlite3.connect(database_path)) as database:
            database.execute("DROP TRIGGER fail_folder_rename")
            database.commit()
    assert snapshot(database_path) == before and ok("folder_catalog") == before_catalog

    # A client holding a stale Deleted flag must not expunge a message whose
    # current flag was cleared, or delete a message since moved to another UID.
    expunged = ok("append", raw=RAW, deleted=True)
    criteria = dict(ids=[expunged["id"]], permanent=True, require_deleted=True,
                    expected_uids={expunged["id"]: expunged["uid"]}, folder="INBOX")
    ok("flags", id=expunged["id"], deleted=False)
    assert ok("delete", **criteria)["deleted_ids"] == []
    assert ok("get", id=expunged["id"])["raw"] == RAW
    ok("flags", id=expunged["id"], deleted=True)
    ok("move", ids=[expunged["id"]], folder="Archive")
    assert ok("delete", **criteria)["deleted_ids"] == []
    moved = ok("get", id=expunged["id"])
    criteria.update(expected_uids={expunged["id"]: moved["uid"]}, folder="Archive")
    assert ok("delete", **criteria)["deleted_ids"] == [expunged["id"]]
    assert not rpc(services, "get", id=expunged["id"])["ok"]
    services.stop("storage")
    with contextlib.closing(sqlite3.connect(database_path)) as database:
        assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert not database.execute("PRAGMA foreign_key_check").fetchall()


def check_rollback(binaries, directory):
    seed_v2(directory)
    path = directory / "data/storage.sqlite3"
    with contextlib.closing(sqlite3.connect(path)) as database:
        database.execute("PRAGMA ignore_check_constraints=ON")
        database.execute("UPDATE messages SET uid=0 WHERE id='legacy'")
        database.commit()
    before = snapshot(path)
    services = Services(binaries, directory)
    try:
        try:
            services.start("storage")
        except AssertionError:
            pass
        else:
            raise AssertionError("corrupt legacy UID unexpectedly migrated")
    finally:
        services.close()
    assert snapshot(path) == before
    with contextlib.closing(sqlite3.connect(path)) as database:
        assert database.execute("PRAGMA user_version").fetchone() == (2,)
        assert not database.execute("SELECT 1 FROM sqlite_master WHERE name IN('messages_v3','mailbox_folders')").fetchall()
        assert [item[1] for item in database.execute("PRAGMA table_info(message_flags)")] == ["id", "answered", "flagged", "draft"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", required=True, type=Path)
    binaries = parser.parse_args().bin_dir.resolve()
    with tempfile.TemporaryDirectory(prefix="postplus-storage-folders-") as temporary:
        directory = Path(temporary)
        migration = directory / "migration"
        migration.mkdir()
        seed_v2(migration)
        services = Services(binaries, migration)
        try:
            checks(services)
        finally:
            services.close()
        rollback = directory / "rollback"
        rollback.mkdir()
        check_rollback(binaries, rollback)
    print("Offline v2 migration, Unicode folders, persistent subscriptions/flags and atomic rollback checks passed.")


if __name__ == "__main__":
    main()
