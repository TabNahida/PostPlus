#!/usr/bin/env python3
"""Local wildcard routing, durable destinations and delivery deduplication."""
import argparse
import contextlib
from email.parser import BytesParser
from email.utils import getaddresses
import secrets
import smtplib
import sqlite3
import time
from pathlib import Path

from integration import PASSWORD, ROOT, Suite, encode_wire


def message(subject):
    return f"From: alice@localhost\r\nSubject: {subject}\r\n\r\nPersistent body\r\n".encode()


def bad(suite, **payload):
    status, _, reply = suite.http("storage", "POST", "/rpc", encode_wire(payload),
                                {"Authorization": f"Bearer {suite.token}"})
    assert status in (200, 400) and not reply["ok"], (status, reply, payload)
    return reply


def jobs(suite):
    return suite.rpc("storage", op="queue_inspect")["jobs"]


def wait_until(check, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError("condition did not become true")


def run(s):
    for name in ("auth", "storage", "filter", "smtp"):
        s.start(name)
    users = ("alice@localhost", "bob@localhost", "charlie@localhost", "sales-vip@localhost", "gone@localhost")
    for user in users:
        assert s.rpc("auth", op="create", username=user, password=PASSWORD)["ok"]
    rpc = lambda op, **fields: s.rpc("storage", op=op, **fields)
    rule = lambda pattern, destination: rpc("forwarding_create", pattern=pattern, destination=destination)["rule"]
    resolve = lambda recipient: rpc("resolve_recipient", recipient=recipient)
    broad = rule("SALES**@LOCALHOST", "bob@localhost")
    assert broad["pattern"] == "sales*"
    assert bad(s, op="forwarding_create", pattern="sales*", destination="bob@localhost")["code"] == "duplicate_rule"
    specific = rule("sales-*", "charlie@localhost")
    rule("sales-vip", "bob@localhost")
    rule("ticket?", "charlie@localhost")
    oldest = rule("*abc", "bob@localhost")
    rule("abc*", "charlie@localhost")
    assert resolve("sales-new@localhost")["destination"] == "charlie@localhost"
    assert resolve("SaLeS12@LOCALHOST")["destination"] == "bob@localhost"
    assert resolve("sales-vip@localhost")["destination"] == "sales-vip@localhost"
    assert resolve("ticket7@localhost")["destination"] == "charlie@localhost"
    assert not resolve("ticket77@localhost")["exists"]
    assert resolve("abcabc@localhost")["rule"]["id"] == oldest["id"]
    assert not resolve("sales-new@remote.test")["exists"]
    for pattern in ("[sales]*", "sales\\*", "sales*@remote.test", "bad..prefix", "", "x" * 65):
        bad(s, op="forwarding_create", pattern=pattern, destination="bob@localhost")
    assert bad(s, op="forwarding_create", pattern="outside*", destination="bob@remote.test")["code"] == "nonlocal_destination"
    assert bad(s, op="forwarding_create", pattern="missing*", destination="absent@localhost")["code"] == "unknown_destination"
    assert len(rpc("forwarding_list", limit=2, offset=1)["rules"]) == 2
    s.stop("storage")
    s.start("storage")
    assert resolve("sales-new@localhost")["rule"]["id"] == specific["id"]
    print("PASS forwarding persistence, normalization, bounded globs, specificity and exact mailbox precedence", flush=True)

    # Several original addresses resolving to one mailbox consume one queue slot.
    with smtplib.SMTP("127.0.0.1", s.ports["smtp"], timeout=10) as client:
        client.ehlo()
        assert client.mail("alice@localhost")[0] == 250
        assert client.rcpt("unknown@localhost")[0] == 550
        assert client.rcpt("sales-new@remote.test")[0] == 550
        assert client.sendmail("alice@localhost", ["sales-one@localhost", "sales-two@localhost", "charlie@localhost"], message("dedupe")) == {}
    queued = jobs(s)
    assert len(queued) == 1 and queued[0]["recipient"] in {"sales-one@localhost", "sales-two@localhost", "charlie@localhost"}

    # Pin the accepted route even if rules change between RCPT, DATA and restart.
    with smtplib.SMTP("127.0.0.1", s.ports["smtp"], timeout=10) as client:
        client.ehlo()
        assert client.mail("alice@localhost")[0] == 250
        assert client.rcpt("sales-change@localhost")[0] == 250
        assert rpc("forwarding_delete", id=specific["id"])["deleted"]
        replacement = rule("sales-*", "bob@localhost")
        assert client.data(message("pinned during DATA"))[0] == 250
    pinned = next(item for item in jobs(s) if item["recipient"] == "sales-change@localhost")
    assert rpc("resolve_recipient", recipient=pinned["recipient"], queue_id=pinned["id"])["destination"] == "charlie@localhost"
    s.stop("storage")
    s.start("storage")
    assert rpc("resolve_recipient", recipient=pinned["recipient"], queue_id=pinned["id"])["destination"] == "charlie@localhost"
    s.start("delivery")
    s.wait_mail("charlie@localhost", 2)
    wait_until(lambda: not jobs(s))
    assert not rpc("list", username="bob@localhost")["messages"]
    assert not rpc("list", username="sales-change@localhost")["messages"]
    s.stop("delivery")
    print("PASS SMTP unknown 550, relay rejection, canonical deduplication and durable accepted routing", flush=True)

    # Legacy queue jobs from one submission also dedupe at delivery. Their
    # original addresses and distinct per-job tombstones remain durable.
    legacy = rpc("enqueue", sender="alice@localhost", recipients=["sales-legacy1@localhost", "sales-legacy2@localhost"], raw=message("legacy aliases"))
    legacy_jobs = jobs(s)
    assert len(legacy_jobs) == 2 and all(item["submission_id"] == legacy["id"] for item in legacy_jobs)
    s.start("delivery")
    bob = s.wait_mail("bob@localhost", 1)
    wait_until(lambda: not jobs(s))
    s.stop("delivery")
    assert rpc("delete", username="bob@localhost", ids=[bob["messages"][0]["id"]], permanent=True)["ok"]
    for job in legacy_jobs:
        reply = rpc("deliver", username="bob@localhost", raw=message("legacy aliases"), delivery_id=job["id"], submission_id=legacy["id"])
        assert reply["ok"] and reply["duplicate"]
    assert not rpc("list", username="bob@localhost")["messages"]
    assert rpc("deliver", username="bob@localhost", raw=message("legacy aliases"), delivery_id="late-duplicate", submission_id=legacy["id"])["duplicate"]
    assert not rpc("list", username="bob@localhost")["messages"]
    print("PASS legacy submission deduplication, crash replay and deleted-message tombstones", flush=True)

    # A deleted destination cannot fall through to a broader rule or be
    # rerouted by an administrator while a durable retry is waiting.
    doomed = rule("missing-*", "gone@localhost")
    rule("missing*", "bob@localhost")
    accepted = resolve("missing-one@localhost")
    assert rpc("enqueue", sender="alice@localhost", recipients=["missing-one@localhost"], recipient_routes={"missing-one@localhost": accepted}, raw=message("missing destination"))["ok"]
    s.stop("auth")
    with contextlib.closing(sqlite3.connect(s.directory / "data" / "auth.sqlite3")) as database:
        database.execute("DELETE FROM users WHERE username='gone@localhost'")
        database.commit()
    s.start("auth")
    assert not resolve("missing-one@localhost")["exists"]
    with smtplib.SMTP("127.0.0.1", s.ports["smtp"], timeout=10) as client:
        client.ehlo()
        assert client.mail("alice@localhost")[0] == 250
        assert client.rcpt("missing-two@localhost")[0] == 550
    s.start("delivery")
    wait_until(lambda: jobs(s) and jobs(s)[0]["attempts"] >= 1)
    s.stop("delivery")
    pending = jobs(s)[0]
    assert rpc("forwarding_delete", id=doomed["id"])["deleted"]
    rule("missing-*", "bob@localhost")
    assert resolve("missing-one@localhost")["destination"] == "bob@localhost"
    assert not rpc("resolve_recipient", recipient=pending["recipient"], queue_id=pending["id"])["exists"]
    assert s.rpc("auth", op="create", username="gone@localhost", password=PASSWORD)["ok"]
    s.start("delivery")
    s.wait_mail("gone@localhost", 1)
    wait_until(lambda: not jobs(s))
    s.stop("delivery")
    assert not rpc("list", username="bob@localhost")["messages"]
    print("PASS missing destination rejection, pinned retry and restoration without rerouting", flush=True)

    # Sent receipts key the original submission independently of later rules.
    route = resolve("sales-idempotent@localhost")
    fields = dict(sender="alice@localhost", sent_username="alice@localhost", submission_id="forwarding-idempotent", recipients=["sales-idempotent@localhost"], recipient_routes={"sales-idempotent@localhost": route}, raw=message("sent receipt"))
    first = rpc("enqueue", **fields)
    assert first["ok"]
    assert rpc("forwarding_delete", id=replacement["id"])["deleted"]
    rule("sales-*", "charlie@localhost")
    second = rpc("enqueue", **fields)
    assert second["duplicate"] and second["sent_id"] == first["sent_id"] and len(jobs(s)) == 1
    assert len(rpc("list", username="alice@localhost", folder="Sent")["messages"]) == 1
    bad(s, op="enqueue", sender="alice@localhost", recipients=["sales-other@localhost"], recipient_routes={"sales-idempotent@localhost": route}, raw=message("bad route"))
    assert rpc("queue_finish", id=jobs(s)[0]["id"])["ok"]
    print("PASS forwarding Sent idempotency and route-map validation", flush=True)

    # Verification source selection is account-scoped, recent, bounded and
    # binary safe; retrieving candidates must not mark messages as seen.
    current = int(time.time())
    binary = b"From: sender@remote.test\r\nSubject: code\r\n\r\nYour code 123456 \xff\r\n"
    candidate = rpc("append", username="bob@localhost", folder="INBOX", raw=binary, internal_date=current)["id"]
    excluded = set()
    for folder in ("Sent", "Drafts", "Trash", "Junk", "Archive"):
        excluded.add(rpc("append", username="bob@localhost", folder=folder, raw=message(folder))["id"])
    for date in (current - 901, current + 120):
        excluded.add(rpc("append", username="bob@localhost", raw=message("out of window"), internal_date=date)["id"])
    excluded.add(rpc("append", username="bob@localhost", raw=message("draft flag"), draft=True)["id"])
    large1 = rpc("append", username="bob@localhost", raw=b"Subject: large1\r\n\r\n" + b"x" * 40000)["id"]
    large2 = rpc("append", username="bob@localhost", raw=b"Subject: large2\r\n\r\n" + b"x" * 40000)["id"]
    candidates = rpc("verification_candidates", username="bob@localhost", max_age_seconds=900, limit=30)["messages"]
    assert candidates[0]["id"] == large2
    assert sum(len(item["raw"]) for item in candidates) <= s.config["max_message_bytes"]
    assert any(item["id"] == candidate and item["raw"] == binary for item in candidates)
    assert all(item["id"] not in excluded and item["id"] != large1 for item in candidates)
    assert len(rpc("verification_candidates", username="bob@localhost", limit=1)["messages"]) == 1
    assert not rpc("verification_candidates", username="nobody@localhost")["messages"]
    assert not rpc("get", username="bob@localhost", id=candidate)["seen"]
    for value in (0, 51, True, "30"):
        bad(s, op="verification_candidates", username="bob@localhost", limit=value)
    print("PASS bounded recent INBOX candidates, folder/draft isolation and binary source without seen mutation", flush=True)


def run_http(s):
    for name in ("auth", "storage", "filter", "web", "admin"):
        s.start(name)
    alice, bob = "alice@localhost", "bob@localhost"
    for user in (alice, bob):
        assert s.rpc("auth", op="create", username=user, password=PASSWORD, admin=user == alice)["ok"]

    def login(service, username):
        status, headers, result = s.http(service, "POST", "/api/login", dict(username=username, password=PASSWORD))
        assert status == 200, (status, result)
        return {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": result["csrf"]}

    browser = login("admin", alice)
    mailbox = login("web", alice)
    route = "/api/admin/forwarding"

    def key(name, permissions):
        status, _, result = s.http("admin", "POST", "/api/admin/api-keys",
                                  dict(name=name, permissions=permissions), browser)
        assert status == 201 and result["ok"], (status, result)
        return {"Authorization": "Bearer " + result["key"]}

    read = key("Forwarding read", ["forwarding:read"])
    write = key("Forwarding write", ["forwarding:write"])
    unrelated = key("Unrelated permission", ["users:read"])
    payload = dict(pattern="HTTP-**@LOCALHOST", destination=bob)
    assert s.http("admin", "GET", route)[0] == 401
    assert s.http("web", "GET", route, headers=mailbox)[0] == 404
    assert s.http("admin", "GET", route, headers=read)[0] == 200
    assert s.http("admin", "GET", route, headers=write)[0] == 403
    for method, path, body in (("GET", route, None), ("POST", route, payload), ("DELETE", route + "/1", None)):
        assert s.http("admin", method, path, body, unrelated)[0] == 403
    assert s.http("admin", "POST", route, payload, read)[0] == 403
    assert s.http("admin", "POST", route, payload, {"Cookie": browser["Cookie"]})[0] == 403
    status, _, created = s.http("admin", "POST", route, payload, write)
    assert status == 201 and created["ok"] and created["rule"]["pattern"] == "http-*", (status, created)
    rule_id = created["rule"]["id"]
    assert s.http("admin", "DELETE", route + f"/{rule_id}", headers=read)[0] == 403
    status, _, listed = s.http("admin", "GET", route, headers=read)
    assert status == 200 and listed["rules"] == [created["rule"]], (status, listed)
    for destination, code in (("absent@localhost", "unknown_destination"), ("outside@remote.test", "nonlocal_destination")):
        status, _, failed = s.http("admin", "POST", route, dict(pattern="invalid-*", destination=destination), write)
        assert status == 400 and failed["code"] == code, (status, failed)
    for suffix in ("", "0", "-1", "abc", "1x", "9223372036854775808"):
        status, _, failed = s.http("admin", "DELETE", route + "/" + suffix, headers=write)
        assert status == 400 and not failed["ok"], (suffix, status, failed)
    print("PASS admin forwarding REST read/write scopes, denied access, destination validation and bad IDs", flush=True)

    recipients = ["http-first@localhost", "http-second@localhost", bob]
    status, _, sent = s.http("web", "POST", "/api/send",
                           dict(to=recipients, subject="HTTP forwarding", text="One canonical delivery"), mailbox)
    assert status == 202 and sent["ok"], (status, sent)
    queued = s.rpc("storage", op="queue_list", limit=100)["jobs"]
    assert len(queued) == 1 and queued[0]["recipient"] in recipients, queued
    sent_box = s.rpc("storage", op="list", username=alice, folder="Sent")["messages"]
    assert len(sent_box) == 1, sent_box
    original = s.rpc("storage", op="get", username=alice, id=sent_box[0]["id"])["raw"]
    headers = BytesParser().parsebytes(original)
    assert [address for _, address in getaddresses(headers.get_all("To", []))] == recipients
    assert queued[0]["raw"] == original
    s.start("delivery")
    inbox = s.wait_mail(bob, 1)["messages"]
    wait_until(lambda: not jobs(s))
    assert len(inbox) == 1 and s.rpc("storage", op="get", username=bob, id=inbox[0]["id"])["raw"] == original
    for alias in recipients[:2]:
        assert not s.rpc("storage", op="list", username=alias)["messages"]
    assert len(s.rpc("storage", op="list", username=alice, folder="Sent")["messages"]) == 1
    status, _, deleted = s.http("admin", "DELETE", route + f"/{rule_id}", headers=write)
    assert status == 200 and deleted["deleted"], (status, deleted)
    assert s.http("admin", "GET", route, headers=read)[2]["rules"] == []
    print("PASS Webmail alias/canonical deduplication, one Inbox delivery and original recipients retained in Sent", flush=True)



def run_domain_change(s):
    for service in ("auth", "storage", "filter", "transfer"): s.start(service)
    target="domain-owner@localhost"
    assert s.rpc("auth",op="create",username=target,password=PASSWORD)["ok"]
    assert s.rpc("storage",op="forwarding_create",pattern="domain-*",destination=target)["ok"]
    recipient="domain-alias@localhost"
    route=s.rpc("storage",op="resolve_recipient",recipient=recipient)
    assert s.rpc("storage",op="enqueue",sender="outside@remote.test",recipients=[recipient],raw=message("domain change"),recipient_routes={recipient:route})["ok"]
    assert s.rpc("storage",op="queue_list")["jobs"][0]["local_route"]
    for service in ("storage", "transfer", "auth"): s.stop(service)
    s.config.update(domain="other.test",outbound_mode="disabled");s.save()
    for service in ("auth", "storage", "transfer", "delivery"): s.start(service)
    wait_until(lambda: jobs(s) and jobs(s)[0]["attempts"]>=1)
    pending=jobs(s)[0]
    assert pending["state"]=="pending" and "configured local domain" in pending["error"],pending
    assert not s.rpc("storage",op="resolve_recipient",recipient=recipient,queue_id=pending["id"])["exists"]
    for service in ("delivery", "storage", "transfer", "auth"):s.stop(service)
    s.config["domain"]="localhost";s.save()
    with sqlite3.connect(s.directory/"data/storage.sqlite3") as db:
        db.execute("UPDATE queue SET next_attempt=0")
    for service in ("auth", "storage", "transfer", "delivery"):s.start(service)
    s.wait_mail(target,1);wait_until(lambda:not jobs(s))
    print("PASS pinned local queue stays pending across domain edits without external transfer, then delivers after restoration",flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build" / "test-runs" / ("forwarding-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory.resolve())
    try:
        run(suite)
        suite.close()
        http_directory = directory / "http"
        http_directory.mkdir()
        suite = Suite(args.bin_dir.resolve(), http_directory.resolve())
        run_http(suite)
        suite.close()
        changed_directory=directory/"domain-change";changed_directory.mkdir()
        suite=Suite(args.bin_dir.resolve(),changed_directory.resolve())
        run_domain_change(suite)
        print("All wildcard forwarding integration tests passed", flush=True)
    except BaseException:
        print(f"Logs: {directory}", flush=True)
        raise
    finally:
        suite.close()


if __name__ == "__main__":
    main()
