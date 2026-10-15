"""Decoded mailbox search, owner isolation and durable recipient delivery history."""
import argparse
import base64
from email.header import Header
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sqlite3
import threading
import time
from urllib.parse import urlencode

from integration import Suite, ROOT, PASSWORD


def login(s, service, username):
    status, headers, body = s.http(service, "POST", "/api/login", {"username": username, "password": PASSWORD})
    assert status == 200, body
    return {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": body["csrf"]}


def run(s):
    for name in ("auth", "storage", "filter", "web", "admin"):
        s.start(name)
    alice, bob, admin = "alice@localhost", "bob@localhost", "admin@localhost"
    for user in (alice, bob, admin):
        assert s.rpc("auth", op="create", username=user, password=PASSWORD, admin=user == admin)["ok"]
    a, b, adm = login(s, "web", alice), login(s, "web", bob), login(s, "admin", admin)
    encoded = Header("客户项目 Café", "utf-8").encode()
    raw = (f"From: Alice <alice@localhost>\r\nTo: bob@localhost\r\nSubject: {encoded}\r\n"
           "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=search-test\r\n\r\n"
           "--search-test\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
           base64.b64encode("<p>世界报告 &amp; 100% literal_under_score</p>".encode()).decode() + "\r\n"
           "--search-test\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*=UTF-8''%E6%8A%A5%E5%91%8A-report.pdf\r\n"
           "Content-Transfer-Encoding: base64\r\n\r\nAAEC\r\n--search-test--\r\n")
    result = s.rpc("storage", op="append", username=alice, folder="INBOX", raw=raw, internal_date=1767225600)
    message = result["id"]
    for who, body in ((bob, "Only Bob private marker"), (alice, "Second 世界报告"), (alice, "Third 世界报告")):
        s.rpc("storage", op="append", username=who, folder="INBOX", raw="Subject: Separate\r\n\r\n" + body, internal_date=1767312000)

    def search(**filters):
        response = s.http("web", "GET", "/api/messages/search?" + urlencode(filters), headers=a)
        assert response[0] == 200, response
        return response[2]

    for term in ("客户项目", "世界报告", "Café", "100%", "literal_under_score", "报告-report.pdf"):
        found = search(q=term)
        assert message in [item["id"] for item in found["messages"]], (term, found)
    assert search(q="100_")["total"] == 0, "SQL wildcards must be literal"
    assert search(q="Only Bob")["total"] == 0
    assert search(**{"from": "ALICE", "to": "bob@", "subject": "客户", "has_attachment": "true"})["total"] == 1
    assert search(q="世界报告", seen="false")["total"] == 3
    assert search(q="世界报告", seen="true")["total"] == 0
    assert search(after="2026-01-01", before="2026-01-02")["total"] == 1
    assert search(after="2026-01-02", before="2026-01-03")["total"] == 2
    pages = [search(q="世界报告", limit=1, offset=n) for n in range(3)]
    assert len({p["messages"][0]["id"] for p in pages}) == 3 and pages[0]["has_more"] and not pages[2]["has_more"]
    assert s.rpc("storage", op="get", username=alice, id=message)["raw"] == raw.encode()
    assert not s.rpc("storage", op="get", username=alice, id=message)["seen"]
    for query in ("username=bob%40localhost", "limit=0", "offset=-1", "seen=maybe", "before=2026-02-30", "after=2026-02-01&before=2026-01-01"):
        assert s.http("web", "GET", "/api/messages/search?" + query, headers=a)[0] == 400, query
    assert s.http("web", "GET", "/api/messages/search?q=x")[0] == 401
    # Cc-only composition and private Bcc draft recipients are searchable, while
    # the result's display To stays the actual MIME To header.
    status, _, draft = s.http("web", "POST", "/api/drafts", {"to": [], "cc": [bob], "bcc": ["hidden@example.test"], "subject": "Private recipients", "text": "Cc-only draft"}, a)
    assert status == 200, draft
    cc_search = search(to=bob, folder="Drafts")
    assert [item["id"] for item in cc_search["messages"]] == [draft["id"]] and not cc_search["messages"][0]["to"], cc_search
    assert search(to="hidden@example.test", folder="Drafts")["total"] == 1
    assert search(q="hidden@example.test")["total"] == 1
    admin_search = s.http("admin", "GET", "/api/admin/messages/search?" + urlencode({"username": alice, "q": "世界报告"}), headers=adm)
    assert admin_search[0] == 200 and admin_search[2]["total"] == 3, admin_search
    for audience, permission, expected in (("mailbox", "mailbox:read", 200), ("mailbox", "mailbox:send", 403)):
        key = s.rpc("auth", op="api_key_create", username=alice, name="Search scope", audience=audience, permissions=[permission])["key"]
        assert s.http("web", "GET", "/api/messages/search?" + urlencode({"q": "世界报告"}), headers={"Authorization": "Bearer " + key})[0] == expected

    # Real queue worker with a deterministic transfer peer: no Internet or mail
    # is sent, while transient/permanent/accepted remote outcomes are exercised.
    calls = {}
    class Transfer(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_POST(self):
            assert self.headers.get("Authorization") == "Bearer " + s.token
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            recipient = payload["recipient"]
            calls[recipient] = calls.get(recipient, 0) + 1
            if recipient.startswith("reject"):
                answer = {"ok": False, "permanent": True, "error": "550 mailbox unavailable"}
            elif recipient.startswith("retry") and calls[recipient] == 1:
                answer = {"ok": False, "error": "451 retry later"}
            else:
                answer = {"ok": True}
            body = json.dumps(answer).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", s.ports["transfer"]), Transfer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        submission = s.rpc("storage", op="enqueue", sender=alice, sent_username=alice,
            recipients=[bob, "accept@example.test", "reject@example.test", "retry@example.test"], raw="Subject: Delivery state\r\n\r\nDelivery test\r\n")
        sent = submission["sent_id"]
        path = "/api/messages/" + sent + "/delivery-status"
        status = s.http("web", "GET", path, headers=a)
        assert status[0] == 200 and {item["state"] for item in status[2]["recipients"]} == {"queued"}, status
        assert s.http("web", "GET", path, headers=b)[0] == 404
        s.start("delivery")
        deadline = time.monotonic() + 20
        saw_retry = False
        while time.monotonic() < deadline:
            status = s.http("web", "GET", path, headers=a)[2]
            states = {item["recipient"]: item for item in status["recipients"]}
            saw_retry |= states["retry@example.test"]["state"] == "retrying"
            if states["retry@example.test"]["state"] == "delivered" and states["reject@example.test"]["state"] == "rejected" and states[bob]["state"] == "delivered":
                break
            time.sleep(0.1)
        else:
            raise AssertionError(status)
        assert saw_retry
        assert states[bob]["delivery_scope"] == "local_mailbox"
        assert states["accept@example.test"]["delivery_scope"] == "remote_mta"
        assert states["retry@example.test"]["attempts"] == 2
        assert [item["state"] for item in states["retry@example.test"]["history"]] == ["queued", "retrying", "delivered"]
        assert states["reject@example.test"]["attempts"] == 1 and "550" in states["reject@example.test"]["error"]
        assert "does not confirm Inbox" in status["notice"]
        s.stop("delivery")
        assert len(s.rpc("storage", op="queue_inspect")["jobs"]) == 1, "Only quarantined rejection remains queued"
        s.stop("storage")
        s.start("storage")
        assert s.http("web", "GET", path, headers=a)[2] == status, "History must survive queue removal and restart"
        assert s.http("admin", "GET", "/api/admin/messages/" + sent + "/delivery-status?" + urlencode({"username": alice}), headers=adm)[0] == 200
        assert s.http("web", "GET", "/api/messages/" + message + "/delivery-status", headers=a)[0] == 404
    finally:
        s.stop("delivery")
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    # The compatible extension can rebuild legacy projections in bounded batches.
    for index in range(103):
        s.rpc("storage", op="append", username=alice, folder="Archive", raw=f"Subject: Legacy {index}\r\n\r\nlegacy-search-{index}")
    s.stop("storage")
    with sqlite3.connect(s.directory / "data/storage.sqlite3") as db:
        db.execute("DELETE FROM message_search")
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2
    s.start("storage")
    first = search(q="legacy-search-0", folder="all")
    assert first["indexing"] and first["indexing_remaining"] > 0
    second = search(q="legacy-search-0", folder="all")
    assert not second["indexing"] and second["total"] == 1, second

    # Simulate rollback to the old queue-only binary, then upgrading again.
    legacy = s.rpc("storage", op="enqueue", sender=alice, sent_username=alice,
        recipients=["legacy-finished@example.test", "legacy-quarantine@example.test"], raw="Subject: Rollback outcome\r\n\r\nLegacy worker\r\n")
    legacy_path = "/api/messages/" + legacy["sent_id"] + "/delivery-status"
    s.stop("storage")
    with sqlite3.connect(s.directory / "data/storage.sqlite3") as db:
        db.execute("DELETE FROM queue WHERE submission_id=? AND recipient=?", (legacy["id"], "legacy-finished@example.test"))
        db.execute("UPDATE queue SET state='quarantined',attempts=1,last_error='old scanner rejected' WHERE submission_id=?", (legacy["id"],))
    s.start("storage")
    reconciled = s.http("web", "GET", legacy_path, headers=a)[2]
    states = {item["recipient"]: item for item in reconciled["recipients"]}
    assert states["legacy-finished@example.test"]["state"] == "failed" and "outcome unavailable" in states["legacy-finished@example.test"]["error"], reconciled
    assert not states["legacy-finished@example.test"]["delivery_scope"]
    assert states["legacy-quarantine@example.test"]["state"] == "rejected" and states["legacy-quarantine@example.test"]["attempts"] == 1
    s.stop("storage")
    s.start("storage")
    assert s.http("web", "GET", legacy_path, headers=a)[2] == reconciled, "Reconciliation is idempotent and never resends finished legacy jobs"
    print("PASS decoded Unicode mailbox search, filters/paging/permissions, bounded legacy index, durable per-recipient retry/reject/delivery history", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("search-delivery-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    finally:
        suite.close()
