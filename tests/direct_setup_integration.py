#!/usr/bin/env python3
"""Private DKIM lifecycle, direct submission gates and durable failure handling.

All SMTP recipients are fixtures. The transport service is replaced by a
loopback fixture for queue tests; no Internet messages or DNS queries occur.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import smtplib
import sqlite3
import threading
import time
from pathlib import Path

from integration import PASSWORD, ROOT, Suite, decode_wire
from setup_integration import NativeServer, assert_private, http, reserve_ports


def prepare(binaries, directory):
    ports = reserve_ports()
    path = directory / "config" / "postplus.json"
    server = NativeServer(binaries, path, ports["admin"], directory, "direct-setup")
    try:
        server.wait(server.setup_ready)
        headers = {"X-Setup-Token": server.token}
        deadline = time.monotonic() + 10
        while True:
            try:
                status, _, defaults = http(ports["admin"], "GET", "/api/setup", headers=headers)
                break
            except OSError:
                assert time.monotonic() < deadline
                time.sleep(0.05)
        assert status == 200
        route = "/api/setup/dkim"
        request = {"domain": "EXAMPLE.COM", "selector": "PoStPlUs"}
        for bad in ({}, {"X-Setup-Token": "wrong"}, {**headers, "Host": "evil.example"},
                    {**headers, "Origin": "https://evil.example"}):
            assert http(ports["admin"], "POST", route, request, bad)[0] == 403
        assert http(ports["admin"], "GET", route, headers=headers)[0] == 405
        for invalid in ({**request, "domain": "localhost"}, {**request, "domain": "192.0.2.1"},
                        {**request, "selector": "../key"}, {**request, "private_key": "no"}):
            assert http(ports["admin"], "POST", route, invalid, headers)[0] == 400
        status, _, record = http(ports["admin"], "POST", route, request, headers)
        assert status == 200 and record["name"] == "postplus._domainkey.example.com", record
        assert record["domain"] == "example.com" and record["selector"] == "postplus"
        assert record["type"] == "TXT" and "p=" in record["value"]
        assert "PRIVATE KEY" not in json.dumps(record) and "private_pem" not in record
        assert len(record["fingerprint"]) == 64
        assert http(ports["admin"], "POST", route, request, headers)[2] == record
        keys = list(path.parent.glob("postplus.dkim-*.pem"))
        assert len(keys) == 1
        key = keys[0]
        original = key.read_bytes()
        assert_private(key)
        payload = {**defaults["defaults"], "domain": "example.com", "mail_hostname": "mail.example.com",
                   "admin_username": "admin@example.com", "admin_password": PASSWORD,
                   "outbound_mode": "direct", "dkim_selector": "PoStPlUs", "ports": ports,
                   "dkim_fingerprint": "stale", "allow_insecure_auth": True}
        status, _, error = http(ports["admin"], "POST", "/api/setup", payload, headers)
        assert status == 400 and error["code"] == "dkim_not_prepared", error
        assert not path.exists() and key.read_bytes() == original
        server.close()
        server = NativeServer(binaries, path, ports["admin"], directory, "direct-setup-retry")
        server.wait(server.setup_ready)
        headers = {"X-Setup-Token": server.token}
        deadline = time.monotonic() + 10
        while True:
            try:
                status, _, repeated = http(ports["admin"], "POST", route, request, headers)
                break
            except OSError:
                assert time.monotonic() < deadline
                time.sleep(0.05)
        assert status == 200 and repeated == record and key.read_bytes() == original
        payload["dkim_fingerprint"] = record["fingerprint"]
        status, _, saved = http(ports["admin"], "POST", "/api/setup", payload, headers)
        assert status == 200 and saved["ok"], saved
        server.wait(server.services_ready)
        config = json.loads(path.read_text())
        assert config["outbound_mode"] == "direct" and config["mail_hostname"] == "mail.example.com"
        assert config["dkim_selector"] == "postplus"
        assert Path(config["dkim_private_key"]) == key and key.read_bytes() == original
        assert "PRIVATE KEY" not in path.read_text()
        assert_private(path)
        print("PASS token-protected public DKIM record, private durable key, retry/restart reuse and direct setup", flush=True)
        return key
    finally:
        server.close()


def gates_and_queue(binaries, directory, key):
    directory.mkdir()
    suite = Suite(binaries, directory)
    suite.config.update(domain="example.com", mail_hostname="mail.example.com", outbound_mode="direct",
                        dkim_private_key=str(key), dkim_selector="postplus")
    suite.save()
    requests = []

    class Transfer(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            assert self.headers["Authorization"] == "Bearer " + suite.token
            body = decode_wire(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            recipient = body["recipient"]
            requests.append(recipient)
            if recipient.startswith("permanent@"):
                reply = {"ok": False, "permanent": True, "error": "Destination SMTP status 550 during RCPT TO."}
            elif recipient.startswith("temporary@"):
                reply = {"ok": False, "permanent": False, "error": "Destination SMTP status 451 during RCPT TO."}
            else:
                reply = {"ok": True}
            content = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, *args):
            pass

    fixture = ThreadingHTTPServer(("127.0.0.1", suite.ports["transfer"]), Transfer)
    thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    thread.start()
    try:
        for service in ("auth", "storage", "filter", "smtp", "web", "admin"):
            suite.start(service)
        user = "sender@example.com"
        assert suite.rpc("auth", op="create", username=user, password=PASSWORD, admin=True)["ok"]
        # Avoid ambient hostname DNS lookups after connecting: a slow runner
        # resolver can consume the server's idle timeout before the first EHLO.
        with smtplib.SMTP("127.0.0.1", suite.ports["smtp"], local_hostname="localhost", timeout=5) as client:
            client.ehlo()
            assert client.mail(user)[0] == 250
            assert client.rcpt("external@destination.example")[0] == 550
            client.rset()
            client.login(user, PASSWORD)
            assert client.mail(user)[0] == 250
            assert client.rcpt("external@destination.example")[0] == 250
            client.rset()
            assert client.mail("foreign@other.example")[0] == 250
            assert client.rcpt("external@destination.example")[0] == 550
            client.rset()
        assert suite.http("web", "POST", "/api/send", {"to": ["nobody@destination.example"], "subject": "x", "text": "x"})[0] == 401
        status, headers, session = suite.http("web", "POST", "/api/login", {"username": user, "password": PASSWORD})
        assert status == 200
        auth = {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": session["csrf"]}
        assert suite.http("web", "POST", "/api/admin/dkim", {}, auth)[0] == 404
        for kind in ("permanent", "temporary", "accepted", "expired"):
            status, _, result = suite.http("web", "POST", "/api/send", {
                "to": [kind + "@destination.example"], "subject": "Delivery fixture", "text": "Queue fixture"}, auth)
            assert status == 202 and result["ok"], result
        with sqlite3.connect(directory / "data/storage.sqlite3") as database:
            database.execute("UPDATE queue SET created_at=? WHERE recipient=?", (int(time.time()) - 864000, "expired@destination.example"))
        status, headers, session = suite.http("admin", "POST", "/api/login", {"username": user, "password": PASSWORD})
        assert status == 200
        cookie = {"Cookie": headers["Set-Cookie"].split(";", 1)[0]}
        assert suite.http("admin", "POST", "/api/admin/dkim", {}, cookie)[0] == 403
        status, _, record = suite.http("admin", "POST", "/api/admin/dkim", {}, {**cookie, "X-CSRF-Token": session["csrf"]})
        assert status == 200 and record["name"] == "postplus._domainkey.example.com"
        suite.start("delivery")
        deadline = time.monotonic() + 15
        while True:
            jobs = suite.rpc("storage", op="queue_inspect")["jobs"]
            permanent = next((job for job in jobs if job["recipient"].startswith("permanent@")), {})
            temporary = next((job for job in jobs if job["recipient"].startswith("temporary@")), {})
            if len(jobs) == 3 and permanent.get("state") == "quarantined" and temporary.get("attempts", 0) >= 1:
                break
            assert time.monotonic() < deadline, jobs
            time.sleep(0.1)
        assert "550" in permanent["error"] and "451" in temporary["error"]
        assert temporary["state"] == "pending" and temporary["next_attempt"] > time.time() - 1
        assert requests.count("permanent@destination.example") == 1 and requests.count("accepted@destination.example") == 1
        expired = next(job for job in jobs if job["recipient"].startswith("expired@"))
        assert expired["state"] == "quarantined" and "age exceeded" in expired["error"]
        assert "expired@destination.example" not in requests
        suite.stop("delivery")
        assert suite.rpc("storage", op="queue_inspect")["jobs"] == jobs
        print("PASS authenticated direct submission, no open relay, DKIM admin CSRF and durable temporary/permanent queue states", flush=True)
    finally:
        suite.close()
        fixture.shutdown()
        fixture.server_close()
        thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = (ROOT / "build/test-runs" / ("direct-" + secrets.token_hex(6))).resolve()
    directory.mkdir(parents=True)
    key = prepare(args.bin_dir.resolve(), directory)
    gates_and_queue(args.bin_dir.resolve(), directory / "queue", key)
    print("All direct setup integration tests passed", flush=True)


if __name__ == "__main__":
    main()
