#!/usr/bin/env python3
"""Real-process integration tests; Python standard library only."""
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
import subprocess
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "Integration-passphrase-2026!"


def encode_wire(value):
    if isinstance(value, dict):
        return {("raw_base64" if k == "raw" else k):
                (base64.b64encode(v if isinstance(v, bytes) else v.encode()).decode() if k == "raw" else encode_wire(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [encode_wire(item) for item in value]
    return value


def decode_wire(value):
    if isinstance(value, dict):
        return {("raw" if k == "raw_base64" else k):
                (base64.b64decode(v) if k == "raw_base64" else decode_wire(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [decode_wire(item) for item in value]
    return value


class Suite:
    def __init__(self, binaries, directory):
        self.binaries = binaries
        self.directory = directory
        self.children = {}
        self.files = []
        self.token = secrets.token_hex(32)
        self.env = dict(os.environ, POSTPLUS_SERVICE_TOKEN=self.token)
        names = ["auth", "storage", "filter", "transfer", "smtp", "pop3", "imap", "web", "admin", "delivery"]
        # Reserve all simultaneously so ports are unique within this test instance.
        reservations = [socket.socket() for _ in names]
        for item in reservations:
            item.bind(("127.0.0.1", 0))
        self.ports = {name: item.getsockname()[1] for name, item in zip(names, reservations)}
        for item in reservations:
            item.close()
        self.config = json.loads((ROOT / "config/postplus.example.json").read_text())
        self.config.update(ports={k: v for k, v in self.ports.items() if k != "delivery"},
                           delivery_lock_port=self.ports["delivery"],
                           data_dir=str(directory / "data"), web_root=str(ROOT / "web"),
                           log_dir=str(directory / "data/logs"),
                           max_message_bytes=65536, timeout_seconds=5, max_connections=8,
                           allow_insecure_auth=True)
        self.path = directory / "postplus.json"
        self.save()

    def save(self):
        self.path.write_text(json.dumps(self.config), encoding="utf-8")

    def start(self, service):
        log = (self.directory / f"{service}.log").open("ab")
        self.files.append(log)
        binary = self.binaries / (f"postplus-{service}" + (".exe" if os.name == "nt" else ""))
        child = subprocess.Popen([str(binary), "--config", str(self.path)], env=self.env,
                                 stdout=log, stderr=log,
                                 creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        self.children[service] = child
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError(f"{service} exited: {(self.directory / f'{service}.log').read_text(errors='replace')}")
            try:
                with socket.create_connection(("127.0.0.1", self.ports[service]), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise TimeoutError(f"{service} did not start")

    def stop(self, service):
        child = self.children.pop(service, None)
        if child and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()

    def close(self):
        for name in list(self.children)[::-1]:
            self.stop(name)
        for file in self.files:
            file.close()

    def http(self, service, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.ports[service], timeout=15)
        payload = None if body is None else json.dumps(body).encode()
        try:
            connection.request(method, path, payload, {"Content-Type": "application/json", **(headers or {})})
            reply = connection.getresponse()
            content = reply.read()
            return reply.status, dict(reply.getheaders()), json.loads(content) if "json" in reply.getheader("Content-Type", "") else content
        finally:
            connection.close()

    def rpc(self, service, **payload):
        status, _, result = self.http(service, "POST", "/rpc", encode_wire(payload), {"Authorization": f"Bearer {self.token}"})
        assert status == 200, (service, status, result)
        return decode_wire(result)

    def wait_mail(self, user, count):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            result = self.rpc("storage", op="list", username=user)
            if len(result["messages"]) == count:
                return result
            time.sleep(0.1)
        raise AssertionError(f"expected {count} messages for {user}, got {result}")


def run(s):
    for service in ("auth", "storage", "filter", "transfer", "smtp", "pop3", "imap", "web", "admin"):
        s.start(service)
    alice, bob = "alice@localhost", "bob@localhost"
    for user in (alice, bob):
        assert s.rpc("auth", op="create", username=user, password=PASSWORD, admin=user == alice)["ok"]
    assert not s.rpc("auth", op="create", username=alice, password=PASSWORD)["ok"]
    assert not s.rpc("auth", op="verify", username=bob, password="wrong password")["ok"]
    assert s.http("storage", "POST", "/rpc", {"op": "stats"})[0] == 401
    assert s.http("auth", "POST", "/rpc", {"op": "list"}, {"Authorization": "Bearer wrong"})[0] == 401
    print("PASS auth, duplicate users, RPC authorization", flush=True)

    raw = (b"From: alice@localhost\r\nTo: bob@localhost\r\nSubject: protocol integration\r\n"
           b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\nHello\r\n.dot-prefixed\r\nLatin byte: \xff\r\n")
    with smtplib.SMTP("127.0.0.1", s.ports["smtp"], local_hostname="localhost", timeout=10) as client:
        client.ehlo()
        assert client.mail(alice)[0] == 250
        assert client.rcpt("unknown@localhost")[0] == 550
        assert client.rcpt("remote@example.net")[0] == 550
        client.rset()
        client.login(alice, PASSWORD)
        assert client.sendmail(alice, [bob], raw) == {}
    queued = s.rpc("storage", op="queue_list", limit=1)["jobs"]
    assert len(queued) == 1 and queued[0]["raw"] == raw
    # Restart the owner process before delivery: acceptance must survive a crash/restart.
    s.stop("storage")
    s.start("storage")
    assert s.rpc("storage", op="queue_list", limit=1)["jobs"][0]["raw"] == raw
    s.start("delivery")
    box = s.wait_mail(bob, 1)
    message_id = box["messages"][0]["id"]
    assert s.rpc("storage", op="get", username=bob, id=message_id)["raw"] == raw
    assert not s.rpc("storage", op="get", username=alice, id=message_id)["ok"]
    print("PASS SMTP, relay rejection, binary-safe queue, crash recovery and delivery", flush=True)

    client = poplib.POP3("127.0.0.1", s.ports["pop3"], timeout=10)
    client.user(bob)
    client.pass_(PASSWORD)
    assert client.stat()[0] == 1
    assert b"\r\n".join(client.retr(1)[1]) + b"\r\n" == raw
    client.dele(1)
    client.close()  # no QUIT => rollback deferred deletion
    assert len(s.rpc("storage", op="list", username=bob)["messages"]) == 1
    client = poplib.POP3("127.0.0.1", s.ports["pop3"], timeout=10)
    client.user(bob)
    client.pass_(PASSWORD)
    client.dele(1)
    client.rset()
    assert client.stat()[0] == 1
    client.quit()
    print("PASS POP3 byte preservation, dot unstuffing and deletion rollback", flush=True)

    client = imaplib.IMAP4("127.0.0.1", s.ports["imap"], timeout=10)
    assert client.login(bob, PASSWORD)[0] == "OK"
    assert client.select("INBOX")[1] == [b"1"]
    uid = str(box["messages"][0]["uid"])
    status, result = client.uid("fetch", uid, "(UID RFC822.SIZE BODY.PEEK[])")
    assert status == "OK" and any(isinstance(item, tuple) and item[1] == raw for item in result), result
    assert not s.rpc("storage", op="list", username=bob)["messages"][0]["seen"]
    assert client.uid("store", uid, "+FLAGS", "(\\Seen)")[0] == "OK"
    assert s.rpc("storage", op="list", username=bob)["messages"][0]["seen"]
    assert client.uid("search", None, "ALL")[1] == [uid.encode()]
    assert client.uid("store", uid, "+FLAGS", "(\\Deleted)")[0] == "OK"
    assert client.expunge()[0] == "OK"
    client.logout()
    assert s.wait_mail(bob, 0)
    # Redelivery of the same durable job must not resurrect an explicitly deleted mail.
    assert s.rpc("storage", op="deliver", username=bob, raw=raw, delivery_id=queued[0]["id"])["ok"]
    assert len(s.rpc("storage", op="list", username=bob)["messages"]) == 0
    print("PASS IMAP UID/literal/flags/EXPUNGE and delivery idempotency", flush=True)

    assert s.http("web", "GET", "/")[0] == 200
    assert s.http("web", "GET", "/api/messages")[0] == 401
    status, headers, login = s.http("web", "POST", "/api/login", {"username": bob, "password": PASSWORD})
    assert status == 200, login
    cookies = {"Cookie": headers["Set-Cookie"].split(";", 1)[0]}
    csrf = {**cookies, "X-CSRF-Token": login["csrf"]}
    assert s.http("web", "GET", "/api/admin/users", headers=cookies)[0] == 404
    assert s.http("web", "GET", "/api/admin/logs", headers=cookies)[0] == 404
    assert s.http("web", "GET", "/api/admin/logs")[0] == 404
    assert s.http("admin", "GET", "/api/admin/logs")[0] == 401
    assert s.http("admin", "GET", "/api/admin/users", headers=cookies)[0] == 401
    assert s.http("admin", "POST", "/api/login", {"username": bob, "password": PASSWORD})[0] == 403
    for service in ("web", "admin"):
        assert s.http(service, "GET", "/favicon.svg")[0] == 200
    assert s.http("admin", "GET", "/")[0] == 200
    assert s.http("admin", "GET", "/api/messages")[0] == 404
    assert s.http("admin", "POST", "/api/send", {})[0] == 404
    assert s.http("web", "GET", "/i18n.js")[0] == 200
    payload = {"to": [alice], "subject": "Webmail test", "text": "Hello from Webmail"}
    assert s.http("web", "POST", "/api/send", payload, cookies)[0] == 403
    assert s.http("web", "POST", "/api/send", payload, csrf)[0] in (200, 202)
    s.wait_mail(alice, 1)
    status, headers, admin = s.http("admin", "POST", "/api/login", {"username": alice, "password": PASSWORD})
    assert status == 200
    admin_headers = {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": admin["csrf"]}
    assert admin_headers["Cookie"].startswith("pp_admin_session=") and cookies["Cookie"].startswith("pp_session=")
    assert s.http("web", "GET", "/api/session", headers=admin_headers)[0] == 401
    # Browsers send both host cookies to both ports. Each service must select
    # its own cookie, regardless of their order, without changing the other login.
    combined = {"Cookie": admin_headers["Cookie"] + "; " + cookies["Cookie"]}
    assert s.http("web", "GET", "/api/session", headers=combined)[2]["username"] == bob
    assert s.http("admin", "GET", "/api/session", headers=combined)[2]["username"] == alice
    assert s.http("admin", "GET", "/api/admin/users", headers=admin_headers)[0] == 200
    assert s.http("admin", "GET", "/api/admin/stats", headers=admin_headers)[0] == 200
    status, _, logs = s.http("admin", "GET", "/api/admin/logs?service=admin&level=info&limit=2", headers=admin_headers)
    assert status == 200 and 0 < len(logs["entries"]) <= 2, logs
    assert all(entry["service"] == "admin" and entry["level"] == "info" for entry in logs["entries"]), logs
    assert PASSWORD not in json.dumps(logs) and s.token not in json.dumps(logs), "secrets in admin logs"
    for query in ("service=../auth", "service=%2e%2e", "level=critical", "limit=0", "limit=501", "limit=-1", "limit=2&limit=3", "path=config"):
        assert s.http("admin", "GET", "/api/admin/logs?" + query, headers=admin_headers)[0] == 400, query
    alice_id = s.rpc("storage", op="list", username=alice)["messages"][0]["id"]
    assert s.http("web", "GET", f"/api/messages/{alice_id}", headers=cookies)[0] in (403, 404)
    assert s.http("web", "POST", "/api/logout", {}, csrf)[0] in (200, 204)
    assert s.http("web", "GET", "/api/messages", headers=cookies)[0] == 401
    assert s.http("admin", "GET", "/api/session", headers=admin_headers)[0] == 200
    status, reset_headers, reset_session = s.http("web", "POST", "/api/login", {"username": alice, "password": PASSWORD})
    assert status == 200
    reset_cookie = {"Cookie": reset_headers["Set-Cookie"].split(";", 1)[0]}
    assert "credential_version" not in reset_session
    assert s.http("admin", "POST", "/api/admin/password", {"username": alice, "password": PASSWORD}, admin_headers)[0] == 200
    assert s.http("web", "GET", "/api/session", headers=reset_cookie)[0] == 401
    assert s.http("admin", "GET", "/api/session", headers=admin_headers)[0] == 401
    print("PASS Webmail/API session, CSRF, account isolation, admin authorization and compose", flush=True)

    # Signature composed at runtime to avoid storing antivirus test signatures as source artifacts.
    signature = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}" + b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    infected = b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(signature) + b"\r\n"
    assert s.rpc("filter", op="scan", raw=infected)["action"] == "reject"
    clean = s.rpc("filter", op="scan", raw=raw)
    assert clean["ok"] and clean["action"] == "accept", clean
    s.stop("filter")
    s.config["clamav_host"] = "127.0.0.1"
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        s.config["clamav_port"] = unused.getsockname()[1]
    s.save()
    s.start("filter")
    unavailable = s.rpc("filter", op="scan", raw=raw)
    assert not unavailable["ok"] or unavailable.get("action") != "accept"
    print("PASS encoded EICAR and ClamAV failure handling", flush=True)

    # Default auth policy blocks plaintext even on loopback.
    s.stop("smtp")
    s.config["allow_insecure_auth"] = False
    s.save()
    s.start("smtp")
    with smtplib.SMTP("127.0.0.1", s.ports["smtp"], local_hostname="localhost", timeout=10) as client:
        client.ehlo()
        assert not client.has_extn("auth")
        assert client.docmd("AUTH", "PLAIN " + base64.b64encode(b"\0" + alice.encode() + b"\0" + PASSWORD.encode()).decode())[0] == 538
    print("PASS default plaintext authentication rejection", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build")
    parser.add_argument("--bin-dir", type=Path)
    parser.add_argument("--mode", default="debug", choices=("debug", "release"))
    args = parser.parse_args()
    if args.bin_dir:
        binaries = args.bin_dir.resolve()
    else:
        filename = "postplus-smtp" + (".exe" if os.name == "nt" else "")
        matches = [p.parent for p in args.build_dir.rglob(filename) if p.parent.name == args.mode]
        if len(matches) != 1:
            parser.error(f"Expected one {args.mode} binary directory, found {matches}; use --bin-dir")
        binaries = matches[0].resolve()
    directory = (args.build_dir / "test-runs" / secrets.token_hex(6)).resolve()
    directory.mkdir(parents=True)
    suite = Suite(binaries, directory)
    try:
        run(suite)
        suite.close()
        subprocess.run([os.sys.executable, str(ROOT / "tests/storage_integration.py"),
                        "--bin-dir", str(binaries)], check=True)
        subprocess.run([os.sys.executable, str(ROOT / "tests/tls_transfer_integration.py"),
                        "--bin-dir", str(binaries)], check=True)
        subprocess.run([os.sys.executable, str(ROOT / "tests/protocol_security.py"),
                        "--bin-dir", str(binaries)], check=True)
        subprocess.run([os.sys.executable, str(ROOT / "tests/http_security.py"),
                        "--bin-dir", str(binaries)], check=True)
        subprocess.run([os.sys.executable, str(ROOT / "tests/setup_integration.py"),
                        "--bin-dir", str(binaries)], check=True)
        print("All integration tests passed", flush=True)
    except BaseException:
        print(f"Logs: {directory}", flush=True)
        traceback.print_exc()
        raise
    finally:
        suite.close()


if __name__ == "__main__":
    main()
