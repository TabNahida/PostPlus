#!/usr/bin/env python3
"""Process-level persistence, authentication, quarantine and scanner checks.

Run: python tests/storage_integration.py --bin-dir build/windows/x64/release
Uses temporary databases and ephemeral loopback ports; no external mail is sent.
"""
import argparse
import base64
import concurrent.futures
import contextlib
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def decode_wire(value):
    if isinstance(value, list):
        return [decode_wire(item) for item in value]
    if isinstance(value, dict):
        result = {key: decode_wire(item) for key, item in value.items() if key != "raw_base64"}
        if "raw_base64" in value:
            result["raw"] = base64.b64decode(value["raw_base64"], validate=True).decode("utf-8")
        return result
    return value


class Services:
    def __init__(self, binary_directory, directory):
        self.binary_directory = binary_directory
        self.directory = directory
        self.token = secrets.token_hex(32)
        self.ports = {name: free_port() for name in ("auth", "storage", "filter")}
        self.config = {
            "domain": "localhost", "data_dir": str(directory / "data"),
            "max_message_bytes": 1024 * 1024, "timeout_seconds": 5,
            "max_connections": 32, "ports": self.ports,
            "service_token_env": "POSTPLUS_TEST_SERVICE_TOKEN",
            "clamav_timeout_seconds": 1,
        }
        self.processes = {}
        self.logs = []

    def start(self, name):
        config_path = self.directory / "postplus.json"
        config_path.write_text(json.dumps(self.config), encoding="utf-8")
        executable = self.binary_directory / ("postplus-" + name + (".exe" if os.name == "nt" else ""))
        output = (self.directory / (name + ".log")).open("ab")
        self.logs.append(output)
        environment = dict(os.environ, POSTPLUS_TEST_SERVICE_TOKEN=self.token)
        process = subprocess.Popen([str(executable), "--config", str(config_path)],
                                   env=environment, stdout=output, stderr=output)
        self.processes[name] = process
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(f"{name} exited: {(self.directory / (name + '.log')).read_text(errors='replace')}")
            try:
                with socket.create_connection(("127.0.0.1", self.ports[name]), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise AssertionError(f"{name} did not start")

    def stop(self, name):
        process = self.processes.pop(name, None)
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def close(self):
        for name in list(self.processes):
            self.stop(name)
        for stream in self.logs:
            stream.close()

    def rpc(self, service, op, *, authorized=True, **fields):
        connection = http.client.HTTPConnection("127.0.0.1", self.ports[service], timeout=15)
        headers = {"Content-Type": "application/json"}
        if authorized:
            headers["Authorization"] = "Bearer " + self.token
        try:
            body = json.dumps(dict(op=op, **fields)) if authorized else ""
            connection.request("POST", "/rpc", body, headers)
            response = connection.getresponse()
            body = decode_wire(json.loads(response.read()))
            if authorized:
                assert response.status in (200, 400, 413), (response.status, body)
                if response.status != 200:
                    assert not body["ok"], body
            else:
                assert response.status in (401, 403), (response.status, body)
            return body
        finally:
            connection.close()


def check_auth(services):
    rpc = lambda op, **fields: services.rpc("auth", op, **fields)
    assert not rpc("list", authorized=False)["ok"]
    password = "local-test-secret-123!"
    assert not rpc("create", username="alice@localhost", password="short").get("ok")
    assert rpc("create", username="Alice@LOCALHOST", password=password, admin=True)["ok"]
    assert not rpc("create", username="alice@localhost", password=password)["ok"]
    assert rpc("create", username="o'hara@localhost", password=password)["ok"]
    assert rpc("exists", username="o'hara@localhost")["exists"]
    assert rpc("verify", username="alice@localhost", password=password)["admin"]
    assert not rpc("verify", username="alice@localhost", password="invalid-password")["ok"]
    assert not rpc("verify", username="absent@localhost", password=password)["ok"]
    assert len(rpc("list")["users"]) == 2
    replacement = "replacement-secret-456!"
    assert rpc("change_password", username="alice@localhost", password=replacement)["ok"]
    assert not rpc("verify", username="alice@localhost", password=password)["ok"]
    services.stop("auth")
    with contextlib.closing(sqlite3.connect(services.directory / "data" / "auth.sqlite3")) as database:
        rows = database.execute("SELECT salt,password_hash,iterations FROM users").fetchall()
        assert all(len(salt) == 16 and len(digest) == 32 and rounds >= 600000 for salt, digest, rounds in rows)
        assert rows[0][0] != rows[1][0]
    services.start("auth")
    assert rpc("verify", username="alice@localhost", password=replacement)["admin"]


def check_storage(services):
    rpc = lambda op, **fields: services.rpc("storage", op, **fields)
    raw = "From: alice@localhost\r\nTo: bob@localhost\r\nSubject: Persistent mail\r\n\r\nBody\r\n"
    assert not rpc("stats", authorized=False)["ok"]
    assert not rpc("enqueue", sender="alice@localhost", recipients=["bob@localhost", "bad address"], raw=raw)["ok"]
    assert rpc("stats")["queued"] == 0
    assert rpc("enqueue", sender="", recipients=["alice@localhost", "bob@localhost", "bob@localhost"], raw=raw)["ok"]
    jobs = rpc("queue_list", limit=100)["jobs"]
    assert len(jobs) == 2 and len({job["id"] for job in jobs}) == 2
    assert all(job["raw"] == raw and job["sender"] == "" for job in jobs)
    assert rpc("queue_retry", id=jobs[0]["id"], delay=60, error="temporary failure")["ok"]
    assert rpc("queue_reject", id=jobs[1]["id"], error="test quarantine")["ok"]
    assert not rpc("queue_list")["jobs"]
    assert rpc("stats")["quarantined"] == 1
    inspected = rpc("queue_inspect")["jobs"]
    assert all(job["attempts"] == 1 for job in inspected)
    assert {job["state"] for job in inspected} == {"pending", "quarantined"}
    services.stop("storage")
    services.start("storage")
    assert rpc("stats")["quarantined"] == 1
    assert rpc("stats")["queued"] == 1
    for job in jobs:
        assert rpc("queue_finish", id=job["id"])["ok"]
    assert rpc("stats")["queued"] == 0
    assert rpc("stats")["quarantined"] == 0

    first = rpc("deliver", username="alice@localhost", raw=raw, delivery_id="stable-job")
    assert first["ok"]
    again = rpc("deliver", username="alice@localhost", raw=raw, delivery_id="stable-job")
    assert again["id"] == first["id"]
    mailbox = rpc("list", username="alice@localhost")
    assert len(mailbox["messages"]) == 1
    first_uid = mailbox["messages"][0]["uid"]
    validity = mailbox["uidvalidity"]
    assert 0 < validity <= 0xffffffff
    assert mailbox["uidnext"] == first_uid + 1
    assert mailbox["messages"][0]["internal_date"] > 0
    summary = rpc("list", username="alice@localhost", include_envelope=True)["messages"][0]
    assert summary["subject"] == "Persistent mail" and summary["from"] == "alice@localhost"
    assert rpc("get", username="alice@localhost", id=first["id"])["raw"] == raw
    assert not rpc("get", username="bob@localhost", id=first["id"])["ok"]
    assert rpc("delete", username="bob@localhost", ids=[first["id"]])["ok"]
    assert len(rpc("list", username="alice@localhost")["messages"]) == 1
    assert rpc("flags", username="alice@localhost", id=first["id"], seen=True)["ok"]
    assert rpc("list", username="alice@localhost")["messages"][0]["seen"]
    assert not rpc("delete", username="alice@localhost", ids=[first["id"], "invalid id"])["ok"]
    assert len(rpc("list", username="alice@localhost")["messages"]) == 1
    assert rpc("delete", username="alice@localhost", ids=[first["id"]], permanent=True)["ok"]
    assert rpc("deliver", username="alice@localhost", raw=raw, delivery_id="stable-job")["id"] == first["id"]
    assert not rpc("list", username="alice@localhost")["messages"]
    services.stop("storage")
    services.start("storage")
    empty = rpc("list", username="alice@localhost")
    assert empty["uidvalidity"] == validity and empty["uidnext"] == first_uid + 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        deliveries = list(executor.map(lambda _: rpc("deliver", username="alice@localhost", raw=raw,
                                                    delivery_id="concurrent-job"), range(8)))
    assert len({result["id"] for result in deliveries}) == 1
    mailbox = rpc("list", username="alice@localhost")
    assert len(mailbox["messages"]) == 1
    assert mailbox["messages"][0]["uid"] == first_uid + 1
    assert mailbox["uidnext"] == first_uid + 2
    assert rpc("stats")["bytes"] == len(raw.encode())


class MockClamAV:
    def __init__(self, reply, slow=False):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.reply = reply
        self.slow = slow
        self.stopped = threading.Event()
        self.errors = []
        self.payloads = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    @staticmethod
    def read_exact(connection, count):
        result = b""
        while len(result) < count:
            data = connection.recv(count - len(result))
            if not data:
                raise EOFError("unexpected ClamAV client disconnect")
            result += data
        return result

    def run(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except (TimeoutError, OSError):
                continue
            try:
                with connection:
                    connection.settimeout(5)
                    assert self.read_exact(connection, 10) == b"zINSTREAM\x00"
                    payload = b""
                    while True:
                        size = int.from_bytes(self.read_exact(connection, 4), "big")
                        if not size:
                            break
                        assert size <= 65536
                        payload += self.read_exact(connection, size)
                    self.payloads.append(payload)
                    if self.slow:
                        self.stopped.wait(2)
                    else:
                        connection.sendall(self.reply)
            except Exception as error:
                self.errors.append(error)

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(timeout=5)


def check_filter(services):
    rpc = lambda raw: services.rpc("filter", "scan", raw=raw)
    clean = "From: alice@localhost\r\nSubject: Hello\r\n\r\nNormal mail\r\n"
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    assert rpc(clean)["action"] == "accept"
    assert rpc("Subject: EICAR\r\n\r\n" + eicar.decode())["action"] == "reject"
    attachment = ("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=test-boundary\r\n\r\n"
                  "--test-boundary\r\nContent-Type: application/octet-stream\r\n"
                  "Content-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(eicar).decode() +
                  "\r\n--test-boundary--\r\n")
    assert rpc(attachment)["action"] == "reject"
    spam = rpc("Subject: lottery winner\r\n\r\nUrgent money transfer: free money\r\n")
    assert spam["action"] == "reject" and spam["spam_score"] >= 5
    for reply, expected, slow in ((b"stream: OK\0", "accept", False),
                                  (b"stream: Test-Malware FOUND\0", "reject", False),
                                  (b"stream: size limit exceeded ERROR\0", "defer", False),
                                  (b"", "defer", True)):
        mock = MockClamAV(reply, slow)
        try:
            services.stop("filter")
            services.config.update(clamav_host="127.0.0.1", clamav_port=mock.port)
            services.start("filter")
            started = time.monotonic()
            result = rpc(clean)
            assert result["action"] == expected, result
            if slow:
                assert time.monotonic() - started < 2.5, "ClamAV whole-scan deadline not enforced"
            assert mock.payloads and not mock.errors, mock.errors
            if expected == "accept":
                assert any(b"Normal mail" in payload for payload in mock.payloads)
        finally:
            mock.close()
    services.stop("filter")
    services.config["clamav_port"] = free_port()
    services.start("filter")
    unavailable = rpc(clean)
    assert unavailable["action"] == "defer" and not unavailable["ok"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", required=True, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="postplus-storage-") as temporary:
        services = Services(args.bin_dir.resolve(), Path(temporary))
        try:
            for name in ("auth", "storage", "filter"):
                services.start(name)
            check_auth(services)
            check_storage(services)
            check_filter(services)
        finally:
            services.close()
    print("Authentication, storage persistence/idempotency, quarantine, MIME filtering and ClamAV checks passed.")


if __name__ == "__main__":
    main()
