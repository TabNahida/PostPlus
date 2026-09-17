"""Real online backup/restore, authorization, and native shutdown contracts."""
import argparse
import io
import json
from pathlib import Path
import secrets
import sqlite3
import tarfile
import time

from integration import Suite, ROOT, PASSWORD
from mailbox_web_integration import login
from setup_integration import NativeServer, assert_ports_closed, assert_private, http, request_stop


def backup(s, headers):
    status, _, job = s.http("admin", "POST", "/api/admin/backup", {}, headers)
    assert status == 202, (status, job)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status, _, result = s.http("admin", "GET", "/api/admin/backup?job_id=" + job["job_id"], headers=headers)
        assert status == 200, result
        if result["state"] != "running":
            assert result["state"] == "complete", result
            return result
        time.sleep(0.05)
    raise AssertionError("backup did not complete")


def run(s):
    for name in ("auth", "storage", "admin", "web"):
        s.start(name)
    admin, user = "admin@localhost", "mailbox@localhost"
    for name in (admin, user):
        assert s.rpc("auth", op="create", username=name, password=PASSWORD, admin=name == admin)["ok"]
    assert s.rpc("storage", op="deliver", username=user, raw="Subject: Backed up\r\n\r\nPrivate restored content\r\n", delivery_id=secrets.token_hex(16))["ok"]
    assert s.rpc("storage", op="draft_save", username=user, raw="Subject: Draft snapshot\r\n\r\nDraft body\r\n")["ok"]
    assert s.rpc("storage", op="quota_set", username=user, max_bytes=4 * 1024**3)["ok"]
    assert s.rpc("storage", op="enqueue", sender=user, recipients=["external@example.com"], raw="Subject: Queued backup\r\n\r\nPending\r\n")["ok"]
    policy = s.rpc("auth", op="password_policy_get")
    revised = dict(policy["policy"], min_length=9, require_digit=True)
    assert s.rpc("auth", op="password_policy_set", revision=policy["revision"], policy=revised)["ok"]
    authorized = login(s, "admin", admin)
    ordinary = login(s, "web", user)
    cookie = {"Cookie": authorized["Cookie"]}
    for service in ("web", "admin"):
        assert s.http(service, "GET", "/api/public/config")[2] == {"ok": True, "domain": "localhost"}
    for route in ("/api/admin/backup", "/api/admin/shutdown"):
        assert s.http("admin", "POST", route, {})[0] == 401
        assert s.http("admin", "POST", route, {}, cookie)[0] == 403
        assert s.http("web", "POST", route, {}, ordinary)[0] == 404
    assert s.http("admin", "GET", "/api/admin/backup/download?job_id=anything")[0] == 401
    assert s.http("admin", "GET", "/api/admin/backup/download?job_id=../../config/postplus.json", headers=cookie)[0] == 404
    assert s.http("admin", "POST", "/api/admin/shutdown", {}, authorized)[0] == 503, "standalone admin must not claim native shutdown succeeded"
    # Saved, not yet applied settings and credentials must travel with the archive.
    certificate = ROOT / "tests/fixtures/localhost-test-only.crt"
    private_key = ROOT / "tests/fixtures/localhost-test-only.key"
    relay_secret = s.directory / "relay.secret"
    relay_secret.write_text("saved-relay-test-secret", encoding="utf-8")
    s.config.update(tls_certificate=str(certificate), tls_private_key=str(private_key),
                    smarthost_password_file=str(relay_secret), smarthost_password_env="POSTPLUS_MAINTENANCE_TEST_RELAY")
    s.save()
    job = backup(s, authorized)
    assert job["download_url"] == "/api/admin/backup/download?job_id=" + job["job_id"]
    archive_path = s.directory / "data" / (".backup-" + job["job_id"]) / "postplus-backup.tar"
    assert_private(archive_path)
    status, headers, raw = http(s.ports["admin"], "GET", job["download_url"], headers=cookie)
    assert status == 200 and headers["Content-Type"] == "application/x-tar"
    assert int(headers["Content-Length"]) == len(raw) and "attachment;" in headers["Content-Disposition"]
    restored = s.directory / "restore"
    restored.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        names = set(archive.getnames())
        assert names == {"data/auth.sqlite3", "data/storage.sqlite3", "config/postplus.json", "config/service-token.secret", "config/smarthost.secret", "config/certificates/fullchain.pem", "config/certificates/private-key.pem", "manifest.json", "RESTORE.txt"}, names
        assert all(member.isfile() and member.mode == 0o600 for member in archive.getmembers())
        archive.extractall(restored, filter="data")
    for database in ("auth", "storage"):
        with sqlite3.connect(restored / "data" / (database + ".sqlite3")) as connection:
            assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    with sqlite3.connect(restored / "data/auth.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM users").fetchone() == (2,)
        assert connection.execute("SELECT min_length,require_digit FROM password_policy").fetchone() == (9, 1)
    config = json.loads((restored / "config/postplus.json").read_text())
    assert config["data_dir"] == "../data" and config["web_root"] == "../web"
    assert (restored / "config/service-token.secret").read_text() == s.token
    assert config["service_token_file"] == "service-token.secret"
    assert (restored / "config/certificates/fullchain.pem").read_bytes() == certificate.read_bytes()
    assert (restored / "config/certificates/private-key.pem").read_bytes() == private_key.read_bytes()
    assert (restored / "config/smarthost.secret").read_text() == "saved-relay-test-secret"
    next_job = backup(s, authorized)
    assert next_job["job_id"] != job["job_id"]
    assert s.http("admin", "GET", job["download_url"], headers=cookie)[0] == 404
    print("PASS online SQLite backup, archive extraction/integrity, private permissions, session/CSRF and safe download routes", flush=True)
    s.close()
    config["web_root"] = str(ROOT / "web")
    # This test's isolated listener uses plaintext loopback after verifying the
    # archived TLS pair byte-for-byte; TLS handshakes have their own suite.
    config["tls_certificate"] = ""
    config["tls_private_key"] = ""
    restored_config = restored / "config/postplus.json"
    restored_config.write_text(json.dumps(config), encoding="utf-8")
    server = NativeServer(s.binaries, restored_config, s.ports["admin"], s.directory, "restored-native")
    try:
        server.wait(server.services_ready)
        status, headers, session = http(s.ports["admin"], "POST", "/api/login", {"username": admin, "password": PASSWORD})
        assert status == 200
        a = {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": session["csrf"]}
        assert http(s.ports["admin"], "GET", "/api/admin/password-policy", headers=a)[2]["policy"] == revised
        status, _, inbox = http(s.ports["admin"], "GET", "/api/admin/messages?username=" + user, headers=a)
        assert status == 200 and len(inbox["messages"]) == 1
        assert http(s.ports["admin"], "GET", "/api/admin/messages?username=" + user + "&folder=Drafts", headers=a)[2]["messages"]
        assert http(s.ports["admin"], "GET", "/api/admin/quota?username=" + user, headers=a)[2]["max_bytes"] == 4 * 1024**3
        assert http(s.ports["admin"], "GET", "/api/admin/stats", headers=a)[2]["queued"] == 1
        settings = http(s.ports["admin"], "GET", "/api/admin/config", headers=a)[2]
        assert http(s.ports["admin"], "POST", "/api/admin/config", {"revision": settings["revision"], "values": {"log_level": "warn"}}, a)[0] == 200
        status, _, stopped = http(s.ports["admin"], "POST", "/api/admin/shutdown", {}, a)
        assert status == 202 and stopped["state"] == "shutting_down"
        assert server.process.wait(timeout=45) == 0
        server.reader.join(timeout=3)
        lines = "".join(server.lines)
        assert "administrator requested shutdown" in lines
        assert "1/3 closing" in lines and "2/3 stopping" in lines and "3/3 stopping" in lines
        assert "service group stopped; data saved" in lines
        assert lines.index("admin stopped (exit 0)") < lines.index("requesting storage to stop")
        assert_ports_closed(s.ports)
        assert json.loads(restored_config.read_text())["log_level"] == "warn"
    finally:
        server.close()
    server = NativeServer(s.binaries, restored_config, s.ports["admin"], s.directory, "quiet-native")
    try:
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            assert server.process.poll() is None, "quiet supervisor failed"
            try:
                if http(s.ports["admin"], "GET", "/health")[0] == 200 and any("Webmail:" in line for line in server.lines):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("quiet supervisor did not start")
        request_stop(server.process.pid)
        assert server.process.wait(timeout=45) == 0
        server.reader.join(timeout=3)
        lines = "".join(server.lines)
        assert "[shutdown] shutdown signal received" in lines
        assert "[shutdown] service group stopped; data saved" in lines
        assert_ports_closed(s.ports)
    finally:
        server.close()
    print("PASS restored accounts/folders/quotas/policy, saved settings, administrator shutdown and quiet terminal signal progress", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("maintenance-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    # Exercise the maximum allowed service-token file size on restore.
    suite.token = secrets.token_hex(512)
    suite.env["POSTPLUS_SERVICE_TOKEN"] = suite.token
    try:
        run(suite)
    finally:
        suite.close()


if __name__ == "__main__":
    main()
