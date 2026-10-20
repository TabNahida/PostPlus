"""Administrator API keys: native HTTP/RPC, persistence, backup and transport."""
import argparse
import hashlib
import http.client
import io
import ipaddress
import json
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import ssl
import subprocess
import sys
import tarfile

from integration import PASSWORD, ROOT, Suite
from maintenance_integration import backup
from password_policy_integration import login

ROUTE = "/api/admin/api-keys"
ADMIN_PERMISSIONS = ["users:read", "users:write", "mail:read", "quota:read", "quota:write", "policy:read", "policy:write",
                     "stats:read", "queue:read", "logs:read", "config:read", "config:write", "backup:read", "backup:write",
                     "services:write", "updates:read", "updates:write", "invites:read", "invites:write", "forwarding:read", "forwarding:write"]


def create(s, browser, name="Deployment integration", **options):
    options.setdefault("permissions", ADMIN_PERMISSIONS)
    status, _, result = s.http("admin", "POST", ROUTE, dict(name=name, **options), browser)
    assert status == 201 and result["ok"], (status, result)
    assert re.fullmatch(r"pp_[0-9a-f]{64}", result["key"])
    metadata = result["api_key"]
    assert re.fullmatch(r"[0-9a-f]{32}", metadata["id"])
    assert metadata["prefix"] == result["key"][:11]
    assert metadata["scope"] == "admin" and metadata["active"]
    assert metadata["last_used_at"] is None and metadata["revoked_at"] is None
    assert "digest" not in json.dumps(metadata) and "key" not in metadata
    return result["key"], metadata


def bearer(key):
    return {"Authorization": "Bearer " + key}


def current(s, browser):
    status, _, result = s.http("admin", "GET", ROUTE, headers=browser)
    assert status == 200 and result["ok"], (status, result)
    assert "key" not in result and "digest" not in json.dumps(result)
    return result


def run(s):
    for name in ("auth", "storage", "web", "admin"):
        s.start(name)
    admin, ordinary = "key-admin@localhost", "mailbox@localhost"
    for user in (admin, ordinary):
        assert s.rpc("auth", op="create", username=user, password=PASSWORD, admin=user == admin)["ok"]
    browser, user = login(s, "admin", admin), login(s, "web", ordinary)
    # This suite deliberately exercises many invalid credentials; IP-ban
    # thresholds and defaults are checked in the dedicated security suites.
    security = s.rpc("auth", op="security_get", actor=admin)
    assert s.rpc("auth", op="security_policy_set", actor=admin, revision=security["revision"],
                 policy=dict(security["policy"], failure_threshold=1000, unknown_user_threshold=1000))["ok"]
    cookie = {"Cookie": browser["Cookie"]}
    assert s.http("admin", "GET", ROUTE)[0] == 401
    assert s.http("admin", "GET", ROUTE, headers=cookie)[0] == 403
    assert current(s, browser)["api_keys"] == []
    assert s.http("admin", "POST", ROUTE, {"name": "Denied"}, cookie)[0] == 403
    assert s.http("web", "GET", ROUTE, headers=user)[0] == 404
    assert s.http("web", "POST", ROUTE, {"name": "Denied"}, user)[0] == 404
    assert s.http("auth", "POST", "/rpc", {"op": "api_key_list", "username": admin})[0] == 401
    assert not s.rpc("auth", op="api_key_create", username=ordinary, name="Denied")["ok"]
    invalid = [{}, {"name": ""}, {"name": "   "}, {"name": "x" * 81}, {"name": "a\nb"}, {"name": False}]
    invalid += [dict(name="Test", expires_in_days=value) for value in (0, -1, 3651, 1.5, True, "1", None, 2**64 - 1)]
    invalid += [dict(name="Test", **{field: value}) for field, value in (("owner", ordinary), ("scope", "web"), ("op", "create"))]
    for payload in invalid:
        assert s.http("admin", "POST", ROUTE, payload, browser)[0] == 400, payload
    assert s.http("admin", "PUT", ROUTE, {}, browser)[0] == 405
    key, metadata = create(s, browser, "  CI automation  ", expires_in_days=7)
    assert metadata["name"] == "CI automation" and metadata["owner"] == admin
    assert metadata["expires_at"] - metadata["created_at"] == 7 * 86400
    indefinite, indefinite_metadata = create(s, browser, "Non-expiring integration")
    assert indefinite_metadata["expires_at"] is None
    for method, path, body in (("GET", ROUTE, None), ("POST", ROUTE, {"name": "Denied"}),
                               ("DELETE", ROUTE + "/" + metadata["id"], None)):
        for headers in (bearer(key), {**browser, **bearer(key)}, {**browser, "Authorization": "Bearer wrong"}):
            assert s.http("admin", method, path, body, headers)[0] == 403
    for authorization in ("", "Bearer wrong", "Basic dGVzdA==", "Bearer " + key + "x", "Bearer " + "pp_" + "0" * 64):
        assert s.http("admin", "GET", "/api/admin/users", headers={**browser, "Authorization": authorization})[0] == 401
    external = bearer(key)
    assert s.http("admin", "GET", "/api/admin/users", headers=external)[0] == 200
    status, _, result = s.http("admin", "POST", "/api/admin/users", dict(username="automated@localhost", password=PASSWORD), external)
    assert status == 201 and result["ok"], result
    assert s.http("admin", "POST", "/api/admin/quota", dict(username=ordinary, quota_bytes=123456), external)[0] == 200
    assert s.http("admin", "GET", "/api/admin/quota?username=" + ordinary, headers=external)[2]["max_bytes"] == 123456
    # Cookie mutations continue to require CSRF even while Bearer is supported.
    assert s.http("admin", "POST", "/api/admin/quota", dict(username=ordinary, quota_bytes=654321), cookie)[0] == 403
    for route in ("/api/session", "/api/folders", "/api/messages"):
        assert s.http("web", "GET", route, headers={**user, **external})[0] == 403, route
    assert s.http("web", "GET", "/api/admin/users", headers=external)[0] == 404
    assert s.http("admin", "GET", "/api/session", headers=external)[0] == 403
    assert s.http("admin", "GET", "/api/messages", headers=external)[0] == 404
    assert s.http("admin", "GET", "/api/admin/users", headers=bearer(s.token))[0] == 401
    assert s.http("auth", "POST", "/rpc", {"op": "list"}, external)[0] == 401
    listed = current(s, browser)["api_keys"]
    used = next(item for item in listed if item["id"] == metadata["id"])
    assert used["last_used_at"] >= used["created_at"] and used["active"]
    assert key not in json.dumps(listed) and indefinite not in json.dumps(listed)
    database_path = s.directory / "data/auth.sqlite3"
    with sqlite3.connect(database_path) as database:
        assert database.execute("PRAGMA user_version").fetchone() == (4,)
        record = database.execute("SELECT digest,prefix FROM api_keys WHERE id=?", (metadata["id"],)).fetchone()
        assert record == (hashlib.sha256(key.encode()).digest(), key[:11]), record
        assert not any(name in ("key", "token", "secret") for _, name, *_ in database.execute("PRAGMA table_info(api_keys)"))
    print("PASS one-time secrets, bounded validation, cookie/CSRF management and Bearer administrator calls", flush=True)

    job = backup(s, browser)
    status, _, archive_bytes = s.http("admin", "GET", job["download_url"], headers=external)
    assert status == 200
    restored_database = s.directory / "api-key-backup.sqlite3"
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        restored_database.write_bytes(archive.extractfile("data/auth.sqlite3").read())
    with sqlite3.connect(restored_database) as database:
        assert database.execute("SELECT digest FROM api_keys WHERE id=?", (metadata["id"],)).fetchone() == (hashlib.sha256(key.encode()).digest(),)
    assert key.encode() not in archive_bytes and indefinite.encode() not in archive_bytes
    s.stop("auth")
    s.stop("admin")
    s.start("auth")
    s.start("admin")
    assert s.http("admin", "GET", "/api/admin/users", headers=external)[0] == 200
    assert s.http("admin", "GET", ROUTE, headers=browser)[0] == 401
    browser = login(s, "admin", admin)
    assert {item["id"] for item in current(s, browser)["api_keys"]} == {metadata["id"], indefinite_metadata["id"]}
    assert s.http("admin", "DELETE", ROUTE + "/" + metadata["id"], headers={"Cookie": browser["Cookie"]})[0] == 403
    status, _, revoked = s.http("admin", "DELETE", ROUTE + "/" + metadata["id"], headers=browser)
    assert status == 200 and not revoked["api_key"]["active"] and revoked["api_key"]["revoked_at"] is not None
    assert "key" not in revoked and "digest" not in json.dumps(revoked)
    assert s.http("admin", "DELETE", ROUTE + "/" + metadata["id"], headers=browser)[0] == 200
    assert s.http("admin", "DELETE", ROUTE + "/" + "0" * 32, headers=browser)[0] == 404
    assert s.http("admin", "DELETE", ROUTE + "/invalid", headers=browser)[0] == 400
    assert s.http("admin", "GET", "/api/admin/users", headers=external)[0] == 401
    s.stop("auth")
    s.start("auth")
    assert s.http("admin", "GET", "/api/admin/users", headers=external)[0] == 401
    assert s.http("admin", "GET", "/api/admin/users", headers=bearer(indefinite))[0] == 200
    expiring, expiry_metadata = create(s, browser, "Expiry boundary", expires_in_days=1)
    assert s.http("admin", "GET", "/api/admin/users", headers=bearer(expiring))[0] == 200
    with sqlite3.connect(database_path) as database:
        last_used = database.execute("SELECT last_used_at FROM api_keys WHERE id=?", (expiry_metadata["id"],)).fetchone()
        database.execute("UPDATE api_keys SET expires_at=unixepoch() WHERE id=?", (expiry_metadata["id"],))
    assert s.http("admin", "GET", "/api/admin/users", headers={**browser, **bearer(expiring)})[0] == 401
    with sqlite3.connect(database_path) as database:
        assert database.execute("SELECT last_used_at FROM api_keys WHERE id=?", (expiry_metadata["id"],)).fetchone() == last_used
        database.execute("UPDATE users SET admin=0 WHERE username=?", (admin,))
    assert s.http("admin", "GET", "/api/admin/users", headers=bearer(indefinite))[0] == 401
    with sqlite3.connect(database_path) as database:
        database.execute("UPDATE users SET admin=1 WHERE username=?", (admin,))
    assert s.http("admin", "GET", "/api/admin/users", headers=bearer(indefinite))[0] == 200
    another = "other-admin@localhost"
    assert s.rpc("auth", op="create", username=another, password=PASSWORD, admin=True)["ok"]
    other_key, other_metadata = create(s, login(s, "admin", another), "Deleted owner")
    with sqlite3.connect(database_path) as database:
        database.execute("DELETE FROM users WHERE username=?", (another,))
    assert s.http("admin", "GET", "/api/admin/users", headers=bearer(other_key))[0] == 401
    assert not next(item for item in current(s, browser)["api_keys"] if item["id"] == other_metadata["id"])["active"]
    print("PASS restart persistence, digest-only backup, durable revocation, expiry and live administrator ownership", flush=True)

    # Bound active credentials through actual auth operations, then exercise
    # retention with database fixtures representing a long-running deployment.
    ids = []
    for index in range(99):
        result = s.rpc("auth", op="api_key_create", username=admin, name=f"Limit fixture {index}", permissions=ADMIN_PERMISSIONS)
        assert result["ok"], result
        ids.append(result["api_key"]["id"])
    assert s.http("admin", "POST", ROUTE, dict(name="Above active limit", permissions=ADMIN_PERMISSIONS), browser)[0] == 409
    for identifier in ids:
        assert s.rpc("auth", op="api_key_revoke", username=admin, id=identifier)["ok"]
    with sqlite3.connect(database_path) as database:
        count = database.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]
        database.executemany("INSERT INTO api_keys(id,name,prefix,owner,digest,created_at,revoked_at) VALUES(?,?,?,?,?,1,2)",
                             [(secrets.token_hex(16), "Retention fixture", "pp_redacted", admin, secrets.token_bytes(32)) for _ in range(1000 - count)])
    retention_key, _ = create(s, browser, "Retention remains usable")
    assert len(current(s, browser)["api_keys"]) == 1000
    with sqlite3.connect(database_path) as database:
        assert database.execute("SELECT COUNT(*) FROM api_keys").fetchone() == (1000,)
    assert s.http("admin", "GET", "/api/admin/users", headers=bearer(indefinite))[0] == 200
    assert s.http("admin", "GET", "/api/admin/users", headers=bearer(retention_key))[0] == 200
    logs = "".join(path.read_text(errors="replace") for path in s.directory.rglob("*.log"))
    assert "API key " + metadata["id"] + " owned by administrator " + admin in logs
    for secret in (key, indefinite, expiring, other_key, retention_key):
        assert secret not in logs
        for file in (database_path, Path(str(database_path) + "-wal"), restored_database):
            if file.exists():
                assert secret.encode() not in file.read_bytes()
    print("PASS active/storage limits, inactive metadata retention and secret-free audit/database files", flush=True)


def local_nonloopback_address():
    addresses = []
    for hostname in (socket.gethostname(), socket.getfqdn()):
        try:
            entries = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror:
            continue
        for info in entries:
            value = info[4][0]
            if not ipaddress.ip_address(value).is_loopback:
                addresses.append(value)
    if sys.platform.startswith("linux"):
        # WSL and container hostnames commonly resolve only to loopback.
        # Enumerate local interface addresses without contacting any remote
        # host; every candidate must still bind to this actual test machine.
        try:
            output = subprocess.check_output(["hostname", "-I"], text=True, timeout=5)
            for value in output.split():
                try:
                    parsed = ipaddress.ip_address(value)
                except ValueError:
                    continue
                if parsed.version == 4 and not parsed.is_loopback:
                    addresses.append(value)
        except (OSError, subprocess.SubprocessError):
            pass
        if not addresses:
            try:
                output = subprocess.check_output(["ip", "-j", "-4", "addr", "show"], text=True, timeout=5)
                for interface in json.loads(output):
                    for entry in interface.get("addr_info", []):
                        value = entry.get("local", "")
                        try:
                            parsed = ipaddress.ip_address(value)
                        except ValueError:
                            continue
                        if parsed.version == 4 and not parsed.is_loopback:
                            addresses.append(value)
            except (OSError, subprocess.SubprocessError, ValueError):
                pass
    for value in addresses:
        try:
            with socket.socket() as probe:
                probe.bind((value, 0))
            return value
        except OSError:
            continue
    return None


def http_connection(s, host, *, encrypted=False, method="GET", path="/api/admin/users", body=None, headers=None):
    if encrypted:
        context = ssl.create_default_context(cafile=str(ROOT / "tests/fixtures/localhost-test-only.crt"))
        connection = http.client.HTTPSConnection(host, s.ports["admin"], context=context, timeout=10)
    else:
        connection = http.client.HTTPConnection(host, s.ports["admin"], timeout=10)
    try:
        # The transport fixture hosts the localhost admin portal. Preserve that
        # authority even when connecting through a non-loopback interface so
        # these assertions continue to exercise transport enforcement.
        connection.request(method, path, None if body is None else json.dumps(body), {"Content-Type": "application/json", "Host": "localhost", **(headers or {})})
        response = connection.getresponse()
        result = json.loads(response.read())
        return response.status, dict(response.getheaders()), result
    finally:
        connection.close()


def transport(binaries, directory):
    directory.mkdir(parents=True)
    s = Suite(binaries, directory)
    s.config.update(bind="0.0.0.0", admin_bind="0.0.0.0")
    s.save()
    try:
        s.start("auth")
        s.start("admin")
        admin = "transport-admin@localhost"
        assert s.rpc("auth", op="create", username=admin, password=PASSWORD, admin=True)["ok"]
        browser = login(s, "admin", admin)
        key, metadata = create(s, browser, "Transport integration")
        address = local_nonloopback_address()
        assert address is not None, "A local non-loopback IPv4 interface is required for the remote cleartext rejection regression."
        assert http_connection(s, address, headers={**browser, **bearer(key)})[0] == 403
        assert http_connection(s, address, headers={**bearer(key), "X-Forwarded-Proto": "https", "X-Forwarded-For": "127.0.0.1"})[0] == 403
        assert http_connection(s, address, path=ROUTE, headers=browser)[0] == 403
        s.stop("admin")
        # Explicit loopback API key access is permitted without enabling local
        # plaintext password authentication. Remote connections still fail.
        s.config["allow_insecure_auth"] = False
        s.save()
        s.start("admin")
        assert s.http("admin", "GET", "/api/admin/users", headers={**bearer(key), "Host": "localhost"})[0] == 200
        assert s.http("admin", "POST", "/api/login", dict(username=admin, password=PASSWORD), {"Host": "localhost"})[0] == 403
        assert http_connection(s, address, headers=bearer(key))[0] == 403
        s.stop("admin")
        s.config.update(tls_certificate=str(ROOT / "tests/fixtures/localhost-test-only.crt"),
                        tls_private_key=str(ROOT / "tests/fixtures/localhost-test-only.key"))
        s.save()
        s.start("admin")
        assert http_connection(s, "localhost", encrypted=True, headers=bearer(key))[0] == 200
        status, headers, session = http_connection(s, "localhost", encrypted=True, method="POST", path="/api/login", body=dict(username=admin, password=PASSWORD))
        assert status == 200 and "; Secure" in headers["Set-Cookie"], session
        authorized = {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": session["csrf"]}
        assert http_connection(s, "localhost", encrypted=True, method="DELETE", path=ROUTE + "/" + metadata["id"], headers=authorized)[0] == 200
        assert http_connection(s, "localhost", encrypted=True, headers=bearer(key))[0] == 401
        print("PASS cleartext non-loopback and spoofed proxy-header rejection, loopback key access and verified HTTPS", flush=True)
    finally:
        s.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("api-keys-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    finally:
        suite.close()
    transport(args.bin_dir.resolve(), directory / "transport")
