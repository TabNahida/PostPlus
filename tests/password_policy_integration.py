"""Live password policy, migration, and enforcement across HTTP/RPC/CLI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess

from integration import PASSWORD, ROOT, Suite


DEFAULT = dict(min_length=8, require_uppercase=False, require_lowercase=False,
               require_digit=False, require_symbol=False)
POLICY_ROUTE = "/api/admin/password-policy"


def login(s, service, username, password=PASSWORD):
    status, headers, result = s.http(service, "POST", "/api/login", dict(username=username, password=password))
    assert status == 200, (status, result)
    return {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": result["csrf"]}


def violation(result, *expected):
    assert not result["ok"] and result["code"] == "password_policy_violation", result
    assert set(result["violations"]) == set(expected), result
    assert result["length_unit"] == "unicode_code_points" and result["restart_required"] is False
    assert "password" not in result


def run(s):
    for service in ("auth", "web", "admin"):
        s.start(service)
    original_config = s.path.read_bytes()
    pids = {name: child.pid for name, child in s.children.items()}
    initial = s.rpc("auth", op="password_policy_get")
    assert initial == dict(ok=True, policy=DEFAULT, revision=1, max_password_bytes=1024,
                           length_unit="unicode_code_points", restart_required=False), initial
    admin, user = "policy-admin@localhost", "policy-user@localhost"
    for name in (admin, user):
        assert s.rpc("auth", op="create", username=name, password=PASSWORD, admin=name == admin)["ok"]
    a, u = login(s, "admin", admin), login(s, "web", user)
    assert s.http("admin", "GET", POLICY_ROUTE)[0] == 401
    assert s.http("admin", "POST", "/api/login", dict(username=user, password=PASSWORD))[0] == 403
    assert s.http("web", "GET", POLICY_ROUTE, headers=u)[0] == 404
    assert s.http("web", "POST", POLICY_ROUTE, dict(policy=DEFAULT, revision=1), u)[0] == 404
    assert s.http("auth", "POST", "/rpc", dict(op="password_policy_get"))[0] == 401
    assert s.http("auth", "POST", "/rpc", dict(op="password_policy_set", policy=DEFAULT, revision=1))[0] == 401
    assert s.http("admin", "GET", POLICY_ROUTE, headers=a)[2] == initial
    assert s.http("admin", "POST", POLICY_ROUTE, dict(policy=DEFAULT, revision=1), {"Cookie": a["Cookie"]})[0] == 403
    assert s.http("admin", "PUT", POLICY_ROUTE, {}, a)[0] == 405
    for op in ("create", "change_password"):
        violation(s.rpc("auth", op=op, username=user, password="short"), "min_length")
    for route in ("/api/admin/users", "/api/admin/password"):
        status, _, result = s.http("admin", "POST", route, dict(username=user, password="short"), a)
        assert status == 400, result
        violation(result, "min_length")

    def current():
        status, _, result = s.http("admin", "GET", POLICY_ROUTE, headers=a)
        assert status == 200, result
        return result

    def save(policy):
        before = current()
        status, _, result = s.http("admin", "POST", POLICY_ROUTE, dict(policy=policy, revision=before["revision"]), a)
        assert status == 200 and result["policy"] == policy and not result["restart_required"], result
        assert result["revision"] == before["revision"] + (before["policy"] != policy)
        return result

    relaxed = dict(DEFAULT)
    saved = save(dict(DEFAULT, require_lowercase=True))
    assert saved["revision"] == 2
    assert save(saved["policy"]) == saved
    status, _, conflict = s.http("admin", "POST", POLICY_ROUTE, dict(policy=DEFAULT, revision=1), a)
    assert status == 409 and conflict["code"] == "password_policy_conflict" and conflict["revision"] == 2
    assert conflict["policy"] == saved["policy"]
    assert not s.rpc("auth", op="password_policy_set", policy=DEFAULT, revision=1)["ok"]
    assert s.http("admin", "POST", "/api/admin/users", dict(username="eight@localhost", password="abcdefgh"), a)[0] == 201
    assert s.http("admin", "POST", "/api/admin/password", dict(username=user, password="ijklmnop"), a)[0] == 200
    assert s.http("web", "GET", "/api/session", headers=u)[0] == 401, "Actual resets must still revoke sessions"
    u = login(s, "web", user, "ijklmnop")
    version = s.rpc("auth", op="verify", username=user, password="ijklmnop", session=True)["credential_version"]

    # Validate full-object semantics, strict JSON types, ranges, and bounded revisions.
    invalid = [
        dict(policy={}, revision=2), dict(policy=[], revision=2), dict(policy=None, revision=2),
        dict(policy=dict(relaxed, extra=False), revision=2), dict(policy=relaxed, revision=2, extra=False),
        dict(policy=relaxed), dict(revision=2),
    ]
    invalid += [dict(policy=dict(relaxed, min_length=value), revision=2)
                for value in (0, 7, 129, -1, True, "8", 8.0, 2**64 - 1)]
    invalid += [dict(policy=dict(relaxed, require_digit=value), revision=2)
                for value in (1, 0, "true", None)]
    invalid += [dict(policy=relaxed, revision=value) for value in (0, -1, True, "2", 2.0, 2**64 - 1)]
    for payload in invalid:
        status, _, result = s.http("admin", "POST", POLICY_ROUTE, payload, a)
        assert status == 400 and result["code"] == "invalid_password_policy" and result["errors"], (payload, status, result)
        assert current() == saved, "Invalid policy mutated saved state"
    bad_rpc = s.rpc("auth", op="password_policy_set", revision=2, policy=dict(relaxed, min_length=7))
    assert bad_rpc["code"] == "invalid_password_policy"
    print("PASS password policy authorization, live updates, strict fields and revision conflicts", flush=True)

    category_cases = (
        ("require_uppercase", "abcdefgh", "Abcdefgh"),
        ("require_lowercase", "ABCDEFGH", "aBCDEFGH"),
        ("require_digit", "abcdefgh", "abcdefg1"),
        ("require_symbol", "abcdefgh", "abcdefg!"),
    )
    for index, (category, weak, strong) in enumerate(category_cases):
        save(dict(relaxed, **{category: True}))
        name = f"category-{index}@localhost"
        violation(s.rpc("auth", op="create", username=name, password=weak), category)
        violation(s.rpc("auth", op="change_password", username=user, password=weak), category)
        assert s.rpc("auth", op="create", username=name, password=strong)["ok"]
        assert s.rpc("auth", op="verify", username=name, password=strong)["ok"]
    for value in ("abcd    ", "abcd\t\t\t\t", "abcd😀😀😀😀", "abcd。。，，"):
        violation(s.rpc("auth", op="create", username="not-symbol@localhost", password=value), "require_symbol")

    strong_policy = dict(min_length=16, require_uppercase=True, require_lowercase=True,
                         require_digit=True, require_symbol=True)
    save(strong_policy)
    violation(s.rpc("auth", op="change_password", username=user, password="abcdefgh"),
              "min_length", "require_uppercase", "require_digit", "require_symbol")
    # Changing policy preserves both the old credential and all sessions.
    assert s.rpc("auth", op="verify", username=user, password="ijklmnop", session=True)["credential_version"] == version
    assert s.http("web", "GET", "/api/session", headers=u)[0] == 200
    assert s.http("admin", "GET", "/api/session", headers=a)[0] == 200
    login(s, "web", "eight@localhost", "abcdefgh")
    executable = s.binaries / ("postplus-ctl.exe" if os.name == "nt" else "postplus-ctl")
    for command, account in (("create-user", "cli-weak@localhost"), ("password", user)):
        result = subprocess.run([str(executable), command, account, "--config", str(s.path)],
                                input="weak-cli-secret\n", text=True, capture_output=True, env=s.env, timeout=20,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        assert result.returncode != 0 and "account password policy" in result.stderr, result.stderr
        assert "weak-cli-secret" not in result.stderr + result.stdout
    assert not s.rpc("auth", op="exists", username="cli-weak@localhost")["exists"]
    assert s.rpc("auth", op="verify", username=user, password="ijklmnop")["ok"]
    print("PASS every diversity category, immutable old credentials/sessions and CLI enforcement", flush=True)

    save(relaxed)
    violation(s.rpc("auth", op="create", username="unicode-short@localhost", password="😀" * 7), "min_length")
    assert s.rpc("auth", op="create", username="unicode-eight@localhost", password="密" * 8)["ok"]
    assert s.rpc("auth", op="create", username="unicode-emoji@localhost", password="😀" * 8)["ok"]
    assert s.rpc("auth", op="create", username="combining@localhost", password="a\u0301" * 4)["ok"]
    assert s.rpc("auth", op="create", username="no-trimming@localhost", password="  abcd  ")["ok"]
    assert s.rpc("auth", op="verify", username="no-trimming@localhost", password="  abcd  ")["ok"]
    assert not s.rpc("auth", op="verify", username="no-trimming@localhost", password="abcd")["ok"]
    violation(s.rpc("auth", op="create", username="byte-cap@localhost", password="密" * 350), "max_password_bytes")
    status, _, result = s.http("admin", "POST", "/api/admin/users", dict(username="byte-cap@localhost", password="x" * 1025), a)
    assert status == 400
    violation(result, "max_password_bytes")
    final_policy = save(strong_policy)
    with sqlite3.connect(s.directory / "data/auth.sqlite3") as database:
        before_users = database.execute("SELECT username,salt,password_hash,iterations,admin,created_at FROM users ORDER BY username").fetchall()
        assert database.execute("PRAGMA user_version").fetchone()[0] == 2
    assert s.path.read_bytes() == original_config, "Live policy changed the configuration file"
    assert {name: child.pid for name, child in s.children.items()} == pids, "Live policy restarted a process"
    s.stop("auth")
    s.start("auth")
    assert current() == final_policy
    assert s.http("web", "GET", "/api/session", headers=u)[0] == 200
    with sqlite3.connect(s.directory / "data/auth.sqlite3") as database:
        assert database.execute("SELECT username,salt,password_hash,iterations,admin,created_at FROM users ORDER BY username").fetchall() == before_users
    logs = s.http("admin", "GET", "/api/admin/logs?service=auth&limit=200", headers=a)[2]
    assert any("account password policy changed" in item["message"] for item in logs["entries"])
    admin_logs = s.http("admin", "GET", "/api/admin/logs?service=admin&limit=200", headers=a)[2]
    assert any(admin in item["message"] and "password policy" in item["message"] for item in admin_logs["entries"])
    for secret in (PASSWORD, s.token, "weak-cli-secret", "ijklmnop"):
        assert secret not in json.dumps(logs) + json.dumps(admin_logs)
    print("PASS Unicode codepoint/byte limits, no password transformation, persistence and safe audit", flush=True)


def migration_and_small_cap(binaries, directory):
    """Upgrade a real v1 database without rewriting its credentials."""
    directory.mkdir(parents=True)
    s = Suite(binaries, directory)
    s.config["max_password_bytes"] = 12
    s.save()
    data = directory / "data"
    data.mkdir()
    username, password = "legacy@localhost", "legacy-pass!"
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000, dklen=32)
    with sqlite3.connect(data / "auth.sqlite3") as database:
        database.executescript("CREATE TABLE users (username TEXT PRIMARY KEY, salt BLOB NOT NULL, password_hash BLOB NOT NULL,"
                               "iterations INTEGER NOT NULL, admin INTEGER NOT NULL CHECK(admin IN (0,1)),"
                               "created_at INTEGER NOT NULL DEFAULT (unixepoch())); PRAGMA user_version=1;")
        database.execute("INSERT INTO users VALUES(?,?,?,?,?,?)", (username, salt, digest, 600000, 1, 1000000))
    try:
        s.start("auth")
        assert s.rpc("auth", op="verify", username=username, password=password)["ok"]
        view = s.rpc("auth", op="password_policy_get")
        assert view["policy"] == DEFAULT and view["revision"] == 1 and view["max_password_bytes"] == 12
        with sqlite3.connect(data / "auth.sqlite3") as database:
            assert database.execute("PRAGMA user_version").fetchone()[0] == 2
            assert database.execute("SELECT * FROM users").fetchall() == [(username, salt, digest, 600000, 1, 1000000)]
        result = s.rpc("auth", op="password_policy_set", revision=1, policy=dict(DEFAULT, min_length=13))
        assert result["code"] == "invalid_password_policy" and result["errors"] == [dict(field="min_length", code="out_of_range", min=8, max=12)]
        assert s.rpc("auth", op="password_policy_set", revision=1, policy=dict(DEFAULT, min_length=8))["ok"]
        violation(s.rpc("auth", op="create", username="cap@localhost", password="密" * 8), "max_password_bytes")
        assert s.rpc("auth", op="create", username="cap@localhost", password="abcdefgh")["ok"]
        s.stop("auth")
        s.start("auth")
        assert s.rpc("auth", op="password_policy_get")["revision"] == 1
        assert s.rpc("auth", op="verify", username=username, password=password)["ok"]
        print("PASS v1 schema migration preserves hashes and small byte caps reject impossible policies", flush=True)
    finally:
        s.close()


def large_password_http(binaries, directory):
    """A configured byte cap above 1024 also works through both browser APIs."""
    directory.mkdir(parents=True)
    s = Suite(binaries, directory)
    s.config["max_password_bytes"] = 2048
    s.save()
    try:
        for service in ("auth", "web", "admin"):
            s.start(service)
        admin, account = "admin@localhost", "long-password@localhost"
        assert s.rpc("auth", op="create", username=admin, password=PASSWORD, admin=True)["ok"]
        a = login(s, "admin", admin)
        assert s.http("admin", "GET", POLICY_ROUTE, headers=a)[2]["max_password_bytes"] == 2048
        large_password = "Long-Password1!" * 100
        assert len(large_password) == 1500
        status, _, result = s.http("admin", "POST", "/api/admin/users",
                                   dict(username=account, password=large_password, admin=True), a)
        assert status == 201 and result["ok"], (status, result)
        u, owner = login(s, "web", account, large_password), login(s, "admin", account, large_password)
        assert s.http("web", "GET", "/api/session", headers=u)[0] == 200
        assert s.http("admin", "GET", "/api/session", headers=owner)[0] == 200
        replacement = "Changed-Pass-2!" * 100
        assert len(replacement) > 1024
        assert s.http("admin", "POST", "/api/admin/password", dict(username=account, password=replacement), a)[0] == 200
        assert s.http("web", "GET", "/api/session", headers=u)[0] == 401
        assert s.http("admin", "GET", "/api/session", headers=owner)[0] == 401
        login(s, "web", account, replacement)
        login(s, "admin", account, replacement)
        print("PASS passwords above 1024 bytes through HTTP create/reset and both portal logins", flush=True)
    finally:
        s.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("password-policy-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    finally:
        suite.close()
    migration_and_small_cap(args.bin_dir.resolve(), directory / "migration")
    large_password_http(args.bin_dir.resolve(), directory / "large-password")
