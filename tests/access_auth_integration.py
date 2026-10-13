"""Real auth process: least privilege keys, legacy migration, and atomic invitations."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3

from integration import PASSWORD, ROOT, Suite
from api_keys_integration import ADMIN_PERMISSIONS


def create_key(s, owner, permissions, *, audience="admin"):
    result = s.rpc("auth", op="api_key_create", username=owner, name="Scoped key", audience=audience, permissions=permissions)
    assert result["ok"], result
    return result


def run(s):
    s.start("auth")
    admin, alice, bob = "access-admin@localhost", "access-alice@localhost", "access-bob@localhost"
    for user in (admin, alice, bob):
        assert s.rpc("auth", op="create", username=user, password=PASSWORD, admin=user == admin)["ok"]
    dbpath = s.directory / "data/auth.sqlite3"
    assert s.rpc("auth", op="api_key_create", username=admin, name="No implicit grants")["code"] == "invalid_api_key"
    for permissions in (["unknown:read"], ["users:read", "users:read"], "users:read", [True], ["codes:read"]):
        assert s.rpc("auth", op="api_key_create", username=admin, name="Invalid", permissions=permissions)["code"] == "invalid_api_key"
    readonly = create_key(s, admin, ["users:read"])
    token, identifier = readonly["key"], readonly["api_key"]["id"]
    verified = s.rpc("auth", op="api_key_verify", key=token)
    assert verified["valid"] and verified["admin"] and verified["audience"] == "admin" and verified["permissions"] == ["users:read"]
    with sqlite3.connect(dbpath) as db:
        digest = db.execute("SELECT digest FROM api_keys WHERE id=?", (identifier,)).fetchone()[0]
    updated = s.rpc("auth", op="api_key_update", username=admin, id=identifier, permissions=["stats:read"])
    assert updated["ok"] and "key" not in updated and updated["api_key"]["permissions"] == ["stats:read"]
    assert s.rpc("auth", op="api_key_verify", key=token)["permissions"] == ["stats:read"]
    with sqlite3.connect(dbpath) as db:
        assert db.execute("SELECT digest FROM api_keys WHERE id=?", (identifier,)).fetchone()[0] == digest == hashlib.sha256(token.encode()).digest()
    mailbox = create_key(s, alice, ["codes:read"], audience="mailbox")
    mailbox_id, mailbox_token = mailbox["api_key"]["id"], mailbox["key"]
    view = s.rpc("auth", op="api_key_verify", key=mailbox_token)
    assert view["valid"] and not view["admin"] and view["username"] == alice and view["permissions"] == ["codes:read"]
    assert s.rpc("auth", op="api_key_list", username=bob, audience="mailbox")["api_keys"] == []
    for op in ("api_key_update", "api_key_revoke"):
        assert s.rpc("auth", op=op, username=bob, audience="mailbox", id=mailbox_id, permissions=[])["code"] == "api_key_not_found"
    assert s.rpc("auth", op="api_key_update", username=alice, audience="admin", id=identifier, permissions=[])["code"] == "administrator_required"
    assert s.rpc("auth", op="api_key_update", username=alice, audience="mailbox", id=mailbox_id, permissions=[])["ok"]
    assert s.rpc("auth", op="api_key_verify", key=mailbox_token)["permissions"] == []
    s.stop("auth"); s.start("auth")
    assert s.rpc("auth", op="api_key_verify", key=token)["permissions"] == ["stats:read"]
    assert s.rpc("auth", op="api_key_revoke", username=alice, audience="mailbox", id=mailbox_id)["ok"]
    assert not s.rpc("auth", op="api_key_verify", key=mailbox_token)["valid"]
    print("PASS explicit scopes, immediate edits without secret rotation, owner-bound mailbox audience and durable revocation", flush=True)

    def invite(**options):
        result = s.rpc("auth", op="invite_create", username=admin, name="Recipient onboarding", **options)
        assert result["ok"], result
        return result["token"], result["invitation"]

    assert s.rpc("auth", op="invite_create", username=alice, name="No admin")["code"] == "administrator_required"
    for options in ({"domain": "foreign.example"}, {"localpart": "x@localhost"}, {"localpart": "x", "max_uses": 2},
                    {"max_uses": True}, {"max_uses": 101}, {"expires_in_days": 0}, {"expires_in_days": 366}):
        assert s.rpc("auth", op="invite_create", username=admin, name="Invalid", **options)["code"] == "invalid_invitation", options
    invitation_token, invitation = invite(max_uses=3)
    inspected = s.rpc("auth", op="invite_inspect", token=invitation_token)
    assert inspected["ok"] and inspected["domain"] == "localhost" and inspected["localpart"] == "" and "policy" in inspected
    assert "owner" not in inspected and "token" not in inspected and "digest" not in json.dumps(inspected)
    for payload in ({"localpart": "short", "password": "x"}, {"localpart": "bad@foreign.example", "password": PASSWORD},
                    {"localpart": "privileged", "password": PASSWORD, "admin": True}):
        assert not s.rpc("auth", op="invite_redeem", token=invitation_token, **payload)["ok"]
    assert s.rpc("auth", op="invite_redeem", token=invitation_token, localpart="access-alice", password=PASSWORD)["code"] == "user_exists"
    with sqlite3.connect(dbpath) as db:
        assert db.execute("SELECT uses,digest FROM invitations WHERE id=?", (invitation["id"],)).fetchone() == (0, hashlib.sha256(invitation_token.encode()).digest())
        db.execute("CREATE TRIGGER fail_invitation_use BEFORE UPDATE OF uses ON invitations BEGIN SELECT RAISE(ABORT,'test consume failure'); END")
    # The auth RPC reports the transaction error, but the newly inserted user
    # must be rolled back together with the failed use counter update.
    status, _, result = s.http("auth", "POST", "/rpc", dict(op="invite_redeem", token=invitation_token, localpart="atomic-failure", password=PASSWORD),
                               {"Authorization": "Bearer " + s.token})
    assert status != 200 or not result["ok"], (status, result)
    with sqlite3.connect(dbpath) as db:
        assert db.execute("SELECT 1 FROM users WHERE username='atomic-failure@localhost'").fetchone() is None
        assert db.execute("SELECT uses FROM invitations WHERE id=?", (invitation["id"],)).fetchone() == (0,)
        db.execute("DROP TRIGGER fail_invitation_use")
    assert s.rpc("auth", op="invite_redeem", token=invitation_token, localpart="invited", password=PASSWORD) == {"ok": True, "username": "invited@localhost", "admin": False}
    assert s.rpc("auth", op="verify", username="invited@localhost", password=PASSWORD)["admin"] is False
    print("PASS fixed domain, password policy, nonadmin accounts, address uniqueness and transactional consume rollback", flush=True)

    one_token, one = invite(max_uses=1)
    with ThreadPoolExecutor(max_workers=4) as workers:
        responses = list(workers.map(lambda n: s.rpc("auth", op="invite_redeem", token=one_token, localpart=f"racer-{n}", password=PASSWORD), range(4)))
    assert sum(reply["ok"] for reply in responses) == 1, responses
    assert all(reply["ok"] or reply["code"] == "invitation_unavailable" for reply in responses)
    with sqlite3.connect(dbpath) as db:
        assert db.execute("SELECT uses FROM invitations WHERE id=?", (one["id"],)).fetchone() == (1,)
        assert db.execute("SELECT COUNT(*) FROM users WHERE username LIKE 'racer-%'").fetchone() == (1,)
    fixed_token, fixed = invite(localpart="Fixed-Mailbox")
    assert s.rpc("auth", op="invite_inspect", token=fixed_token)["localpart"] == "fixed-mailbox"
    assert s.rpc("auth", op="invite_redeem", token=fixed_token, localpart="other", password=PASSWORD)["code"] == "invalid_invitation"
    assert s.rpc("auth", op="invite_redeem", token=fixed_token, password=PASSWORD)["username"] == "fixed-mailbox@localhost"
    revoked_token, revoked = invite()
    assert s.rpc("auth", op="invite_revoke", username=admin, id=revoked["id"])["ok"]
    expired_token, expired = invite()
    with sqlite3.connect(dbpath) as db:
        db.execute("UPDATE invitations SET expires_at=unixepoch() WHERE id=?", (expired["id"],))
    s.stop("auth"); s.start("auth")
    for secret in (one_token, fixed_token, revoked_token, expired_token):
        for op in ("invite_inspect", "invite_redeem"):
            assert s.rpc("auth", op=op, token=secret, localpart="should-not-create", password=PASSWORD)["code"] == "invitation_unavailable"
    listed = s.rpc("auth", op="invite_list", username=admin)
    assert "token" not in listed and "digest" not in json.dumps(listed)
    logs = "".join(path.read_text(errors="replace") for path in s.directory.rglob("*.log"))
    for secret in (token, mailbox_token, invitation_token, one_token, fixed_token, revoked_token, expired_token, PASSWORD):
        assert secret not in logs
        for path in (dbpath, Path(str(dbpath) + "-wal")):
            if path.exists(): assert secret.encode() not in path.read_bytes()
    print("PASS concurrent use cap, fixed localpart, expiration/revocation across restart and digest-only persistence", flush=True)


def migration(binaries, directory):
    directory.mkdir(parents=True)
    s = Suite(binaries, directory)
    data = directory / "data"; data.mkdir()
    username, token, identifier = "legacy-access@localhost", "pp_" + secrets.token_hex(32), secrets.token_hex(16)
    salt = secrets.token_bytes(16); digest = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), salt, 600000)
    with sqlite3.connect(data / "auth.sqlite3") as db:
        db.executescript("CREATE TABLE users (username TEXT PRIMARY KEY,salt BLOB NOT NULL,password_hash BLOB NOT NULL,iterations INTEGER NOT NULL,admin INTEGER NOT NULL,created_at INTEGER NOT NULL);"
                        "CREATE TABLE api_keys (id TEXT PRIMARY KEY,name TEXT NOT NULL,prefix TEXT NOT NULL,owner TEXT NOT NULL,digest BLOB NOT NULL UNIQUE,created_at INTEGER NOT NULL,expires_at INTEGER,last_used_at INTEGER,revoked_at INTEGER);PRAGMA user_version=3;")
        db.execute("INSERT INTO users VALUES(?,?,?,?,1,1)", (username, salt, digest, 600000))
        db.execute("INSERT INTO api_keys(id,name,prefix,owner,digest,created_at) VALUES(?,?,?,?,?,1)", (identifier,"Existing key",token[:11],username,hashlib.sha256(token.encode()).digest()))
    try:
        s.start("auth")
        verified = s.rpc("auth", op="api_key_verify", key=token)
        assert verified["valid"] and verified["audience"] == "admin" and set(verified["permissions"]) == set(ADMIN_PERMISSIONS)
        with sqlite3.connect(data / "auth.sqlite3") as db:
            assert db.execute("PRAGMA user_version").fetchone() == (4,)
            assert db.execute("SELECT digest FROM api_keys WHERE id=?", (identifier,)).fetchone() == (hashlib.sha256(token.encode()).digest(),)
            assert db.execute("SELECT salt,password_hash FROM users WHERE username=?", (username,)).fetchone() == (salt,digest)
        s.stop("auth"); s.start("auth")
        assert set(s.rpc("auth", op="api_key_verify", key=token)["permissions"]) == set(ADMIN_PERMISSIONS)
        print("PASS legacy API keys retain complete admin grants without secret/password rotation and migration is idempotent", flush=True)
    finally: s.close()


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--bin-dir", type=Path, required=True); args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("access-auth-" + secrets.token_hex(6)); directory.mkdir(parents=True)
    s = Suite(args.bin_dir.resolve(), directory)
    try: run(s)
    finally: s.close()
    migration(args.bin_dir.resolve(), directory / "legacy")


if __name__ == "__main__": main()
