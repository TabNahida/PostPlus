"""Native HTTP permissions, owner-bound code API, invitation onboarding and auth migration."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import secrets
import sqlite3
from urllib.parse import urlsplit

from integration import PASSWORD, ROOT, Suite
from password_policy_integration import login
from api_keys_integration import bearer
from access_auth_integration import run as auth_run, migration


def run(s):
    for service in ("auth", "storage", "web", "admin"): s.start(service)
    admin, alice, bob = "http-admin@localhost", "http-alice@localhost", "http-bob@localhost"
    for user in (admin, alice, bob):
        assert s.rpc("auth", op="create", username=user, password=PASSWORD, admin=user == admin)["ok"]
    administrator, a, b = login(s, "admin", admin), login(s, "web", alice), login(s, "web", bob)
    keyroute, mailboxroute, invroute = "/api/admin/api-keys", "/api/api-keys", "/api/admin/invitations"

    def key(service, route, session, permissions):
        status, _, result = s.http(service, "POST", route, dict(name="HTTP limited access", permissions=permissions), session)
        assert status == 201 and result["ok"], (status, result)
        return result["key"], result["api_key"]

    admin_key, metadata = key("admin", keyroute, administrator, ["users:read"])
    credential = bearer(admin_key)
    assert s.http("admin", "GET", "/api/admin/users", headers=credential)[0] == 200
    for method, route, body in (("POST", "/api/admin/users", dict(username="not-created@localhost", password=PASSWORD)),
                              ("GET", "/api/admin/messages?username=" + alice, None), ("GET", "/api/admin/stats", None),
                              ("POST", "/api/admin/password", dict(username=alice, password=PASSWORD)),
                              ("GET", "/api/admin/config", None), ("GET", invroute, None)):
        assert s.http("admin", method, route, body, credential)[0] == 403, route
    assert not s.rpc("auth", op="exists", username="not-created@localhost")["exists"]
    for service, route in (("admin", keyroute), ("web", mailboxroute)):
        browser = administrator if service == "admin" else a
        assert s.http(service, "GET", route, headers={"Cookie": browser["Cookie"]})[0] == 403
        for supplied in (credential, {**browser, **credential}):
            assert s.http(service, "GET", route, headers=supplied)[0] == 403
    assert s.http("admin", "POST", keyroute, {"name": "Explicit grants required"}, administrator)[0] == 400
    idroute = keyroute + "/" + metadata["id"]
    assert s.http("admin", "PATCH", idroute, {"permissions": ["stats:read"]}, credential)[0] == 403
    assert s.http("admin", "PATCH", idroute, {"permissions": ["stats:read"]}, {"Cookie": administrator["Cookie"]})[0] == 403
    with sqlite3.connect(s.directory / "data/auth.sqlite3") as db:
        digest = db.execute("SELECT digest FROM api_keys WHERE id=?", (metadata["id"],)).fetchone()[0]
    status, _, result = s.http("admin", "PATCH", idroute, {"permissions": ["stats:read"]}, administrator)
    assert status == 200 and "key" not in result and result["api_key"]["permissions"] == ["stats:read"]
    assert s.http("admin", "GET", "/api/admin/users", headers=credential)[0] == 403
    assert s.http("admin", "GET", "/api/admin/stats", headers=credential)[0] == 200
    with sqlite3.connect(s.directory / "data/auth.sqlite3") as db:
        assert db.execute("SELECT digest FROM api_keys WHERE id=?", (metadata["id"],)).fetchone()[0] == digest == hashlib.sha256(admin_key.encode()).digest()
    print("PASS HTTP least privilege, cookie/CSRF-only management and immediate permission editing without key rotation", flush=True)

    alice_key, alice_meta = key("web", mailboxroute, a, ["codes:read"])
    bob_key, bob_meta = key("web", mailboxroute, b, ["codes:read"])
    for user, code in ((alice,"123456"),(bob,"987654")):
        raw = f"From: service@example.test\r\nTo: {user}\r\nSubject: Verification code {code}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYour verification code is {code}.\r\n"
        assert s.rpc("storage", op="deliver", username=user, raw=raw, delivery_id=secrets.token_hex(16))["ok"]
    for token, expected in ((alice_key,"123456"),(bob_key,"987654")):
        status, _, code = s.http("web", "GET", "/api/verification-code", headers=bearer(token))
        assert status == 200 and code["found"] and code["code"] == expected, (status,code)
        assert "raw" not in code and "body" not in code
        assert s.http("web", "GET", "/api/messages", headers=bearer(token))[0] == 403
        assert s.http("admin", "GET", "/api/admin/users", headers=bearer(token))[0] == 403
    assert s.http("web", "GET", "/api/verification-code?username=" + bob, headers=bearer(alice_key))[0] == 400
    assert s.http("web", "GET", "/api/verification-code", headers=credential)[0] == 403
    assert s.http("web", "PATCH", mailboxroute + "/" + alice_meta["id"], {"permissions": ["mailbox:read"]}, b)[0] == 404
    assert s.http("web", "DELETE", mailboxroute + "/" + alice_meta["id"], headers=b)[0] == 404
    assert s.http("web", "PATCH", mailboxroute + "/" + alice_meta["id"], {"permissions": ["mailbox:read"]}, a)[0] == 200
    assert s.http("web", "GET", "/api/verification-code", headers=bearer(alice_key))[0] == 403
    status, _, messages = s.http("web", "GET", "/api/messages", headers=bearer(alice_key))
    assert status == 200 and len(messages["messages"]) == 1
    bob_id = s.rpc("storage", op="list", username=bob)["messages"][0]["id"]
    assert s.http("web", "GET", "/api/messages/" + bob_id, headers=bearer(alice_key))[0] == 404
    assert s.http("web", "DELETE", mailboxroute + "/" + bob_meta["id"], headers=b)[0] == 200
    assert s.http("web", "GET", "/api/verification-code", headers=bearer(bob_key))[0] == 401
    print("PASS mailbox code-only keys, account isolation, audience separation and immediate permission/revocation enforcement", flush=True)

    invite_key, _ = key("admin", keyroute, administrator, ["invites:read", "invites:write"])
    def invitation(**options):
        status, _, result = s.http("admin", "POST", invroute, dict(name="HTTP registration", **options), bearer(invite_key))
        assert status == 201 and result["ok"], (status,result)
        assert "token" not in result
        token = urlsplit(result["registration_url"]).fragment
        assert token.startswith("pp_inv_") and len(token) == 71
        assert urlsplit(result["registration_url"]).path == "/register"
        return token, result["invitation"]
    assert s.http("web", "GET", "/register")[0] == 200
    token, invitation_meta = invitation(max_uses=1)
    public = "/api/public/invitations/"
    assert s.http("admin", "POST", public+"inspect", {"token":token})[0] == 404
    status, _, inspected = s.http("web", "POST", public+"inspect", {"token":token})
    assert status == 200 and inspected["domain"] == "localhost" and "policy" in inspected
    assert s.http("web", "POST", public+"redeem", dict(token=token,localpart="weak",password="x"))[0] == 400
    assert s.http("web", "POST", public+"redeem", dict(token=token,localpart="foreign@example.net",password=PASSWORD))[0] == 400
    assert s.http("web", "POST", public+"redeem", dict(token=token,localpart="http-alice",password=PASSWORD))[0] == 409
    with sqlite3.connect(s.directory / "data/auth.sqlite3") as db:
        assert db.execute("SELECT uses FROM invitations WHERE id=?", (invitation_meta["id"],)).fetchone() == (0,)
    with ThreadPoolExecutor(max_workers=4) as workers:
        replies = list(workers.map(lambda n: s.http("web", "POST", public+"redeem", dict(token=token,localpart=f"http-invited-{n}",password=PASSWORD)), range(4)))
    successes = [reply for reply in replies if reply[0] == 201]
    assert len(successes) == 1 and all(reply[0] in (201,410) for reply in replies), replies
    winner = successes[0][2]["username"]
    assert successes[0][2]["admin"] is False
    assert login(s,"web",winner)
    assert s.http("admin", "POST", "/api/login", dict(username=winner,password=PASSWORD))[0] == 403
    assert s.http("web", "POST", public+"inspect", {"token":token})[0] == 410
    revoked_token, revoked = invitation()
    assert s.http("admin", "DELETE", invroute+"/"+revoked["id"], headers=bearer(invite_key))[0] == 200
    assert s.http("web", "POST", public+"inspect", {"token":revoked_token})[0] == 410
    listed = s.http("admin", "GET", invroute, headers=bearer(invite_key))[2]
    assert "registration_url" not in str(listed) and token not in str(listed) and revoked_token not in str(listed)
    logs="".join(path.read_text(errors="replace") for path in s.directory.rglob("*.log"))
    for secret in (admin_key,alice_key,bob_key,invite_key,token,revoked_token,PASSWORD): assert secret not in logs
    print("PASS scoped invitation management, fragment-only registration links, failed attempts preserve uses and one concurrent ordinary-account registration wins", flush=True)


def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--bin-dir",type=Path,required=True); args=parser.parse_args()
    directory=ROOT/"build/test-runs"/("access-invites-"+secrets.token_hex(6)); directory.mkdir(parents=True)
    for name, operation in (("http",run),("auth",auth_run)):
        scenario=directory/name; scenario.mkdir(); s=Suite(args.bin_dir.resolve(),scenario)
        try: operation(s)
        finally: s.close()
    migration(args.bin_dir.resolve(),directory/"legacy")


if __name__=="__main__": main()
