"""Native HTTP permissions, owner-bound code API, invitation onboarding and auth migration."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import imaplib
import poplib
import smtplib
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
                              ("GET", "/api/admin/config", None), ("GET", "/api/admin/dns", None),
                              ("POST", "/api/admin/dns/check", {}), ("GET", invroute, None)):
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

    diagnostics_key, _ = key("admin", keyroute, administrator, ["config:read"])
    for method, route, body in (("GET", "/api/admin/dns", None), ("POST", "/api/admin/dns/check", {})):
        status, _, result = s.http("admin", method, route, body, bearer(diagnostics_key))
        assert status == 400 and result["code"] == "invalid_dns_input", (status, result)
    assert s.http("admin", "POST", "/api/admin/dns/check", {}, {"Cookie": administrator["Cookie"]})[0] == 403
    # GET prepares every recommendation without a DNS query or configuration write.
    before = s.path.read_bytes()
    saved = json.loads(before); saved["domain"] = "example.com"; saved["mail_hostname"] = "mail.example.com"
    s.path.write_text(json.dumps(saved), encoding="utf-8")
    try:
        snapshot = s.path.read_bytes()
        status, _, result = s.http("admin", "GET", "/api/admin/dns", headers=bearer(diagnostics_key))
        assert status == 200 and result["domain"] == "example.com" and result["hostname"] == "mail.example.com", (status, result)
        assert {"a", "aaaa", "mx", "spf", "dkim", "dmarc", "ptr"} <= {record["id"] for record in result["records"]}
        assert s.path.read_bytes() == snapshot, "DNS recommendations must never change server configuration"
        status, _, result = s.http("admin", "POST", "/api/admin/dns/check", {"hostname": "elsewhere.example.org"}, bearer(diagnostics_key))
        assert status == 400 and result["code"] == "invalid_dns_input", (status, result)
    finally:
        s.path.write_bytes(before)
    assert s.http("admin", "GET", "/admin-dns.js")[0] == 200
    print("PASS DNS config:read permission, POST CSRF, saved-only recommendations, no writes and caller-host rejection", flush=True)

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


def deletion_run(s):
    for service in ("auth", "storage", "web", "admin", "imap", "pop3", "smtp"): s.start(service)
    admin, victim, other = "delete-root@localhost", "delete-user@localhost", "delete-other@localhost"
    for username in (admin, victim, other):
        assert s.rpc("auth", op="create", username=username, password=PASSWORD, admin=username != other)["ok"]
    browser, session = login(s, "admin", admin), login(s, "web", victim)
    key = s.rpc("auth", op="api_key_create", username=victim, name="To revoke", audience="mailbox", permissions=["mailbox:read"])["key"]
    invitation = s.rpc("auth", op="invite_create", username=victim, name="To revoke")["token"]
    read_key = s.rpc("auth", op="api_key_create", username=admin, name="Read only", permissions=["users:read"])["key"]
    route = "/api/admin/users"
    body = dict(username=victim, confirm_username=victim)
    assert s.http("admin", "DELETE", route, body)[0] == 401
    assert s.http("admin", "DELETE", route, body, {"Cookie":browser["Cookie"]})[0] == 403
    assert s.http("admin", "DELETE", route, body, bearer(read_key))[0] == 403
    assert s.http("web", "DELETE", route, body, session)[0] == 404
    assert s.http("admin", "DELETE", route, dict(username=victim, confirm_username=other), browser)[0] == 400
    assert s.http("admin", "DELETE", route, dict(username=admin, confirm_username=admin), browser)[2]["code"] == "account_delete_self"
    assert s.rpc("auth", op="user_delete", username=victim, actor=other)["code"] == "administrator_required"
    raw = b"From: sender@localhost\r\nTo: delete-user@localhost\r\nSubject: Delete test\r\n\r\nPrivate mail\r\n"
    original = s.rpc("storage", op="deliver", username=victim, raw=raw, delivery_id="d"*32)["id"]
    s.rpc("storage", op="quota_set", username=victim, max_messages=5)
    s.rpc("storage", op="forwarding_create", pattern="delete-*", destination=victim)
    s.rpc("storage", op="enqueue", sender=admin, recipients=[victim], raw=raw)
    s.rpc("storage", op="enqueue", sender=admin, recipients=["delete-alias@localhost"], raw=raw,
          recipient_routes={"delete-alias@localhost":{"exists":True,"destination":victim,"rule":{"id":1,"pattern":"delete-*"}}})
    s.rpc("storage", op="enqueue", sender=victim, recipients=["outside@example.net"], raw=raw, sent_username=victim)
    queue = s.rpc("storage", op="queue_list", limit=100)["jobs"]
    ids = [item["id"] for item in queue if item["recipient"] == victim]
    imap = imaplib.IMAP4("127.0.0.1",s.ports["imap"]); imap.login(victim,PASSWORD); imap.select("INBOX")
    pop = poplib.POP3("127.0.0.1",s.ports["pop3"],timeout=5); pop.user(victim); pop.pass_(PASSWORD)
    smtp = smtplib.SMTP("127.0.0.1",s.ports["smtp"],local_hostname="localhost",timeout=5); smtp.login(victim,PASSWORD)
    status, _, deleted = s.http("admin", "DELETE", route, body, browser)
    assert status == 200 and deleted["ok"], (status,deleted)
    assert not s.rpc("auth", op="exists", username=victim)["exists"]
    assert s.http("web", "GET", "/api/messages", headers=session)[0] == 401
    assert s.http("web", "GET", "/api/messages", headers=bearer(key))[0] == 401
    assert s.rpc("auth", op="invite_inspect", token=invitation)["code"] == "invitation_unavailable"
    assert s.rpc("storage", op="forwarding_list")["rules"] == []
    assert s.rpc("storage", op="queue_list", limit=100)["jobs"] == []
    with sqlite3.connect(s.directory/"data/storage.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM messages WHERE username=?",(victim,)).fetchone() == (0,)
        assert db.execute("SELECT COUNT(*) FROM mailboxes WHERE username=?",(victim,)).fetchone() == (0,)
        assert db.execute("SELECT COUNT(*) FROM message_flags WHERE id=?",(original,)).fetchone() == (0,)
    # Reuse never exposes old mail or permits old protocol sessions to continue.
    assert s.rpc("auth", op="create", username=victim, password=PASSWORD)["ok"]
    assert s.rpc("storage", op="list", username=victim)["messages"] == []
    for identifier in ids:
        assert s.rpc("storage", op="deliver", username=victim, raw=raw, delivery_id=identifier)["duplicate"]
    assert s.rpc("storage", op="list", username=victim)["messages"] == []
    try: imap.noop(); raise AssertionError("Old IMAP session survived deletion/recreation")
    except imaplib.IMAP4.abort: pass
    finally: imap.shutdown()
    try: pop.stat(); raise AssertionError("Old POP3 session survived deletion/recreation")
    except poplib.error_proto: pass
    finally: pop.close()
    assert smtp.noop()[0] == 421; smtp.close()
    # Auth commits disabling before storage cleanup; failures remain visible and
    # retryable, and address reuse is blocked until all cleanup has succeeded.
    pending = "delete-pending@localhost"
    assert s.rpc("auth", op="create", username=pending, password=PASSWORD)["ok"]
    s.rpc("storage", op="deliver", username=pending, raw=raw, delivery_id="e"*32)
    s.stop("storage")
    payload = dict(username=pending, confirm_username=pending)
    status, _, failure = s.http("admin", "DELETE", route, payload, browser)
    assert status == 503 and failure["code"] == "account_cleanup_pending", (status,failure)
    listed = s.http("admin", "GET", route, headers=browser)[2]["users"]
    assert next(item for item in listed if item["username"] == pending)["deletion_pending"]
    assert s.rpc("auth", op="create", username=pending, password=PASSWORD)["code"] == "account_cleanup_pending"
    s.stop("auth"); s.start("auth"); s.start("storage")
    assert s.http("admin", "DELETE", route, payload, browser)[0] == 200
    assert s.rpc("auth", op="create", username=pending, password=PASSWORD)["ok"]
    assert s.rpc("storage", op="list", username=pending)["messages"] == []
    print("PASS confirmed account deletion, self/CSRF/permission protection, mail/queue/rule purge, credential revocation, clean address reuse and durable retry after storage failure",flush=True)


def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--bin-dir",type=Path,required=True); args=parser.parse_args()
    directory=ROOT/"build/test-runs"/("access-invites-"+secrets.token_hex(6)); directory.mkdir(parents=True)
    for name, operation in (("http",run),("auth",auth_run),("account-deletion",deletion_run)):
        scenario=directory/name; scenario.mkdir(); s=Suite(args.bin_dir.resolve(),scenario)
        try: operation(s)
        finally: s.close()
    migration(args.bin_dir.resolve(),directory/"legacy")


if __name__=="__main__": main()
