#!/usr/bin/env python3
"""Owner-bound verification-code API using real auth, storage and HTTP services."""
import argparse
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path
import secrets
import time

from integration import PASSWORD, ROOT, Suite
from password_policy_integration import login


ROUTE = "/api/verification-code"


def message(body, *, subject="Account security", html=False, encoding="8bit"):
    value = EmailMessage(policy=SMTP)
    value["From"] = "Security <security@example.com>"
    value["Subject"] = subject
    value.set_content(body, subtype="html" if html else "plain", charset="utf-8", cte=encoding)
    return value.as_bytes()


def run(s):
    # Use isolated ephemeral listeners; mail is appended directly to test-owned
    # storage so this test needs no external SMTP, DNS, or certificate services.
    for service in ("auth", "storage", "web", "admin"):
        s.start(service)
    admin, alice, bob, empty = (name + "@localhost" for name in ("code-admin", "code-alice", "code-bob", "code-empty"))
    for user in (admin, alice, bob, empty):
        assert s.rpc("auth", op="create", username=user, password=PASSWORD, admin=user == admin)["ok"]
    a, b, none, administrator = (login(s, portal, user) for portal, user in
                                (("web", alice), ("web", bob), ("web", empty), ("admin", admin)))
    assert s.http("web", "GET", ROUTE)[0] == 401
    assert s.http("admin", "GET", ROUTE, headers=administrator)[0] == 404

    def check(headers, expected=None, identifier=None, folder=None):
        route = ROUTE if folder is None else ROUTE + "?folder=" + folder
        status, response_headers, result = s.http("web", "GET", route, headers=headers)
        assert status == 200 and result["ok"], (status, result)
        assert response_headers["Cache-Control"] == "no-store", response_headers
        if expected is None:
            assert result == {"ok": True, "found": False}, result
        else:
            assert result["found"] and result["code"] == expected, result
            assert result["message_id"] == identifier and result["from"] == "Security <security@example.com>", result
            assert result["expires_at"] - result["received_at"] == 900, result
            assert result["expires_at"] > int(time.time()), result
            assert set(result) == {"ok", "found", "code", "message_id", "from", "subject", "received_at", "expires_at"}, result
        return result

    def append(raw, *, username=alice, age=0, folder="INBOX", seen=False, draft=False):
        result = s.rpc("storage", op="append", username=username, folder=folder, raw=raw,
                       internal_date=int(time.time()) - age, seen=seen, draft=draft)
        assert result["ok"], result
        return result["id"]

    def clear(user=alice):
        ids = [item["id"] for item in s.rpc("storage", op="list", username=user)["messages"]]
        if ids:
            assert s.rpc("storage", op="delete", username=user, ids=ids, permanent=True)["ok"]

    check(a); check(none)
    foreign = append(message("Your verification code is 998877."), username=bob)
    append(message("Order 123456, date 2026-10-13, invoice amount 1234.56."))
    check(a); check(none); check(b, "998877", foreign)
    for query in ("username=" + bob, "message_id=" + foreign, "folder=Archive", "max_age_seconds=86400"):
        assert s.http("web", "GET", ROUTE + "?" + query, headers=a)[0] == 400, query
    assert s.http("web", "POST", ROUTE, {}, a)[0] == 404
    for query in ("folder=Sent", "folder=Drafts", "folder=Junk", "folder=", "folder=Trash&username=" + bob, "folder=INBOX&folder=Trash"):
        assert s.http("web", "GET", ROUTE + "?" + query, headers=a)[0] == 400, query
    trash_code = append(message("Verification code: 876543"), folder="Trash")
    check(a, "876543", trash_code, folder="Trash")
    check(a, folder="INBOX")
    check(b, folder="Trash")
    assert s.rpc("storage", op="verification_candidates", username=alice, folder="Trash")["messages"][0]["id"] == trash_code
    assert s.http("storage", "POST", "/rpc", {"op":"verification_candidates", "username":alice, "folder":"Sent"},
                  {"Authorization":"Bearer " + s.token})[0] == 400
    assert s.rpc("storage", op="delete", username=alice, ids=[trash_code], permanent=True)["ok"]
    check(a, folder="Trash")
    print("PASS authenticated own-account lookup, empty/ordinary mail, fixed filters and admin portal isolation", flush=True)

    clear()
    append(message("Verification code: 111111"), age=901)
    append(message("Verification code: 222222"), age=-120)
    append(message("Verification code: 333333"), folder="Archive")
    append(message("Verification code: 444444"), folder="Drafts", draft=True)
    append(message("Verification code: 555555"), draft=True)
    check(a)
    identifier = append(message("111111\nYour verification code is 001234.", subject="Your login code"), age=60)
    check(a, "001234", identifier)
    print("PASS expired/future timestamps, non-INBOX mail and drafts excluded; leading zeros preserved", flush=True)

    clear()
    older = append(message("OTP: 123456"), age=120)
    html = append(message("<script>OTP:111111</script><div style='display:none'>OTP:222222</div>"
                          "<blockquote>OTP:333333</blockquote><p>Verification code: &#48;&#48;&#53;&#54;&#55;&#56;</p>", html=True), age=60)
    # Newer noise must never displace the latest usable, visible code.
    append(message("Please review this message.\n> Verification code: 654321"))
    append(message("Verification code: 654321", subject="Fwd: Your login code"))
    append(message("Verification code: 222222\nSecurity code: 333333"))
    append(b"Subject: Verification code\r\nContent-Transfer-Encoding: base64\r\n\r\n###")
    append(b"Subject: Login code\r\nContent-Type: multipart/mixed; boundary=bad\r\n\r\n--bad\r\n\r\nOTP:999999")
    result = check(a, "005678", html)
    assert result["subject"] == "Account security" and result["message_id"] != older
    chinese = append(message("您的验证码是：006789。", subject="邮箱验证", encoding="base64"))
    assert check(a, "006789", chinese)["subject"] == "邮箱验证"
    print("PASS newest usable code skips malformed, forwarded and ambiguous MIME; visible HTML and encoded Chinese work", flush=True)

    # Retrieval is a read-only convenience and must preserve all existing flags.
    before = s.rpc("storage", op="list", username=alice)
    folders = s.rpc("storage", op="folders", username=alice)
    for _ in range(3):
        check(a, "006789", chinese)
    assert s.rpc("storage", op="list", username=alice) == before
    assert s.rpc("storage", op="folders", username=alice) == folders
    assert all(not item["seen"] for item in before["messages"])
    assert s.rpc("storage", op="flags", username=alice, id=chinese, seen=True, flagged=True, answered=True)["ok"]
    before = s.rpc("storage", op="list", username=alice)
    check(a, "006789", chinese)
    assert s.rpc("storage", op="list", username=alice) == before
    print("PASS repeated code lookup preserves unread counts and Seen/Answered/Flagged state", flush=True)

    # Bearer integrations are independently scoped and cannot select an account.
    status, _, issued = s.http("web", "POST", "/api/api-keys", {"name": "Code reader", "permissions": ["codes:read"]}, a)
    assert status == 201 and issued["ok"], (status, issued)
    key, key_id = issued["key"], issued["api_key"]["id"]
    bearer = {"Authorization": "Bearer " + key}
    check(bearer, "006789", chinese)
    trash_code = append(message("Verification code: 987654"), folder="Trash")
    check(bearer, "987654", trash_code, folder="Trash")
    check(bearer, "006789", chinese, folder="INBOX")
    assert s.rpc("storage", op="delete", username=alice, ids=[trash_code], permanent=True)["ok"]
    before = s.rpc("storage", op="list", username=alice)
    for route in ("/api/messages", "/api/folders", "/api/session", "/api/api-keys"):
        assert s.http("web", "GET", route, headers=bearer)[0] == 403, route
    assert s.http("admin", "GET", ROUTE, headers=bearer)[0] == 404
    assert s.http("web", "GET", ROUTE + "?username=" + bob, headers=bearer)[0] == 400
    status, _, edited = s.http("web", "PATCH", "/api/api-keys/" + key_id, {"permissions": ["mailbox:read"]}, a)
    assert status == 200 and edited["ok"], (status, edited)
    assert s.http("web", "GET", ROUTE, headers=bearer)[0] == 403
    status, _, edited = s.http("web", "PATCH", "/api/api-keys/" + key_id, {"permissions": ["codes:read"]}, a)
    assert status == 200 and edited["ok"]
    assert s.http("web", "DELETE", "/api/api-keys/" + key_id, headers=a)[0] == 200
    assert s.http("web", "GET", ROUTE, headers=bearer)[0] == 401
    assert s.rpc("storage", op="list", username=alice) == before
    print("PASS mailbox Bearer codes:read scope, immediate permission edits, revocation and no message mutation", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("verification-code-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    finally:
        suite.close()


if __name__ == "__main__":
    main()
