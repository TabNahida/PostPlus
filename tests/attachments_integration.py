#!/usr/bin/env python3
"""Compose/draft/attachment contracts against isolated local mailboxes only."""
import argparse
import base64
from email import policy
from email.parser import BytesParser
from pathlib import Path
import secrets
from urllib.parse import urlencode

from integration import PASSWORD, ROOT, Suite


def login(s, service, username):
    status, headers, result = s.http(service, "POST", "/api/login", {"username": username, "password": PASSWORD})
    assert status == 200, result
    return {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": result["csrf"]}


def run(s):
    for name in ("auth", "storage", "filter", "web", "admin"):
        s.start(name)
    owner, target, blind, outsider, admin = [value + "@localhost" for value in ("writer", "target", "blind", "other", "admin")]
    for address in (owner, target, blind, outsider, admin):
        assert s.rpc("auth", op="create", username=address, password=PASSWORD, admin=address == admin)["ok"]
    u, o, a = login(s, "web", owner), login(s, "web", outsider), login(s, "admin", admin)
    binary = bytes(range(256)) * 6 + b"\r\n.dot\x00end"
    upload = {"filename": "../附件.bin", "content_type": "application/octet-stream", "data_base64": base64.b64encode(binary).decode()}
    payload = dict(to=[target], cc=[outsider], bcc=[blind], subject="附件 subject", text="Plain alternative", html="<p><strong>Rich alternative</strong></p>", attachments=[upload])
    status, _, draft = s.http("web", "POST", "/api/drafts", payload, u)
    assert status == 200, draft
    draft_id = draft["id"]
    raw = s.rpc("storage", op="get", username=owner, id=draft_id)["raw"]
    decoded = BytesParser(policy=policy.default).parsebytes(raw)
    assert decoded["Bcc"] == blind and decoded["Cc"] == outsider
    assert decoded.get_body(preferencelist=("plain",)).get_content().strip() == payload["text"]
    assert decoded.get_body(preferencelist=("html",)).get_content().strip() == payload["html"]
    file = list(decoded.iter_attachments())[0]
    assert file.get_filename() == "附件.bin" and file.get_payload(decode=True) == binary
    viewed = s.http("web", "GET", "/api/messages/" + draft_id, headers=u)
    assert viewed[0] == 200, viewed
    metadata = viewed[2]["message"]["attachments"]
    assert metadata == [{"index": 0, "filename": "附件.bin", "content_type": "application/octet-stream", "size": len(binary)}], metadata
    # Download is authorized like the source message and never changes Seen.
    s.rpc("storage", op="flags", username=owner, id=draft_id, seen=False)
    status, headers, content = s.http("web", "GET", f"/api/messages/{draft_id}?attachment=0", headers=u)
    assert status == 200 and content == binary, (status, content)
    assert headers["Content-Type"] == "application/octet-stream"
    assert headers["Content-Disposition"].startswith("attachment;") and "filename*=UTF-8''" in headers["Content-Disposition"]
    assert "../" not in headers["Content-Disposition"]
    assert not s.rpc("storage", op="get", username=owner, id=draft_id)["seen"]
    assert s.http("web", "GET", f"/api/messages/{draft_id}?attachment=0")[0] == 401
    assert s.http("web", "GET", f"/api/messages/{draft_id}?attachment=0", headers=o)[0] == 404
    assert s.http("web", "GET", f"/api/messages/{draft_id}?attachment=1", headers=u)[0] == 404
    assert s.http("web", "GET", f"/api/messages/{draft_id}?attachment=-1", headers=u)[0] == 400
    inspected = s.http("admin", "GET", f"/api/admin/messages/{draft_id}?" + urlencode({"username": owner, "attachment": 0}), headers=a)
    assert inspected[0] == 200 and inspected[2] == binary, inspected
    # Mailbox API keys use the same read permission for byte downloads.
    for permissions, expected in ((["mailbox:read"], 200), (["mailbox:send"], 403)):
        key = s.rpc("auth", op="api_key_create", username=owner, audience="mailbox", name="Attachment test", permissions=permissions)
        assert key["ok"], key
        assert s.http("web", "GET", f"/api/messages/{draft_id}?attachment=0", headers={"Authorization": "Bearer " + key["key"]})[0] == expected
    reference = {"message_id": draft_id, "index": 0}
    preserved = dict(payload, id=draft_id, attachments=[reference])
    assert s.http("web", "POST", "/api/drafts", preserved, u)[0] == 200
    assert list(BytesParser(policy=policy.default).parsebytes(s.rpc("storage", op="get", username=owner, id=draft_id)["raw"]).iter_attachments())[0].get_payload(decode=True) == binary
    assert s.http("web", "POST", "/api/drafts", dict(payload, attachments=[reference]), o)[0] == 404
    # Repeated draft replacement can remove and reorder referenced MIME parts.
    reordered = s.http("web", "POST", "/api/drafts", dict(payload, attachments=[upload,dict(upload,filename="second.bin")]), u)
    assert reordered[0] == 200, reordered
    reorder_id = reordered[2]["id"]
    changed = s.http("web", "POST", "/api/drafts", dict(payload,id=reorder_id,attachments=[{"message_id":reorder_id,"index":1}]), u)
    assert changed[0] == 200, changed
    assert s.http("web", "POST", "/api/drafts", dict(payload,id=reorder_id,attachments=[{"message_id":reorder_id,"index":0}]), u)[0] == 200
    assert s.http("web", "DELETE", "/api/messages/"+reorder_id, headers=u)[0] == 200
    # Replies resolve Message-ID/References only from an owned original.
    source_raw = (f"From: sender@example.test\r\nTo: {owner}\r\nMessage-ID: <source@example.test>\r\nReferences: <thread@example.test>\r\nSubject: Original\r\n\r\nOriginal body\r\n").encode()
    source = s.rpc("storage", op="deliver", username=owner, raw=source_raw, delivery_id=secrets.token_hex(12))
    assert source["ok"], source
    # Send/write scopes alone cannot read or forward existing mailbox content.
    def mailbox_key(permissions):
        key = s.rpc("auth", op="api_key_create", username=owner, audience="mailbox", name="Composition scopes", permissions=permissions)
        assert key["ok"], key
        return {"Authorization": "Bearer " + key["key"]}

    send_only = mailbox_key(["mailbox:send"])
    send_read = mailbox_key(["mailbox:send", "mailbox:read"])
    write_only = mailbox_key(["mailbox:write"])
    write_read = mailbox_key(["mailbox:write", "mailbox:read"])
    api_payload = dict(to=[target], subject="Scope regression", text="Submitted with an API key", attachments=[upload])
    assert s.http("web", "POST", "/api/send", api_payload, send_only)[0] == 202, "Upload-only send needs only mailbox:send"
    assert s.http("web", "POST", "/api/send", dict(api_payload, attachments=[reference]), send_only)[0] == 403
    assert s.http("web", "POST", "/api/send", dict(api_payload, reply_to_id=source["id"]), send_only)[0] == 403
    assert s.http("web", "POST", "/api/send", dict(api_payload, attachments=[reference], reply_to_id=source["id"]), send_read)[0] == 202
    assert s.http("web", "POST", "/api/drafts", dict(api_payload, attachments=[reference]), write_only)[0] == 403
    assert s.http("web", "POST", "/api/drafts", dict(api_payload, reply_to_id=source["id"]), write_only)[0] == 403
    for key, body in ((write_only, api_payload), (write_read, dict(api_payload, attachments=[reference], reply_to_id=source["id"]))):
        allowed = s.http("web", "POST", "/api/drafts", body, key)
        assert allowed[0] == 200, allowed
        assert s.http("web", "DELETE", "/api/messages/"+allowed[2]["id"], headers=u)[0] == 200
    outbound = dict(payload, attachments=[reference], reply_to_id=source["id"], draft_id=draft_id)
    status, _, sent = s.http("web", "POST", "/api/send", outbound, u)
    assert status == 202, sent
    sent_raw = s.rpc("storage", op="get", username=owner, id=sent["sent_id"])["raw"]
    parsed = BytesParser(policy=policy.default).parsebytes(sent_raw)
    assert parsed["Bcc"] is None and blind.encode() not in sent_raw
    assert parsed["To"] == target and parsed["Cc"] == outsider
    assert parsed["In-Reply-To"] == "<source@example.test>" and parsed["References"] == "<thread@example.test> <source@example.test>"
    assert list(parsed.iter_attachments())[0].get_payload(decode=True) == binary
    assert {job["recipient"] for job in s.rpc("storage", op="queue_list", limit=100)["jobs"]} == {target, outsider, blind}
    assert not s.rpc("storage", op="list", username=owner, folder="Drafts")["messages"]
    # Bcc-only mail is valid and never leaks the Bcc header to recipients.
    only_blind = s.http("web", "POST", "/api/send", dict(to=[], bcc=[blind], subject="Private", text="Only blind recipient"), u)
    assert only_blind[0] == 202, only_blind
    for changes in ({"attachments": [dict(upload, data_base64="!!!")]}, {"attachments": [dict(upload, content_type="text/plain\r\nInjected: yes")]}, {"attachments": [upload] * 65}, {"in_reply_to": "<x>\r\nInjected: yes"}):
        assert s.http("web", "POST", "/api/drafts", dict(payload, **changes), u)[0] == 400, changes
    too_large = dict(upload, data_base64=base64.b64encode(b"x" * 60000).decode())
    assert s.http("web", "POST", "/api/drafts", dict(payload, attachments=[too_large]), u)[0] == 413
    print("PASS exact binary attachments, Unicode names, authorized downloads, draft retention, rich MIME, Cc/Bcc privacy, reply threads and bounded uploads", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("attachments-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    finally:
        suite.close()
