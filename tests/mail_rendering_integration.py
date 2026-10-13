#!/usr/bin/env python3
"""Real-service Unicode, HTML, CID and forwarded-message display regressions.

Fixtures enter through SMTP. Every connection is loopback;
the original MIME bytes are checked independently through storage and IMAP.
"""
import argparse
import base64
import imaplib
from pathlib import Path
import quopri
import secrets
import smtplib
from urllib.parse import urlencode

from integration import PASSWORD, ROOT, Suite


USER = "reader@localhost"
ADMIN = "admin@localhost"
DATE = "Tue, 13 Oct 2026 10:20:30 +0000"
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jHh8AAAAASUVORK5CYII="
)


def base64_body(value):
    encoded = base64.b64encode(value)
    return b"\r\n".join(encoded[offset:offset + 76] for offset in range(0, len(encoded), 76)) + b"\r\n"


def encoded_word(text, charset="utf-8", encoding="B"):
    value = text.encode(charset)
    if encoding == "B":
        payload = base64.b64encode(value).decode("ascii")
    else:
        payload = quopri.encodestring(value, quotetabs=True).decode("ascii").replace(" ", "_")
    return f"=?{charset}?{encoding}?{payload}?="


def headers(subject, sender="source@example.test", recipient=USER):
    return (f"From: {sender}\r\nTo: {recipient}\r\nSubject: {subject}\r\n"
            f"Date: {DATE}\r\nMIME-Version: 1.0\r\n").encode("ascii")


def text_part(text, subtype="plain", charset="utf-8", cte="quoted-printable", disposition=""):
    value = text.encode(charset)
    if cte == "base64":
        body = base64_body(value)
    elif cte == "quoted-printable":
        body = quopri.encodestring(value, quotetabs=True).replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    else:
        body = value
    if not body.endswith(b"\r\n"):
        body += b"\r\n"
    result = f'Content-Type: text/{subtype}; charset="{charset}"\r\nContent-Transfer-Encoding: {cte}\r\n'
    if disposition:
        result += f"Content-Disposition: {disposition}\r\n"
    return result.encode("ascii") + b"\r\n" + body


def multipart(subtype, boundary, parts, prefix=b"", disposition="", parameters=""):
    header = f'Content-Type: multipart/{subtype}; boundary="{boundary}"{parameters}\r\n'
    if disposition:
        header += f"Content-Disposition: {disposition}\r\n"
    result = prefix + header.encode("ascii") + b"\r\nMIME preamble must not become the display body.\r\n"
    for part in parts:
        result += b"--" + boundary.encode("ascii") + b"\r\n" + part
        if not result.endswith(b"\r\n"):
            result += b"\r\n"
    return result + b"--" + boundary.encode("ascii") + b"--\r\nMIME epilogue must not become the display body.\r\n"


def forwarded_part(raw, cte="8bit", explicit=True):
    content_type = b"Content-Type: message/rfc822\r\n" if explicit else b""
    if not explicit:
        # A multipart/digest child defaults to message/rfc822. The empty MIME
        # header block must be distinct from the embedded RFC 5322 headers.
        return b"\r\n" + raw
    value = base64_body(raw) if cte == "base64" else raw
    return (content_type + f"Content-Transfer-Encoding: {cte}\r\n".encode("ascii") +
            b'Content-Disposition: attachment; filename="forwarded.eml"\r\n\r\n' + value)


def fixtures():
    gbk_subject = encoded_word("中文", "gbk") + "\r\n " + encoded_word("标题", "gbk")
    gbk_from = encoded_word("测试发件人", "gbk") + " <source@example.test>"
    gbk_to = encoded_word("测试收件人", "gbk", "Q") + f" <{USER}>"
    yield "gbk-qp-html", headers(gbk_subject, gbk_from, gbk_to) + text_part(
        "<html><body><p>中文 HTML 正文：这是编码测试。</p></body></html>", "html", "gbk"), {
            "subject": "中文标题", "from": "测试发件人 <source@example.test>",
            "to": f"测试收件人 <{USER}>", "text": "", "html": "中文 HTML 正文：这是编码测试。"}

    yield "gb18030-base64-text", headers(encoded_word("扩展汉字标题", "gb18030", "Q")) + text_part(
        "GB18030 中文及扩展汉字：\U00020000。\r\n第二行。", charset="gb18030", cte="base64"), {
            "subject": "扩展汉字标题", "text": "GB18030 中文及扩展汉字：\U00020000。", "html": ""}

    yield "utf8-base64-html", headers(encoded_word("只有 HTML 的邮件")) + text_part(
        "<article><h1>HTML 邮件</h1><p>没有纯文本替代项。</p></article>", "html", cte="base64"), {
            "subject": "只有 HTML 的邮件", "text": "", "html": "没有纯文本替代项。"}

    meta_body = '<html><head><meta charset="gb2312"></head><body><p>由网页声明编码的中文。</p></body></html>'
    yield "html-meta-charset", headers("HTML meta charset") + (
        b"Content-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
        base64_body(meta_body.encode("gb2312"))), {
            "subject": "HTML meta charset", "text": "", "html": "由网页声明编码的中文。"}
    yield "mime-charset-precedence", headers("MIME charset wins") + text_part(
        '<html><head><meta charset="gbk"></head><body><p>MIME 编码优先。</p></body></html>', "html", "utf-8", "base64"), {
            "subject": "MIME charset wins", "text": "", "html": "MIME 编码优先。"}

    yield "alternative", multipart("alternative", "alternative-body", [
        text_part("纯文本替代正文。\r\n", cte="base64"),
        text_part("<p><strong>HTML 替代正文。</strong></p>", "html")], headers(encoded_word("两种正文"))), {
            "subject": "两种正文", "text": "纯文本替代正文。", "html": "HTML 替代正文。"}

    yield "named-text-attachment", multipart("mixed", "attachment-body", [
        text_part("TextAttachmentSentinel 中文附件内容", disposition='attachment; filename="notes.txt"'),
        text_part("<p>正确的 HTML 正文。</p>", "html")], headers("Attachment before body")), {
            "subject": "Attachment before body", "text": "", "html": "正确的 HTML 正文。",
            "absent": ["TextAttachmentSentinel"]}

    # A filename alone identifies an attached text part, even when a sender
    # omits Content-Disposition. Neither it nor an attached multipart is body.
    named = (b'Content-Type: text/plain; charset=utf-8; name="notes.txt"\r\n\r\n'
             b"NamedTextSentinel\r\n")
    attached_container = multipart("alternative", "attached-alternative", [
        text_part("AttachedMultipartSentinel"), text_part("<b>AttachedMultipartSentinel</b>", "html")],
        disposition='attachment; filename="body.mime"')
    yield "attachment-only", multipart("mixed", "attachments-only", [named, attached_container],
                                        headers("Attached text is not body")), {
            "subject": "Attached text is not body", "text": "", "html": "",
            "absent": ["NamedTextSentinel", "AttachedMultipartSentinel"]}

    inline_png = (b"Content-Type: image/png\r\nContent-ID: <pixel@postplus>\r\n"
                  b"Content-Disposition: inline\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
                  base64_body(PNG))
    inline_svg = (b"Content-Type: image/svg+xml\r\nContent-ID: <script@postplus>\r\n\r\n"
                  b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>\r\n')
    related = multipart("related", "related-body", [
        text_part('<p>内嵌图片正文。</p><img src="cid:pixel@postplus"><img src="cid:script@postplus">', "html"),
        inline_png, inline_svg], headers(encoded_word("内嵌图片")))
    yield "related-cid", related, {"subject": "内嵌图片", "text": "", "html": "cid:pixel@postplus",
                                   "image": {"cid": "pixel@postplus", "content_type": "image/png", "data": PNG}}

    yield "related-start", multipart("related", "related-root-second", [
        inline_png, b"Content-ID: <html-root@postplus>\r\n" +
        text_part('<p>显式指定的 related 正文。</p><img src="cid:pixel@postplus">', "html")],
        headers("Related start root"), parameters='; start="<html-root@postplus>"'), {
            "subject": "Related start root", "text": "", "html": "显式指定的 related 正文。",
            "image": {"cid": "pixel@postplus", "content_type": "image/png", "data": PNG}}

    original = headers(encoded_word("转发原始标题", "gbk"), gbk_from, gbk_to) + text_part(
        "<p>原始邮件中文正文。</p>", "html", "gbk", "base64")
    yield "attached-rfc822", multipart("mixed", "attached-message", [
        text_part("转发说明正文。"), forwarded_part(original)], headers(encoded_word("转发外层标题"))), {
            "subject": "转发外层标题", "text": "转发说明正文。", "html": "",
            "forwarded": [{"subject": "转发原始标题", "from": "测试发件人 <source@example.test>",
                           "to": f"测试收件人 <{USER}>", "text": "", "html": "原始邮件中文正文。"}]}

    digest_second = headers("Second digest message", "second@example.test") + text_part("第二封摘要正文。")
    yield "digest-default-rfc822", multipart("digest", "message-digest", [
        forwarded_part(original, explicit=False), forwarded_part(digest_second)], headers("Digest wrapper")), {
            "subject": "Digest wrapper", "text": "", "html": "",
            "forwarded": [{"subject": "转发原始标题", "text": "", "html": "原始邮件中文正文。"},
                          {"subject": "Second digest message", "from": "second@example.test", "text": "第二封摘要正文。", "html": ""}]}

    middle = multipart("mixed", "middle-message", [text_part("中间转发说明。"), forwarded_part(related)],
                       headers(encoded_word("中间转发标题"), "middle@example.test"))
    yield "nested-base64-rfc822", multipart("mixed", "nested-message", [
        text_part("最外层转发说明。"), forwarded_part(middle, "base64")], headers(encoded_word("多层转发标题"))), {
            "subject": "多层转发标题", "text": "最外层转发说明。", "html": "",
            "forwarded": [{"subject": "中间转发标题", "from": "middle@example.test", "text": "中间转发说明。", "html": "",
                          "forwarded": [{"subject": "内嵌图片", "text": "", "html": "内嵌图片正文。",
                                         "image": {"cid": "pixel@postplus", "content_type": "image/png", "data": PNG}}]}]}


def login(suite, service, username):
    status, headers, response = suite.http(service, "POST", "/api/login", {"username": username, "password": PASSWORD})
    assert status == 200, (service, status, response)
    return {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": response["csrf"]}


def check_view(view, expected, label):
    assert set(("subject", "from", "to", "date", "text", "html", "forwarded", "inline_images")) <= view.keys(), (label, view)
    assert view["date"] == DATE, (label, "Date lost", view)
    for field in ("subject", "from", "to"):
        if field in expected:
            assert view[field] == expected[field], (label, field, view[field], expected[field])
    for field in ("text", "html"):
        value = view[field]
        assert isinstance(value, str) and "\ufffd" not in value, (label, field, value)
        if expected[field]:
            assert expected[field] in value, (label, field, value, expected[field])
        else:
            assert not value.strip(), (label, field, "non-body content became body", value)
    for sentinel in expected.get("absent", []):
        assert sentinel not in view["text"] + view["html"], (label, "attachment leaked into body", view)
    forwards = expected.get("forwarded", [])
    assert len(view["forwarded"]) == len(forwards), (label, "wrong forwarded count", view)
    for index, (actual, wanted) in enumerate(zip(view["forwarded"], forwards)):
        check_view(actual, wanted, f"{label}/forwarded/{index}")
    image = expected.get("image")
    if image:
        assert len(view["inline_images"]) == 1, (label, view["inline_images"])
        actual = view["inline_images"][0]
        assert actual["cid"] == image["cid"] and actual["content_type"] == image["content_type"], (label, actual)
        assert base64.b64decode(actual["data"], validate=True) == image["data"], (label, "CID image bytes changed")
    else:
        assert view["inline_images"] == [], (label, "forwarded or attached images leaked into parent scope", view)


def run(suite):
    for service in ("auth", "storage", "filter", "smtp", "imap", "web", "admin", "delivery"):
        suite.start(service)
    for username in (ADMIN, USER):
        assert suite.rpc("auth", op="create", username=username, password=PASSWORD, admin=username == ADMIN)["ok"]
    administrator = login(suite, "admin", ADMIN)
    reader = login(suite, "web", USER)
    samples = list(fixtures())
    for index, (label, raw, expected) in enumerate(samples):
        assert raw.endswith(b"\r\n") and max(map(len, raw.split(b"\r\n"))) <= 998, (label, "invalid SMTP fixture framing")
        previous = {item["id"] for item in suite.rpc("storage", op="list", username=USER)["messages"]}
        with smtplib.SMTP("127.0.0.1", suite.ports["smtp"], local_hostname="rendering-fixture", timeout=10) as smtp:
            assert smtp.sendmail("source@example.test", [USER], raw) == {}
        suite.wait_mail(USER, index + 1)
        messages = suite.rpc("storage", op="list", username=USER)["messages"]
        added = [item for item in messages if item["id"] not in previous]
        assert len(added) == 1, (label, added)
        identifier, uid = added[0]["id"], str(added[0]["uid"])
        original = suite.rpc("storage", op="get", username=USER, id=identifier)
        assert original["raw"] == raw and not original["seen"], (label, "original changed before display", original)
        status, _, admin = suite.http("admin", "GET", f"/api/admin/messages/{identifier}?" + urlencode({"username": USER}), headers=administrator)
        assert status == 200, (label, status, admin)
        check_view(admin["message"], expected, label)
        after_admin = suite.rpc("storage", op="get", username=USER, id=identifier)
        assert not after_admin["seen"] and after_admin["raw"] == raw, (label, "administrator inspection changed the message")
        status, _, web = suite.http("web", "GET", "/api/messages/" + identifier, headers=reader)
        assert status == 200 and web["message"] == admin["message"], (label, "admin and Webmail display disagree", web, admin)
        after_web = suite.rpc("storage", op="get", username=USER, id=identifier)
        assert after_web["seen"] and after_web["raw"] == raw, (label, "Webmail view altered original MIME")
        with imaplib.IMAP4("127.0.0.1", suite.ports["imap"], timeout=10) as client:
            assert client.login(USER, PASSWORD)[0] == "OK"
            assert client.select("INBOX")[0] == "OK"
            status, fetched = client.uid("fetch", uid, "(UID RFC822.SIZE BODY.PEEK[])")
            assert status == "OK" and any(isinstance(item, tuple) and item[1] == raw for item in fetched), (label, "IMAP original was rewritten", fetched)
    assert suite.rpc("storage", op="queue_list", limit=100)["jobs"] == []
    print("PASS GBK/GB18030 and RFC2047 Chinese, QP/base64 HTML, alternatives, attachment exclusion, raster CID scope, recursive forwards/digest, matching admin/Webmail views, Seen policy and original SMTP/IMAP bytes", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("mail-rendering-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    finally:
        suite.close()


if __name__ == "__main__":
    main()
