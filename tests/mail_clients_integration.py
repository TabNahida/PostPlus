#!/usr/bin/env python3
"""Real standard-library SMTP/IMAP/POP clients on all encrypted listener modes."""
import argparse
import base64
from contextlib import closing
from email.message import EmailMessage
from email.policy import SMTP
import http.client
import imaplib
import os
from pathlib import Path
import poplib
import secrets
import smtplib
import socket
import ssl
import time
from urllib.parse import quote
from xml.etree import ElementTree

from integration import PASSWORD, ROOT, Suite


def context():
    value = ssl.create_default_context(cafile=str(ROOT / "tests/fixtures/localhost-test-only.crt"))
    value.minimum_version = ssl.TLSVersion.TLSv1_2
    return value


def wait_tls(s, name):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("localhost", s.ports[name]), timeout=2) as raw:
                with context().wrap_socket(raw, server_hostname="localhost"):
                    return
        except (OSError, ssl.SSLError):
            time.sleep(0.05)
    raise AssertionError(name + " did not become a TLS listener")


def literal(data):
    values = [item[1] for item in data if isinstance(item, tuple)]
    assert len(values) == 1, data
    return values[0]


def discovery_request(s, method, path, body=None, encrypted=True):
    connection = (http.client.HTTPSConnection("localhost", s.ports["web"], context=context(), timeout=10)
                  if encrypted else http.client.HTTPConnection("localhost", s.ports["web"], timeout=10))
    try:
        connection.request(method, path, body=body, headers={"Content-Type": "application/xml"} if body else {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def verify_discovery(s, username):
    for path in ("/mail/config-v1.1.xml", "/.well-known/autoconfig/mail/config-v1.1.xml"):
        status, headers, body = discovery_request(s, "GET", path + "?emailaddress=" + quote(username))
        assert status == 200 and headers["Content-Type"].startswith("application/xml")
        assert headers["Cache-Control"] == "no-store"
        configuration = ElementTree.fromstring(body)
        provider = configuration.find("emailProvider")
        assert configuration.tag == "clientConfig" and provider.findtext("domain") == "localhost"
        incoming = {item.attrib["type"]: item for item in provider.findall("incomingServer")}
        for protocol, alias in (("imap", "imaps"), ("pop3", "pop3s")):
            assert incoming[protocol].findtext("hostname") == "localhost"
            assert incoming[protocol].findtext("port") == str(s.ports[alias])
            assert incoming[protocol].findtext("socketType") == "SSL"
            assert incoming[protocol].findtext("username") == username
        outgoing = provider.find("outgoingServer")
        assert outgoing.attrib["type"] == "smtp" and outgoing.findtext("port") == str(s.ports["submission"])
        assert outgoing.findtext("socketType") == "STARTTLS" and outgoing.findtext("username") == username
    xml = ('<?xml version="1.0"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">'
           '<Request><EMailAddress>' + username + '</EMailAddress><AcceptableResponseSchema>'
           'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a'
           '</AcceptableResponseSchema></Request></Autodiscover>')
    status, _, body = discovery_request(s, "POST", "/autodiscover/autodiscover.xml", xml)
    assert status == 200, (status, body)
    configuration = ElementTree.fromstring(body)
    protocols = {item.findtext("{*}Type"): item for item in configuration.findall(".//{*}Protocol")}
    for protocol, alias, security in (("IMAP", "imaps", "SSL"), ("POP3", "pop3s", "SSL"), ("SMTP", "submission", "TLS")):
        assert protocols[protocol].findtext("{*}Server") == "localhost"
        assert protocols[protocol].findtext("{*}Port") == str(s.ports[alias])
        assert protocols[protocol].findtext("{*}Encryption") == security
        assert protocols[protocol].findtext("{*}LoginName") == username
    assert discovery_request(s, "GET", "/mail/config-v1.1.xml?emailaddress=other%40example.com")[0] == 404
    assert discovery_request(s, "POST", "/autodiscover/autodiscover.xml",
                             '<!DOCTYPE test [<!ENTITY x SYSTEM "file:///etc/passwd">]><EMailAddress>&x;</EMailAddress>')[0] == 400
    print("PASS HTTPS Thunderbird/Outlook discovery returns the active TLS ports and full-email username; foreign domains and XML entities rejected", flush=True)


def run(s):
    # Certificates alone enable TLS client listeners; the explicit ports are
    # ephemeral to avoid requiring root or colliding with real mail servers.
    s.config.update(tls_certificate=str(ROOT / "tests/fixtures/localhost-test-only.crt"),
                    tls_private_key=str(ROOT / "tests/fixtures/localhost-test-only.key"),
                    allow_insecure_auth=False, max_connections=16, max_mailbox_messages=4)
    s.save()
    for service in ("auth", "storage", "filter", "transfer", "delivery", "smtp", "pop3", "imap", "web"):
        s.start(service)
    for alias in ("smtps", "pop3s", "imaps"):
        wait_tls(s, alias)
    alice, bob = "client-alice@localhost", "client-bob@localhost"
    for user in (alice, bob):
        assert s.rpc("auth", op="create", username=user, password=PASSWORD)["ok"]
    verify_discovery(s, bob)
    messages = []
    for number in range(2):
        message = EmailMessage(policy=SMTP)
        message["From"] = '"Client, Alice" <' + alice + ">"
        message["To"] = bob
        message["Subject"] = "第三方客户端中文邮件 " + str(number + 1)
        message["Message-ID"] = f"<mail-client-{number}@localhost>"
        message.set_content("测试正文，保留中文和换行。\n", charset="utf-8", cte="8bit")
        message.add_alternative("<p>中文 HTML 正文</p>\n", subtype="html", charset="utf-8")
        messages.append(message.as_bytes())

    with smtplib.SMTP("localhost", s.ports["submission"], timeout=10) as client:
        assert client.ehlo()[0] == 250
        assert client.has_extn("starttls") and not client.has_extn("auth")
        assert client.mail(alice)[0] == 530
        assert client.docmd("AUTH", "PLAIN " + base64.b64encode(f"\0{alice}\0{PASSWORD}".encode()).decode())[0] == 538
        client.starttls(context=context())
        client.ehlo()
        assert client.has_extn("auth") and client.has_extn("8bitmime") and not client.has_extn("starttls")
        assert client.mail(alice)[0] == 530
        client.login(alice, PASSWORD)
        assert client.sendmail(alice, [bob], messages[0], mail_options=["BODY=8BITMIME"]) == {}
        assert client.mail(alice)[0] == 250 and client.rcpt("external@example.com")[0] == 550
        client.rset()
    with smtplib.SMTP_SSL("localhost", s.ports["smtps"], context=context(), timeout=10) as client:
        client.ehlo()
        assert client.has_extn("auth") and not client.has_extn("starttls")
        assert client.mail(alice)[0] == 530
        client.user, client.password = alice, PASSWORD
        assert client.auth("LOGIN", client.auth_login, initial_response_ok=False)[0] == 235
        assert client.sendmail(alice, [bob], messages[1], mail_options=["BODY=8BITMIME"]) == {}
    inbox = s.wait_mail(bob, 2)
    assert len(s.rpc("storage", op="list", username=alice, folder="Sent")["messages"]) == 2
    stored = {str(item["uid"]): s.rpc("storage", op="get", username=bob, id=item["id"])["raw"] for item in inbox["messages"]}
    print("PASS SMTP 587 STARTTLS and 465 implicit TLS require encryption/authentication and deliver UTF-8 multipart mail", flush=True)

    with imaplib.IMAP4_SSL("localhost", s.ports["imaps"], ssl_context=context(), timeout=10) as client:
        assert client.login(bob, PASSWORD)[0] == "OK"
        assert client.select("INBOX")[1] == [b"2"]
        uids = client.uid("search", None, "ALL")[1][0].decode().split()
        for uid in uids:
            status, data = client.uid("fetch", uid, "(UID ENVELOPE BODYSTRUCTURE FLAGS BODY.PEEK[])")
            assert status == "OK" and literal(data) == stored[uid]
            metadata = b" ".join(item[0] if isinstance(item, tuple) else item for item in data if item is not None)
            assert b"ENVELOPE (" in metadata and b"BODYSTRUCTURE ((" in metadata and b'"ALTERNATIVE"' in metadata
            status, data = client.uid("fetch", uid, "(BODY.PEEK[1] BODY.PEEK[2.MIME])")
            assert status == "OK" and any(b"Content-Type: text/html" in item[1] for item in data if isinstance(item, tuple))
        assert all(not item["seen"] for item in s.rpc("storage", op="list", username=bob)["messages"])
        assert client.uid("store", uids[0], "+FLAGS.SILENT", "(\\Seen \\Answered \\Flagged)")[0] == "OK"
        assert client.uid("search", None, "ANSWERED", "FLAGGED")[1] == [uids[0].encode()]
        assert client.uid("copy", uids[0], "Archive")[0] == "OK"
        assert client.response("COPYUID")[1][0] is not None
        before = s.rpc("storage", op="list", username=bob, folder="Archive")
        # A two-message copy would exceed the account quota; neither source
        # may be copied and no UID may be consumed on a failed transaction.
        assert client.uid("copy", ",".join(uids), "Archive")[0] == "NO"
        after = s.rpc("storage", op="list", username=bob, folder="Archive")
        assert after["messages"] == before["messages"] and after["uidnext"] == before["uidnext"]
        assert client.uid("move", uids[1], "Trash")[0] == "OK"
        assert client.select("Archive")[1] == [b"1"]
        flags = client.fetch("1", "(FLAGS)")[1]
        assert all(flag in b" ".join(flags) for flag in (b"\\Seen", b"\\Answered", b"\\Flagged"))
        assert client.select("Trash")[1] == [b"1"]
        assert literal(client.fetch("1", "(BODY.PEEK[])")[1]) == stored[uids[1]]
        draft = b"From: client-bob@localhost\r\nTo: client-alice@localhost\r\nSubject: Client draft\r\n\r\n" + b"x" * 20000 + b"\r\n"
        assert client.append("Drafts", "(\\Seen \\Draft)", '"13-Oct-2026 12:34:56 +0800"', draft)[0] == "OK"
        assert client.response("APPENDUID")[1][0] is not None
        assert client.select("Drafts")[1] == [b"1"]
        status, data = client.fetch("1", "(BODY.PEEK[] INTERNALDATE FLAGS)")
        assert status == "OK" and literal(data) == draft
        assert b'13-Oct-2026 04:34:56 +0000' in b" ".join(item[0] if isinstance(item, tuple) else item for item in data)
        before = s.rpc("storage", op="list", username=bob, folder="Drafts")
        assert client.append("Drafts", None, None, b"Subject: Over quota\r\n\r\nbody\r\n")[0] == "NO"
        after = s.rpc("storage", op="list", username=bob, folder="Drafts")
        assert after["messages"] == before["messages"] and after["uidnext"] == before["uidnext"]
        assert client.store("1", "+FLAGS.SILENT", "(\\Deleted)")[0] == "OK"
        draft_uid = client.uid("search", None, "ALL")[1][0]
        assert client.uid("expunge", draft_uid)[0] == "OK"
        assert client.uid("search", None, "ALL")[1] == [b""]
    # Persistent flags survive a storage restart and a new client connection.
    s.stop("storage")
    s.start("storage")
    with imaplib.IMAP4("localhost", s.ports["imap"], timeout=10) as client:
        assert "LOGINDISABLED" in client.capabilities and "STARTTLS" in client.capabilities
        client.starttls(ssl_context=context())
        client.authenticate("PLAIN", lambda _: f"\0{bob}\0{PASSWORD}".encode())
        assert client.select("INBOX")[1] == [b"1"]
        assert b"\\Answered" in b" ".join(client.fetch("1", "(FLAGS)")[1])
    print("PASS IMAP 993/143 secure login, ENVELOPE/BODYSTRUCTURE/MIME sections, persistent flags, APPEND, COPY, MOVE and UID EXPUNGE", flush=True)

    expected = next(iter(stored.values()))
    with closing(poplib.POP3_SSL("localhost", s.ports["pop3s"], context=context(), timeout=10)) as client:
        client.user(bob)
        client.pass_(PASSWORD)
        assert client.stat()[0] == 1
        retrieved = b"\r\n".join(client.retr(1)[1]) + b"\r\n"
        assert retrieved == expected
        assert len(client.uidl()[1]) == 1
        client.quit()
    with closing(poplib.POP3("localhost", s.ports["pop3"], timeout=10)) as client:
        assert "STLS" in client.capa()
        client.stls(context=context())
        client.user(bob)
        client.pass_(PASSWORD)
        assert client.stat()[0] == 1
        client.quit()
    print("PASS POP3 995 implicit TLS and 110 STLS read the same durable inbox with exact message bytes", flush=True)

    # Disabling every optional TLS listener must close only those sockets.
    for service in ("smtp", "pop3", "imap"):
        s.stop(service)
    for alias in ("submission", "smtps", "pop3s", "imaps"):
        s.config["ports"][alias] = 0
    s.save()
    for service in ("smtp", "pop3", "imap"):
        s.start(service)
    for alias in ("submission", "smtps", "pop3s", "imaps"):
        try:
            with socket.create_connection(("localhost", s.ports[alias]), timeout=0.2):
                raise AssertionError("disabled listener remained open: " + alias)
        except OSError:
            pass
    # Configured aliases without credentials must never become plaintext SMTP
    # submission or implicit-TLS listeners, even in local development mode.
    for service in ("smtp", "pop3", "imap", "web"):
        s.stop(service)
    s.config.update(tls_certificate="", tls_private_key="", allow_insecure_auth=True)
    for alias in ("submission", "smtps", "pop3s", "imaps"):
        s.config["ports"][alias] = s.ports[alias]
    s.save()
    for service in ("smtp", "pop3", "imap", "web"):
        s.start(service)
    assert discovery_request(s, "GET", "/mail/config-v1.1.xml", encrypted=False)[0] == 403
    for alias in ("submission", "smtps", "pop3s", "imaps"):
        try:
            with socket.create_connection(("localhost", s.ports[alias]), timeout=0.2):
                raise AssertionError("certificate-free TLS listener opened: " + alias)
        except OSError:
            pass
    print("PASS optional encrypted listeners honor port 0 and stay closed without TLS credentials", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("mail-clients-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    finally:
        suite.close()
