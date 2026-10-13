#!/usr/bin/env python3
"""Internet-style inbound SMTP, local delivery and relay-boundary regressions.

Every connection is loopback. No public DNS query or external message is sent.
"""
import argparse
from collections import Counter
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path
import secrets
import smtplib
import ssl

from integration import PASSWORD, ROOT, Suite


def message(sender, recipients, subject):
    mail = EmailMessage(policy=SMTP)
    mail["From"] = sender
    mail["To"] = ", ".join(recipients)
    mail["Subject"] = subject
    # Inbound mail must retain the external sender's signature, even though
    # this offline fixture is not an actual cryptographic signature.
    mail["DKIM-Signature"] = "v=1; a=rsa-sha256; d=outlook.com; s=selector1; b=fixture; bh=fixture;"
    mail.set_content("External receipt fixture.\n.leading dot\n中文正文\n", cte="quoted-printable")
    mail.add_alternative("<p>External receipt fixture.</p>", subtype="html", cte="quoted-printable")
    mail.add_attachment(b"\x00\x01\xfe\xff", maintype="application", subtype="octet-stream", filename="fixture.bin")
    return mail.as_bytes()


def client(suite):
    return smtplib.SMTP("127.0.0.1", suite.ports["smtp"], local_hostname="inbound-fixture", timeout=10)


def run(suite):
    alice, bob = "alice@example.com", "bob@example.com"
    foreign, remote = "external@outlook.com", "external@example.net"
    suite.config.update(domain="example.com", mail_hostname="mail.example.com", outbound_mode="disabled")
    suite.save()
    for name in ("auth", "storage", "filter", "admin"):
        suite.start(name)
    for username in (alice, bob):
        assert suite.rpc("auth", op="create", username=username, password=PASSWORD, admin=username == alice)["ok"]
    status, headers, login = suite.http("admin", "POST", "/api/login", {"username": alice, "password": PASSWORD})
    assert status == 200, login
    authorized = {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": login["csrf"]}
    status, _, public = suite.http("admin", "POST", "/api/admin/dkim", {"domain": "example.com", "selector": "postplus"}, authorized)
    assert status == 200 and public["name"] == "postplus._domainkey.example.com", public
    keys = list(suite.directory.glob("postplus.dkim-*.pem"))
    assert len(keys) == 1
    suite.stop("admin")
    suite.config.update(outbound_mode="direct", dkim_private_key=str(keys[0]))
    suite.save()
    suite.start("smtp")
    expected = []

    def accepted(sender, recipients, raw):
        expected.extend((sender, recipient, raw) for recipient in recipients)

    with client(suite) as peer:
        peer.ehlo()
        assert peer.mail(foreign)[0] == 250
        assert peer.rcpt("unknown@example.com")[0] == 550
        # The MX hostname identifies the machine; it is not a second mailbox domain.
        assert peer.rcpt("alice@mail.example.com")[0] == 550
        assert peer.rcpt(remote)[0] == 550
        assert peer.docmd("DATA")[0] == 503
    assert suite.rpc("storage", op="queue_list", limit=100)["jobs"] == []

    def mixed_receipt(mode):
        raw = message(foreign, [alice, bob], mode + " external receipt")
        with client(suite) as peer:
            peer.ehlo()
            assert peer.mail(foreign)[0] == 250
            assert peer.rcpt(remote)[0] == 550
            assert peer.rcpt(alice.upper())[0] == 250
            assert peer.rcpt("unknown@example.com")[0] == 550
            assert peer.rcpt(bob)[0] == 250
            # Rejecting remote recipients must preserve already accepted local ones.
            assert peer.rcpt(remote)[0] == 550
            assert peer.data(raw)[0] == 250
        accepted(foreign, [alice, bob], raw)

    mixed_receipt("direct")
    bounce = message("postmaster@outlook.com", [alice], "Null reverse path receipt")
    with client(suite) as peer:
        peer.ehlo()
        assert peer.mail("")[0] == 250
        assert peer.rcpt(alice)[0] == 250
        assert peer.data(bounce)[0] == 250
    accepted("", [alice], bounce)

    spoofed = message(alice, [bob], "Unauthenticated local reverse path")
    with client(suite) as peer:
        peer.ehlo()
        assert peer.mail(alice)[0] == 250
        assert peer.rcpt(bob)[0] == 250
        assert peer.rcpt(remote)[0] == 550
        assert peer.data(spoofed)[0] == 250
    accepted(alice, [bob], spoofed)
    assert suite.rpc("storage", op="list", username=alice, folder="Sent")["messages"] == []
    assert suite.rpc("storage", op="list", username=bob, folder="Sent")["messages"] == []

    with client(suite) as peer:
        peer.ehlo()
        peer.login(bob, PASSWORD)
        assert peer.mail(bob)[0] == 250
        assert peer.rcpt(remote)[0] == 250
        peer.rset()  # This permission check never submits an external message.
        assert peer.mail(foreign)[0] == 250
        assert peer.rcpt(remote)[0] == 550
        assert peer.rcpt(alice)[0] == 250
        raw = message(foreign, [alice], "Authenticated local receipt")
        assert peer.data(raw)[0] == 250
        accepted(foreign, [alice], raw)

    suite.stop("smtp")
    suite.config.update(tls_certificate=str(ROOT / "tests/fixtures/localhost-test-only.crt"),
                        tls_private_key=str(ROOT / "tests/fixtures/localhost-test-only.key"), allow_insecure_auth=False)
    suite.save()
    suite.start("smtp")
    context = ssl.create_default_context(cafile=str(ROOT / "tests/fixtures/localhost-test-only.crt"))
    with smtplib.SMTP("localhost", suite.ports["smtp"], local_hostname="inbound-fixture", timeout=10) as peer:
        peer.ehlo()
        assert peer.has_extn("starttls") and not peer.has_extn("auth")
        peer.starttls(context=context)
        peer.ehlo()
        raw = message(foreign, [bob], "Unauthenticated STARTTLS receipt")
        assert peer.mail(foreign)[0] == 250
        assert peer.rcpt(bob)[0] == 250
        assert peer.rcpt(remote)[0] == 550
        assert peer.data(raw)[0] == 250
        accepted(foreign, [bob], raw)

    for mode in ("disabled", "relay"):
        suite.stop("smtp")
        suite.config.update(outbound_mode=mode, smarthost_host="relay.example.net" if mode == "relay" else "")
        suite.save()
        suite.start("smtp")
        mixed_receipt(mode)

    jobs = suite.rpc("storage", op="queue_list", limit=100)["jobs"]
    observed = Counter((job["sender"], job["recipient"], job["raw"]) for job in jobs)
    assert observed == Counter(expected), "Rejected recipients leaked into the queue or inbound MIME changed"
    suite.start("delivery")
    for username in (alice, bob):
        raw_messages = [raw for _, recipient, raw in expected if recipient == username]
        inbox = suite.wait_mail(username, len(raw_messages))
        stored = [suite.rpc("storage", op="get", username=username, id=item["id"])["raw"] for item in inbox["messages"]]
        assert Counter(stored) == Counter(raw_messages), "Local delivery changed external headers, MIME or attachment bytes"
    assert suite.rpc("storage", op="queue_list", limit=100)["jobs"] == []
    print("PASS unauthenticated foreign/null/local senders, mailbox domain vs MX hostname, mixed recipients, no open relay, STARTTLS, all outbound modes and exact inbound MIME delivery", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("inbound-smtp-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    finally:
        suite.close()


if __name__ == "__main__":
    main()
