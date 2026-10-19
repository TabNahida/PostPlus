#!/usr/bin/env python3
"""Offline inbound spam policy, scanner and durable Junk routing checks."""
import argparse
import base64
from email.header import Header
import http.server
import json
import quopri
from pathlib import Path
import secrets
import smtplib
import socket
import threading
import time

from integration import PASSWORD, ROOT, Suite


class RspamdFixture:
    def __init__(self):
        self.reply = {"score": 0.2, "action": "no action", "symbols": {"LOCAL_TEST": {"score": 0.2}}}
        self.status = 200
        self.delay = 0
        self.chunked = False
        self.requests = []
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                fixture.requests.append((self.path, dict(self.headers), raw))
                if fixture.delay:
                    time.sleep(fixture.delay)
                body = json.dumps(fixture.reply).encode()
                self.send_response(fixture.status)
                if fixture.chunked:
                    self.send_header("Transfer-Encoding", "chunked")
                else:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write((f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n") if fixture.chunked else body)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def check(s):
    clean = "From: normal@example.net\r\nTo: alice@localhost\r\nSubject: Normal mail\r\n\r\nA normal message.\r\n"
    spam = "From: normal@example.net\r\nTo: alice@localhost\r\nSubject: lottery winner\r\n\r\nUrgent money transfer with free money.\r\n"
    s.config.update(spam_threshold=5, spam_allow_senders=[], spam_block_senders=[], rspamd_enabled=False,
                    rspamd_timeout_seconds=1, clamav_host="")
    s.save()
    s.start("filter")

    def scan(raw, **metadata):
        return s.rpc("filter", op="scan", raw=raw, **metadata)

    def configure(**fields):
        s.stop("filter")
        s.config.update(fields)
        s.save()
        s.start("filter")

    result = scan(spam, inbound=True, sender="normal@example.net")
    assert result["action"] == "spam" and result["spam_score"] == 8 and result["spam_reasons"], result
    assert scan(clean, inbound=True)["action"] == "accept"
    assert scan(spam, inbound=False)["action"] == "accept"
    forged = "Authentication-Results: attacker.invalid; spf=pass; dkim=pass\r\nX-Spam-Status: No\r\nX-Spam-Score: -999\r\n" + spam
    assert scan(forged, inbound=True)["spam_score"] == result["spam_score"], "Untrusted auth/spam headers bypassed filtering"
    ignored_headers = "Authentication-Results: lottery winner free money urgent money transfer\r\nX-Spam-Status: lottery winner free money\r\n" + clean
    assert scan(ignored_headers)["spam_score"] == 0
    encoded = "Subject: " + Header("lottery winner urgent money transfer", "utf-8").encode() + "\r\n\r\nBody\r\n"
    assert scan(encoded)["action"] == "spam", "Encoded subject bypassed scoring"
    folded = "Content-Type: text/plain; charset=utf-8\r\n\r\nlot\u200btery\t\r\n winner; urgent\u00a0money transfer; fr\u00adee money"
    assert scan(folded)["spam_score"] == 8, "Whitespace/invisible separators bypassed scoring"
    html_headers = "Subject: Account notice\r\nContent-Type: text/html; charset=utf-8\r\n"
    obscured_html = "<p>lot<!--comment-->tery<span> win</span>ner</p><p>urgent&nbsp;money&#x2002;transfer</p><p>fr&shy;ee mo&#x6e;ey</p>"
    obscured = html_headers + "Content-Transfer-Encoding: quoted-printable\r\n\r\n" + quopri.encodestring(obscured_html.encode()).decode()
    assert scan(obscured)["spam_score"] == 8, "Encoded HTML entities and inline tags bypassed scoring"
    assert scan(html_headers + "\r\n<head><title>Newsletter</title><body>" + obscured_html)["spam_score"] == 8, "Optional closing head tag hid body scoring"
    base64_spam = "Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(b"lottery winner urgent money transfer").decode()
    assert scan(base64_spam)["spam_score"] == 6
    harmless_html = ("<head><title>free money</title><style>.lottery winner { content: 'urgent money transfer'; }</style></head>"
                     "<script>const example = '<form><input>lottery winner urgent money transfer</form>';</script>"
                     "<!-- <form><input>lottery winner urgent money transfer -->"
                     "<format>Ordinary newsletter</format><span title='<input>free money'>Hello</span>"
                     "<a href='https://safe.example/?next=https://bit.ly/test'>Article</a>"
                     "<a href='https://bit.ly.attacker.example/path'>Article</a>"
                     "<a href='https://bit.ly@safe.example/path'>Article</a>")
    assert scan(html_headers + "\r\n" + harmless_html)["spam_score"] == 0, "Markup or URL substrings caused a false positive"
    for raw_element in ("script", "style", "title"):
        raw_text_html = "<" + raw_element + ">const x = '<span';</" + raw_element + "><p>lottery winner urgent money transfer</p>"
        assert scan(html_headers + "\r\n" + raw_text_html)["spam_score"] == 6, "Raw HTML element swallowed visible body"
    nested_template = "<template><template>ignored</template>lottery winner urgent money transfer<form></form></template><p>Hello</p>"
    assert scan(html_headers + "\r\n" + nested_template)["spam_score"] == 0, "Nested template content was treated as visible"
    nested_script = "<template><script>const x = '</template>';</script>free money</template><p>lottery winner urgent money transfer</p>"
    assert scan(html_headers + "\r\n" + nested_script)["spam_score"] == 6, "Raw element changed template nesting"
    unknown_tags = "<script.foo>lottery winner urgent money transfer</script.foo><form!x>Offer</form!x><input_data>"
    assert scan(html_headers + "\r\n" + unknown_tags)["spam_score"] == 6, "Unknown tag punctuation was mistaken for active HTML"
    linked = html_headers + "\r\n<a HREF='https&#58;//b&#105;t.ly/test?foo=1&amp;bar=2'>Article</a>"
    assert scan(linked)["spam_score"] == 1, "Encoded shortened href was not recognized"
    gtube = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
    gtube_mail = "Subject: Spam filter test\r\n\r\n" + gtube
    for gtube_message in (gtube_mail,
                          "Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(gtube.encode()).decode(),
                          html_headers + "\r\n<p>" + gtube.replace("GTUBE", "GT&#85;BE") + "</p>"):
        verdict = scan(gtube_message)
        assert verdict["action"] == "spam" and "GTUBE anti-spam test signature detected" in verdict["spam_reasons"], verdict
    assert scan(gtube_mail, inbound=False)["action"] == "accept", "GTUBE changed authenticated submission exemption"
    configure(spam_threshold=1000, spam_rules=[])
    assert scan(gtube_mail)["action"] == "spam", "GTUBE depends on configured weighted rules"
    s.config.pop("spam_rules")
    configure(spam_threshold=5, blocked_terms=["lottery winner"])
    assert scan(obscured)["action"] == "reject", "HTML obfuscation bypassed configured blocked terms"
    assert scan(obscured, inbound=False)["action"] == "reject", "Submission bypassed normalized blocked terms"
    configure(blocked_terms=[])
    heuristic = "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture\r\n\r\n--fixture\r\nContent-Type: text/html\r\n\r\n<form><input name=password></form><a href=https://bit.ly/test>Sign in</a>\r\n--fixture\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=offer.exe\r\n\r\nnot an executable\r\n--fixture--\r\n"
    assert scan(heuristic)["action"] == "spam" and scan(heuristic)["spam_score"] == 6
    for attachment_headers in (
        "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*=utf-8''installer%2Eexe",
        "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*0*=utf-8''install; filename*1*=er%2Eexe",
        "Content-Type: application/octet-stream; name=installer.exe\r\nContent-Disposition: attachment",
        "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"=?UTF-8?B?aW5zdGFsbGVyLmV4ZQ==?=\"",
    ):
        encoded_name = ("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=filename-test\r\n\r\n"
                        "--filename-test\r\nContent-Type: text/html\r\n\r\n<form></form>\r\n"
                        "--filename-test\r\n" + attachment_headers + "\r\n\r\nPayload\r\n--filename-test--\r\n")
        filename_verdict = scan(encoded_name)
        assert filename_verdict["action"] == "spam" and filename_verdict["spam_score"] == 5, filename_verdict
        assert "Executable attachment filename" in filename_verdict["spam_reasons"]
    for suffix, expected_score in (("lnk", 3), ("hta", 3), ("msi", 3), ("wsf", 3), ("exe.txt", 0)):
        attachment = "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=invoice." + suffix + "\r\n\r\nPayload"
        assert scan(attachment)["spam_score"] == expected_score, (suffix, scan(attachment))
    configure(spam_allow_senders=["trusted@example.net", "@trusted.example"], spam_block_senders=["blocked.example", "trusted@example.net"])
    assert scan(clean, sender="sale@blocked.example")["action"] == "spam"
    assert scan(clean, sender="sale@sub.blocked.example")["action"] == "accept", "Domain policies must match exactly"
    assert scan(spam, sender="person@trusted.example")["action"] == "accept"
    assert scan(gtube_mail, sender="person@trusted.example")["action"] == "accept", "GTUBE bypassed explicit allow policy"
    assert scan(clean, sender="trusted@example.net")["action"] == "spam", "Block must take precedence"
    assert scan("From: person@trusted.example\r\n" + spam, sender="remote@example.net")["action"] == "spam"
    eicar = "Subject: Malware\r\n\r\nX5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\r\n"
    assert scan(eicar, sender="person@trusted.example")["action"] == "reject", "Allow policy bypassed malware"
    assert scan(eicar, inbound=False)["action"] == "reject", "Authenticated submissions bypassed malware"
    configure(spam_allow_senders=[], spam_block_senders=[], spam_rules=[{"term": "normal", "weight": 1000}] * 1000)
    maximum = scan(clean)
    assert maximum["spam_score"] == 1000000 and len(maximum["spam_reasons"]) == 128, maximum
    long_term = "中" * 85
    configure(spam_rules=[{"term": long_term, "weight": 5}])
    bounded = scan("Subject: long rule\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + long_term + "\r\n")
    assert bounded["action"] == "spam" and len(bounded["spam_reasons"][0].encode()) <= 256, bounded
    s.config.pop("spam_rules")
    configure()
    print("PASS normalized MIME/HTML scoring, GTUBE, conservative link/form signals, sender policies and outbound malware protection", flush=True)

    scanner = RspamdFixture()
    try:
        configure(rspamd_enabled=True, rspamd_port=scanner.port, spam_allow_senders=[], spam_block_senders=[])
        result = scan(clean, inbound=True, sender="normal@example.net", peer_ip="198.51.100.8", helo="sender.example.net", recipient="alice@localhost")
        assert result["action"] == "accept" and result["spam_score"] == 0.2 and "Rspamd: LOCAL_TEST" in result["spam_reasons"], result
        path, headers, raw = scanner.requests[-1]
        assert path == "/checkv2" and headers["IP"] == "198.51.100.8" and headers["From"] == "normal@example.net" and raw == clean.encode()
        scanner.reply = {"score": 9, "action": "reject", "symbols": {"SPAM_TEST": {"score": 9}}}
        scanner.chunked = True
        assert scan(clean)["action"] == "spam", "Chunked Rspamd verdict was not handled"
        scanner.reply = {"score": 0, "action": "soft reject"}
        assert scan(clean)["action"] == "defer"
        scanner.reply = {"action": "no action"}
        assert scan(clean)["action"] == "defer", "Incomplete scanner response reported clean"
        scanner.reply = {"score": 0, "action": "unknown"}
        assert scan(clean)["action"] == "defer", "Unknown scanner verdict reported clean"
        scanner.status = 503
        assert scan(clean)["action"] == "defer"
        scanner.status = 200
        scanner.reply = {"score": 0, "action": "no action"}
        scanner.delay = 2
        started = time.monotonic()
        assert scan(clean)["action"] == "defer"
        assert time.monotonic() - started < 2.5, "Scanner whole-request deadline was not enforced"
    finally:
        scanner.close()
    assert scan(clean)["action"] == "defer", "Scanner outage did not defer"
    before = len(scanner.requests)
    assert scan(spam, inbound=False)["action"] == "accept"
    assert len(scanner.requests) == before, "Authenticated submission contacted inbound scanner"
    print("PASS Rspamd trusted metadata, fixed/chunked framing, local verdicts and outage/timeout retry policy", flush=True)

    configure(rspamd_enabled=False)
    for service in ("auth", "storage", "smtp"):
        s.start(service)
    user = "alice@localhost"
    assert s.rpc("auth", op="create", username=user, password=PASSWORD)["ok"]
    with smtplib.SMTP("127.0.0.1", s.ports["smtp"], local_hostname="inbound.example.net", timeout=10) as client:
        assert client.sendmail("normal@example.net", [user], spam) == {}
    with smtplib.SMTP("127.0.0.1", s.ports["smtp"], local_hostname="outbound.example.net", timeout=10) as client:
        client.login(user, PASSWORD)
        assert client.sendmail(user, [user], spam) == {}
    jobs = s.rpc("storage", op="queue_list", limit=100)["jobs"]
    assert len(jobs) == 2
    inbound = next(job for job in jobs if job["sender"] == "normal@example.net")
    outbound = next(job for job in jobs if job["sender"] == user)
    assert inbound["inbound"] and inbound["peer_ip"] == "127.0.0.1" and inbound["helo"] == "inbound.example.net", inbound
    assert not outbound["inbound"], outbound
    s.start("delivery")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        inbox = s.rpc("storage", op="list", username=user, folder="INBOX")["messages"]
        junk = s.rpc("storage", op="list", username=user, folder="Junk")["messages"]
        if len(inbox) == len(junk) == 1:
            break
        time.sleep(0.1)
    assert len(inbox) == len(junk) == 1, (inbox, junk, s.rpc("storage", op="queue_inspect"))
    stored = s.rpc("storage", op="get", username=user, id=junk[0]["id"])
    assert stored["raw"] == spam.encode(), "Junk routing changed signed MIME bytes"
    assert stored["filter_action"] == "spam" and stored["spam_score"] == 8 and stored["spam_reasons"], stored
    assert s.rpc("storage", op="stats")["quarantined"] == 0, "Normal spam incorrectly quarantined"
    print("PASS persisted SMTP ingress facts, inbound Junk delivery, authenticated Inbox delivery and unchanged MIME", flush=True)

    s.stop("delivery")
    s.stop("storage")
    s.start("storage")
    persisted = s.rpc("storage", op="get", username=user, id=junk[0]["id"])
    assert persisted["spam_reasons"] == stored["spam_reasons"] and persisted["filter_action"] == "spam"
    # Rspamd has stopped; its configured outage must retain a pending queue
    # item with a retry diagnostic, then complete when service is restored.
    configure(rspamd_enabled=True)
    queued = s.rpc("storage", op="enqueue", sender="normal@example.net", recipients=[user], raw=clean, inbound=True)
    assert queued["ok"]
    s.start("delivery")
    deadline = time.monotonic() + 10
    pending = []
    while time.monotonic() < deadline:
        pending = s.rpc("storage", op="queue_inspect")["jobs"]
        if pending and pending[0]["attempts"] >= 1:
            break
        time.sleep(0.1)
    assert len(pending) == 1 and pending[0]["state"] == "pending" and "Rspamd unavailable" in pending[0]["error"], pending
    s.stop("delivery")
    configure(rspamd_enabled=False)
    assert s.rpc("storage", op="queue_retry", id=pending[0]["id"], delay=1, error="scanner restored")["ok"]
    s.start("delivery")
    s.wait_mail(user, 2)
    assert not s.rpc("storage", op="queue_list")["jobs"]
    assert s.rpc("storage", op="stats")["quarantined"] == 0
    print("PASS persisted spam verdicts, scanner outage pending retry and successful recovery", flush=True)

    s.stop("delivery")
    s.start("web")
    status, headers, login = s.http("web", "POST", "/api/login", {"username": user, "password": PASSWORD})
    assert status == 200, login
    authorized = {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": login["csrf"]}
    configure(spam_block_senders=[user])
    outgoing = {"to": [user], "subject": "lottery winner", "text": "Urgent money transfer with free money."}
    submitted = s.http("web", "POST", "/api/send", outgoing, authorized)
    assert submitted[0] == 202, "Authenticated Webmail must skip inbound sender blocks and spam scores: " + str(submitted)
    configure(rspamd_enabled=True)
    unavailable_outgoing = s.http("web", "POST", "/api/send", {"to": [user], "subject": "Scanner outage", "text": "Ordinary authenticated mail"}, authorized)
    assert unavailable_outgoing[0] == 202, "Inbound Rspamd outage must not block authenticated Webmail: " + str(unavailable_outgoing)
    malware = s.http("web", "POST", "/api/send", {"to": [user], "subject": "Malware", "text": eicar.split("\r\n\r\n", 1)[1]}, authorized)
    assert malware[0] == 422, "Authenticated Webmail must retain malware protection: " + str(malware)
    pending = s.rpc("storage", op="queue_list", limit=100)["jobs"]
    assert len(pending) == 2 and all(not job["inbound"] for job in pending), pending
    s.start("delivery")
    s.wait_mail(user, 4)
    assert s.rpc("storage", op="stats")["quarantined"] == 0
    print("PASS Webmail authenticated spam/block bypass, malware rejection and inbound-scanner outage immunity", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("antispam-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        check(suite)
    finally:
        suite.close()


if __name__ == "__main__":
    main()
