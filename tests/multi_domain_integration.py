#!/usr/bin/env python3
"""Real services: independent suffixes, registration and domain-scoped delivery."""
import argparse
from pathlib import Path
import secrets
import smtplib
from urllib.parse import urlsplit

from integration import PASSWORD, ROOT, Suite
from password_policy_integration import login


def run(s):
    s.config.update(domain=" Example.COM ", additional_domains=["EXAMPLE.NET", "example.net"],
                    outbound_mode="disabled")
    s.config.pop("mail_hostname", None)  # Derive the hostname from the normalized primary suffix.
    s.save()
    for service in ("auth", "storage", "filter", "smtp", "web", "admin"):
        s.start(service)
    assert s.rpc("auth", op="create", username="admin@example.com", password=PASSWORD, admin=True)["ok"]
    administrator = login(s, "admin", "admin@example.com")
    status, _, public = s.http("web", "GET", "/api/public/config")
    assert status == 200 and public["domain"] == "example.com" and public["domains"] == ["example.com", "example.net"], public
    for username in ("same@example.com", "same@example.net"):
        status, _, created = s.http("admin", "POST", "/api/admin/users",
                                    dict(username=username, password=PASSWORD), administrator)
        assert status == 201 and created["ok"], (status, created)
    assert s.http("admin", "POST", "/api/admin/users", dict(username="no@unhosted.org", password=PASSWORD), administrator)[0] == 400
    primary, secondary = login(s, "web", "same@example.com"), login(s, "web", "same@example.net")
    status, _, invitation = s.http("admin", "POST", "/api/admin/invitations",
                                 dict(name="Second domain", domain="EXAMPLE.NET", localpart="invited"), administrator)
    assert status == 201 and invitation["invitation"]["domain"] == "example.net", invitation
    token = urlsplit(invitation["registration_url"]).fragment
    public_invite = "/api/public/invitations/"
    status, _, inspected = s.http("web", "POST", public_invite + "inspect", {"token": token})
    assert status == 200 and inspected["domain"] == "example.net", inspected
    status, _, redeemed = s.http("web", "POST", public_invite + "redeem", dict(token=token, password=PASSWORD))
    assert status == 201 and redeemed["username"] == "invited@example.net", redeemed
    assert not s.rpc("auth", op="exists", username="invited@example.com")["exists"]
    assert s.http("admin", "POST", "/api/admin/invitations", dict(name="Foreign", domain="unhosted.org"), administrator)[0] == 400
    status, _, pending = s.http("admin", "POST", "/api/admin/invitations", dict(name="Temporarily removed domain", domain="example.net"), administrator)
    assert status == 201, pending
    pending_token = urlsplit(pending["registration_url"]).fragment
    s.stop("auth")
    s.config["additional_domains"] = []
    s.save()
    s.start("auth")
    assert s.http("web", "POST", public_invite + "inspect", {"token": pending_token})[0] == 410
    s.stop("auth")
    s.config["additional_domains"] = ["example.net"]
    s.save()
    s.start("auth")
    assert s.http("web", "POST", public_invite + "inspect", {"token": pending_token})[2]["domain"] == "example.net"
    for domain in ("example.com", "example.net"):
        status, _, dns = s.http("admin", "GET", "/api/admin/dns?domain=" + domain, headers=administrator)
        assert status == 200 and dns["domain"] == domain and dns["hostname"] == "mail.example.com", dns
        assert next(record for record in dns["records"] if record["id"] == "mx")["name"] == domain
    assert s.http("admin", "GET", "/api/admin/dns?domain=unhosted.org", headers=administrator)[0] == 400
    # Prefix-only legacy rules remain on the primary domain, never every suffix.
    assert s.rpc("storage", op="forwarding_create", pattern="alias-*", destination="same@example.com")["ok"]
    assert s.rpc("storage", op="resolve_recipient", recipient="alias-one@example.com")["destination"] == "same@example.com"
    assert not s.rpc("storage", op="resolve_recipient", recipient="alias-one@example.net")["exists"]
    status, _, rule = s.http("admin", "POST", "/api/admin/forwarding",
                            dict(pattern="alias-*@EXAMPLE.NET", destination="same@example.com"), administrator)
    assert status == 201 and rule["rule"]["domain"] == "example.net", rule
    assert s.rpc("storage", op="resolve_recipient", recipient="alias-one@example.net")["destination"] == "same@example.com"
    assert len(s.http("admin", "GET", "/api/admin/forwarding", headers=administrator)[2]["rules"]) == 2
    assert s.http("admin", "DELETE", "/api/admin/forwarding/" + str(rule["rule"]["id"]), headers=administrator)[2]["deleted"]
    assert not s.rpc("storage", op="resolve_recipient", recipient="alias-one@example.net")["exists"]
    with smtplib.SMTP("127.0.0.1", s.ports["smtp"], local_hostname="sender.example.org", timeout=10) as smtp:
        for domain in ("example.com", "example.net"):
            raw = f"From: outside@example.org\r\nTo: same@{domain}\r\nSubject: Incoming {domain}\r\n\r\nIndependent mailbox.\r\n"
            assert smtp.sendmail("outside@example.org", ["same@" + domain], raw) == {}
        assert smtp.mail("outside@example.org")[0] == 250
        assert smtp.rcpt("same@unhosted.org")[0] == 550
    status, _, sent = s.http("web", "POST", "/api/send", dict(to=["invited@example.net"], subject="Local cross-domain", text="No relay required"), primary)
    assert status == 202 and sent["ok"], sent
    assert s.http("web", "POST", "/api/send", dict(to=["outside@unhosted.org"], subject="External", text="Blocked"), secondary)[0] == 400
    s.start("delivery")
    primary_mail = s.wait_mail("same@example.com", 1)["messages"]
    secondary_mail = s.wait_mail("same@example.net", 1)["messages"]
    assert len(primary_mail) == len(secondary_mail) == 1
    primary_raw = s.rpc("storage", op="get", username="same@example.com", id=primary_mail[0]["id"])["raw"]
    secondary_raw = s.rpc("storage", op="get", username="same@example.net", id=secondary_mail[0]["id"])["raw"]
    assert b"Subject: Incoming example.com" in primary_raw and b"Subject: Incoming example.net" in secondary_raw
    assert len(s.wait_mail("invited@example.net", 1)["messages"]) == 1
    assert s.http("web", "GET", "/api/messages/" + secondary_mail[0]["id"], headers=primary)[0] == 404
    print("PASS multi-domain accounts, invitations, DNS, inbound SMTP, isolated mailboxes, local cross-domain delivery and scoped forwarding", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build" / "test-runs" / ("multi-domain-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory.resolve())
    try:
        run(suite)
    except BaseException:
        print(f"Logs: {directory}", flush=True)
        raise
    finally:
        suite.close()


if __name__ == "__main__":
    main()
