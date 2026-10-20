#!/usr/bin/env python3
"""Hostname-scoped portals with real auth, cookies, API keys and invitations."""
import argparse
from pathlib import Path
import secrets
import socket
from urllib.parse import urlsplit

from integration import PASSWORD, ROOT, Suite


def request(s, service, method, path, host, body=None, headers=None):
    return s.http(service, method, path, body, {**(headers or {}), "Host": host})


def login(s, service, host, username):
    status, headers, result = request(s, service, "POST", "/api/login", host,
                                      dict(username=username, password=PASSWORD))
    assert status == 200, (host, username, status, result)
    return {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": result["csrf"]}


def run(s):
    s.config.update(domain="example.com", mail_hostname="mail.example.com", additional_domains=["example.net"],
                    webmail_shared_hostname="", outbound_mode="disabled")
    s.config.pop("admin_hostname", None)  # Existing installations default to their first domain.
    s.save()
    for service in ("auth", "storage", "web", "admin"):
        s.start(service)
    for username in ("administrator@example.net", "same@example.com", "same@example.net"):
        assert s.rpc("auth", op="create", username=username, password=PASSWORD,
                     admin=username.startswith("administrator"))["ok"]

    for host in ("example.com", "EXAMPLE.COM.", "example.com:443"):
        status, _, public = request(s, "web", "GET", "/api/public/config", host)
        assert status == 200 and public["domain"] == "example.com" and public["domains"] == ["example.com"], public
    assert request(s, "web", "GET", "/api/public/config", "example.net")[2]["domains"] == ["example.net"]
    assert s.http("web", "GET", "/api/public/config")[2]["domains"] == ["example.com", "example.net"]
    for host in ("unhosted.org", "example.com.attacker.org", "mail.example.com"):
        for service in ("web", "admin"):
            status, _, result = request(s, service, "GET", "/", host)
            assert status == 421 and result["code"] == "portal_host_mismatch", (host, status, result)
    for host in ("example.com:0", "example.com:65536", "example.com:", "example.com:443:80", "[::1", "[::1]x", "[::1]:", "a..com", "example.com,example.net", "example.com@localhost", "example.com/", "bad host"):
        assert request(s, "web", "GET", "/api/public/config", host)[0] == 400, host
    # Duplicate Host is rejected by the HTTP parser before portal routing.
    with socket.create_connection(("127.0.0.1", s.ports["web"]), timeout=5) as sock:
        sock.sendall(b"GET /api/public/config HTTP/1.1\r\nHost: example.com\r\nHost: example.net\r\n\r\n")
        assert sock.recv(4096).startswith(b"HTTP/1.1 400 ")
    assert request(s, "web", "GET", "/api/public/config", "unhosted.org", headers={"X-Forwarded-Host": "example.com"})[0] == 421
    assert request(s, "web", "GET", "/api/public/config", "example.net", headers={"X-Forwarded-Host": "example.com"})[2]["domains"] == ["example.net"]
    assert request(s, "admin", "GET", "/api/public/config", "example.net")[0] == 421
    administrator = login(s, "admin", "example.com", "administrator@example.net")
    primary = login(s, "web", "example.com", "same@example.com")
    secondary = login(s, "web", "example.net", "same@example.net")
    assert request(s, "web", "POST", "/api/login", "example.com", dict(username="same@example.net", password=PASSWORD))[0] == 403
    for host in ("example.net", "127.0.0.1", "localhost"):
        status, _, result = request(s, "web", "GET", "/api/session", host, headers=primary)
        assert status == 401 and result["code"] == "session_host_mismatch", (status, result)
    assert request(s, "web", "GET", "/api/session", "example.com", headers=primary)[0] == 200
    assert request(s, "web", "GET", "/api/session", "example.net", headers=secondary)[0] == 200
    print("PASS strict Host parsing, admin host isolation, per-domain login and host-bound cookies", flush=True)

    status, _, key = request(s, "web", "POST", "/api/api-keys", "example.net",
                             dict(name="Scoped mailbox", permissions=["mailbox:read"]), secondary)
    assert status == 201, key
    bearer = {"Authorization": "Bearer " + key["key"]}
    assert request(s, "web", "GET", "/api/folders", "example.net", headers=bearer)[0] == 200
    assert request(s, "web", "GET", "/api/folders", "example.com", headers=bearer)[0] == 403
    status, _, invitation = request(s, "admin", "POST", "/api/admin/invitations", "example.com",
                                    dict(name="Domain-bound", domain="example.net", localpart="invited"), administrator)
    assert status == 201 and urlsplit(invitation["registration_url"]).hostname == "example.net", invitation
    token = urlsplit(invitation["registration_url"]).fragment
    endpoint = "/api/public/invitations/"
    assert request(s, "web", "POST", endpoint + "inspect", "example.com", dict(token=token))[0] == 403
    assert request(s, "web", "POST", endpoint + "redeem", "example.com", dict(token=token, password=PASSWORD))[0] == 403
    assert not s.rpc("auth", op="exists", username="invited@example.net")["exists"]
    assert request(s, "web", "POST", endpoint + "inspect", "example.net", dict(token=token))[0] == 200
    assert request(s, "web", "POST", endpoint + "redeem", "example.net", dict(token=token, password=PASSWORD))[0] == 201
    print("PASS API-key domain checks, invitation URL selection and pre-redemption host checks", flush=True)

    status, _, read_key = request(s, "admin", "POST", "/api/admin/api-keys", "example.com",
                                  dict(name="Domain reader", permissions=["config:read"]), administrator)
    assert status == 201, read_key
    reader = {"Authorization": "Bearer " + read_key["key"]}
    status, _, catalog = request(s, "admin", "GET", "/api/admin/domains?limit=1&offset=1", "example.com", headers=reader)
    assert status == 200 and catalog["total"] == 2 and len(catalog["items"]) == 1, catalog
    assert request(s, "admin", "GET", "/api/admin/domains?limit=bad", "example.com", headers=reader)[0] == 400
    status, _, preview = request(s, "admin", "POST", "/api/admin/domains/preview", "example.com", dict(domain="new.example.org"), reader)
    assert status == 200, (status, preview)
    payload = dict(domain="new.example.org", revision=catalog["revision"])
    assert request(s, "admin", "POST", "/api/admin/domains", "example.com", payload, reader)[0] == 403
    status, _, write_key = request(s, "admin", "POST", "/api/admin/api-keys", "example.com",
                                   dict(name="Domain writer", permissions=["config:write"]), administrator)
    assert status == 201, write_key
    writer = {"Authorization": "Bearer " + write_key["key"]}
    status, _, added = request(s, "admin", "POST", "/api/admin/domains", "example.com", payload, writer)
    assert status == 201 and added["record"]["status"] == "pending", added
    assert request(s, "web", "GET", "/", "new.example.org")[0] == 421
    assert request(s, "admin", "POST", "/api/admin/domains/remove", "example.com",
                   dict(domain="new.example.org", revision=added["revision"]), writer)[0] == 200
    print("PASS authenticated domain API pagination, preview and separate read/write permission enforcement", flush=True)

    # An explicitly empty default written by the settings editor behaves exactly
    # like a missing key; it must not lock administrators out after restart.
    s.stop("admin")
    s.config["admin_hostname"] = ""
    s.save()
    s.start("admin")
    assert login(s, "admin", "example.com", "administrator@example.net")

    for service in ("web", "admin"):
        s.stop(service)
    s.config.update(admin_hostname="manage.example.org", webmail_shared_hostname="inbox.example.org")
    s.save()
    for service in ("web", "admin"):
        s.start(service)
    assert request(s, "admin", "GET", "/", "example.com")[0] == 421
    administrator = login(s, "admin", "manage.example.org", "administrator@example.net")
    shared = login(s, "web", "inbox.example.org", "same@example.com")
    assert login(s, "web", "inbox.example.org", "same@example.net")
    assert request(s, "web", "GET", "/api/public/config", "inbox.example.org")[2]["domains"] == ["example.com", "example.net"]
    assert request(s, "web", "GET", "/api/folders", "inbox.example.org", headers=bearer)[0] == 200
    assert request(s, "web", "GET", "/api/session", "example.com", headers=shared)[0] == 401
    status, _, invitation = request(s, "admin", "POST", "/api/admin/invitations", "manage.example.org",
                                    dict(name="Shared portal", domain="example.com", localpart="sharedinvite"), administrator)
    assert status == 201 and urlsplit(invitation["registration_url"]).hostname == "inbox.example.org", invitation
    assert request(s, "web", "POST", endpoint + "redeem", "inbox.example.org",
                   dict(token=urlsplit(invitation["registration_url"]).fragment, password=PASSWORD))[0] == 201

    # Removing a hosted domain retains its users. The last administrator must
    # remain able to repair configuration through the designated admin portal,
    # while the removed mailbox cannot use the shared Webmail portal.
    for service in ("auth", "web", "admin"):
        s.stop(service)
    s.config["additional_domains"] = []
    s.save()
    for service in ("auth", "web", "admin"):
        s.start(service)
    retained = login(s, "admin", "manage.example.org", "administrator@example.net")
    assert request(s, "admin", "GET", "/api/admin/users", "manage.example.org", headers=retained)[0] == 200
    assert request(s, "admin", "POST", "/api/login", "example.net", dict(username="administrator@example.net", password=PASSWORD))[0] == 421
    assert request(s, "web", "POST", "/api/login", "inbox.example.org", dict(username="same@example.net", password=PASSWORD))[0] == 403

    s.stop("web")
    s.config["allow_insecure_auth"] = False
    s.save()
    s.start("web")
    assert s.http("web", "GET", "/api/public/config")[0] == 421
    assert s.http("web", "GET", "/health")[0] == 200
    assert request(s, "web", "GET", "/api/public/config", "example.com")[0] == 200
    assert request(s, "web", "POST", "/api/login", "example.com", dict(username="same@example.com", password=PASSWORD))[0] == 403
    print("PASS dedicated admin hostname, shared Webmail login and explicit loopback development access", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build" / "test-runs" / ("portals-" + secrets.token_hex(6))
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
