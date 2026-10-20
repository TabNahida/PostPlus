#!/usr/bin/env python3
"""Domain management HTTP contract, migration, pagination and permissions."""
import argparse
import json
from pathlib import Path
import secrets

from integration import PASSWORD, ROOT, Suite
from password_policy_integration import login


def run(s):
    legacy = [f"tenant-{number:03d}.example.net" for number in range(160)]
    s.config.update(domain="example.com", additional_domains=legacy,
                    outbound_mode="disabled", mail_hostname="mail.example.com")
    s.save()
    for service in ("auth", "storage", "web", "admin"):
        s.start(service)
    assert s.rpc("auth", op="create", username="admin@example.com", password=PASSWORD, admin=True)["ok"]
    assert s.rpc("auth", op="create", username="kept@tenant-159.example.net", password=PASSWORD)["ok"]
    administrator = login(s, "admin", "admin@example.com")
    base = "/api/admin/domains"
    assert s.http("admin", "GET", base)[0] == 401
    status, _, listing = s.http("admin", "GET", base, headers=administrator)
    assert status == 200 and listing["total"] == 161 and listing["active_count"] == 161, listing
    assert len(listing["items"]) == 25 and listing["items"][0]["primary"]
    assert not listing["items"][0]["can_remove"]
    names = []
    for offset in range(0, 161, 23):
        status, _, page = s.http("admin", "GET", f"{base}?offset={offset}&limit=23", headers=administrator)
        assert status == 200 and page["total"] == 161
        names += [item["domain"] for item in page["items"]]
    assert len(names) == len(set(names)) == 161
    assert set(names) == {"example.com", *legacy}
    status, _, filtered = s.http("admin", "GET", base + "?q=TENANT-159", headers=administrator)
    assert status == 200 and [item["domain"] for item in filtered["items"]] == [legacy[-1]]
    for query in ("?limit=0", "?limit=201", "?offset=-1", "?offset=1.5", "?unknown=x"):
        assert s.http("admin", "GET", base + query, headers=administrator)[0] == 400, query
    print("PASS more than 50 hosted domains, stable pagination and exact search", flush=True)

    revision = listing["revision"]
    draft = {"revision": revision, "domain": " NEW.EXAMPLE.ORG "}
    assert s.http("admin", "POST", base, draft, {"Cookie": administrator["Cookie"]})[0] == 403
    status, _, added = s.http("admin", "POST", base, draft, administrator)
    assert status == 201 and added["record"]["status"] == "pending", added
    assert added["record"]["domain"] == "new.example.org" and not added["record"]["can_activate"]
    assert not added["restart_required"]
    saved = json.loads(s.path.read_text(encoding="utf-8"))
    assert "additional_domains" not in saved and len(saved["mail_domains"]) == 161
    assert "new.example.org" not in saved["mail_domains"]
    assert saved["domain_registry"]["new.example.org"]["status"] == "pending"
    assert s.http("admin", "POST", base, dict(revision=revision, domain="raced.example.org"), administrator)[0] == 409
    revision = added["revision"]
    assert s.http("admin", "POST", base, dict(revision=revision, domain="new.example.org"), administrator)[0] == 409
    assert s.http("admin", "POST", base + "/activate", dict(revision=revision, domain="new.example.org"), administrator)[0] == 409
    status, _, guide = s.http("admin", "POST", base + "/preview", dict(domain="new.example.org"), administrator)
    assert status == 200 and guide["domain"] == "new.example.org" and guide["hostname"] == "mail.example.com", guide
    assert next(record for record in guide["records"] if record["id"] == "mx")["name"] == "new.example.org"
    assert s.http("admin", "POST", base + "/preview", dict(domain="new.example.org", dns={"hostname": "attacker.example"}), administrator)[0] == 400
    assert s.http("admin", "POST", base + "/preview", dict(domain="new.example.org", dns={"resolver": "127.0.0.1"}), administrator)[0] == 400
    assert s.http("web", "GET", base, headers=administrator)[0] == 404
    assert s.http("web", "GET", "/api/public/config", headers={"Host": "new.example.org"})[0] == 421
    assert s.http("admin", "POST", "/api/admin/users", dict(username="user@new.example.org", password=PASSWORD), administrator)[0] == 400
    print("PASS pending domains, legacy migration, CSRF, conflicts and DNS draft isolation", flush=True)

    status, _, key = s.http("admin", "POST", "/api/admin/api-keys",
                            dict(name="Domain reader", permissions=["config:read"]), administrator)
    assert status == 201, key
    reader = {"Authorization": "Bearer " + key["key"]}
    assert s.http("admin", "GET", base, headers=reader)[0] == 200
    assert s.http("admin", "POST", base + "/preview", dict(domain="new.example.org"), reader)[0] == 200
    assert s.http("admin", "POST", base, dict(revision=revision, domain="denied.example.org"), reader)[0] == 403
    assert s.http("admin", "POST", base + "/check", dict(revision=revision, domain="new.example.org"), reader)[0] == 403
    assert s.http("admin", "POST", base + "/remove", dict(revision=revision, domain="example.com"), administrator)[0] == 409
    status, _, removed = s.http("admin", "POST", base + "/remove", dict(revision=revision, domain="new.example.org"), administrator)
    assert status == 200 and removed["accounts_retained"] and not removed["restart_required"], removed
    revision = removed["revision"]
    status, _, removed = s.http("admin", "POST", base + "/remove", dict(revision=revision, domain=legacy[-1]), administrator)
    assert status == 200 and removed["restart_required"] and removed["accounts_retained"], removed
    assert s.rpc("auth", op="exists", username="kept@tenant-159.example.net")["exists"]
    config = s.http("admin", "GET", "/api/admin/config", headers=administrator)[2]
    for values in ({"mail_domains": ["bypass.example"]}, {"additional_domains": ["bypass.example"]}, {"domain_registry": {}}, {"domain": "changed.example"}):
        assert s.http("admin", "POST", "/api/admin/config", dict(revision=config["revision"], values=values, apply=False), administrator)[0] == 400
    print("PASS API permissions, primary protection, retained accounts and lifecycle bypass rejection", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build" / "test-runs" / ("domains-" + secrets.token_hex(6))
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
