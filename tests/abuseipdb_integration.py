#!/usr/bin/env python3
"""Private AbuseIPDB settings, scoped tools and public verification without live API calls."""
import argparse
import json
from pathlib import Path
import secrets

from integration import PASSWORD, ROOT, Suite


def run(s):
    for service in ("auth", "storage", "web", "admin"):
        s.start(service)
    admin, user = "abuse-admin@localhost", "abuse-user@localhost"
    for username in (admin, user):
        assert s.rpc("auth", op="create", username=username, password=PASSWORD, admin=username == admin)["ok"]
    assert not s.rpc("auth", op="abuseipdb_get", actor=user)["ok"]
    assert s.http("admin", "GET", "/api/admin/abuseipdb")[0] == 401
    status, headers, login = s.http("admin", "POST", "/api/login", {"username": admin, "password": PASSWORD})
    assert status == 200
    session = {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": login["csrf"]}

    def request(method="GET", suffix="", body=None, headers=None):
        return s.http("admin", method, "/api/admin/abuseipdb" + suffix, body, session if headers is None else headers)

    status, _, initial = request()
    assert status == 200 and initial["revision"] == 1 and not initial["settings"]["enabled"]
    assert not initial["api_key_configured"] and len(initial["quotas"]) == 8
    assert all(row["limit"] is None and row["used"] is None for row in initial["quotas"])
    assert all("api_key" not in row for row in (initial, initial["settings"]))
    assert s.http("web", "GET", "/abuseipdb-verification.html")[0] == 404
    secret = "private-abuse-test-secret-never-return"
    token = "abuseipdb-verification-PostPlusTest_2026"
    patch = {"revision": initial["revision"], "settings": {"api_key": secret, "api_key_env": "", "verification_token": token}}
    assert request("PUT", "/settings", patch, {"Cookie": session["Cookie"]})[0] == 403
    status, _, saved = request("PUT", "/settings", patch)
    assert status == 200 and saved["api_key_configured"] and saved["revision"] == 2, saved
    assert secret not in json.dumps(saved)
    assert request("PUT", "/settings", patch)[0] == 409
    assert request("PUT", "/settings", {"revision": 2, "settings": {"score_threshold": True}})[0] == 400
    assert request("PUT", "/settings", {"revision": 2, "settings": {"api_key": "bad\r\nInjected: true"}})[0] == 400
    assert request("PUT", "/settings", {"revision": 2, "settings": {"verification_token": "<script>bad</script>"}})[0] == 400
    # These tools validate before they could reach the network. Disabled state
    # also guarantees that synthetic reports never leave the test machine.
    for suffix, payload in (("/check", {"ipAddress": "127.0.0.1"}),
                            ("/report", {"ip": "8.8.8.8", "categories": [99], "comment": "test"}),
                            ("/bulk-check", {"ips": ["hostname.example"]}),
                            ("/unknown", {})):
        assert request("POST", suffix, payload)[0] == 400
    status, _, result = request("POST", "/check", {"ipAddress": "8.8.8.8"})
    assert status == 400 and result["code"] == "abuseipdb_not_configured"
    for service in ("web", "admin"):
        status, headers, body = s.http(service, "GET", "/abuseipdb-verification.html")
        assert status == 200 and body.decode().strip() == token, (status, body)
        assert "text/html" in headers["Content-Type"] and headers["Cache-Control"] == "no-store"
    readonly = s.rpc("auth", op="api_key_create", username=admin, name="Abuse read", permissions=["security:read"])["key"]
    writer = s.rpc("auth", op="api_key_create", username=admin, name="Abuse write", permissions=["security:write"])["key"]
    ro, rw = {"Authorization": "Bearer " + readonly}, {"Authorization": "Bearer " + writer}
    assert request(headers=ro)[0] == 200
    assert request(headers=rw)[0] == 403
    assert request("POST", "/check", {"ipAddress": "8.8.8.8"}, ro)[2]["code"] == "abuseipdb_not_configured"
    assert request("POST", "/clear-address", {"ipAddress": "8.8.8.8"}, ro)[0] == 403
    assert request("PUT", "/settings", {"revision": 2, "settings": {}}, ro)[0] == 403
    assert s.http("web", "GET", "/api/admin/abuseipdb", headers=session)[0] == 404
    s.stop("auth"); s.start("auth")
    status, _, loaded = request()
    assert status == 200 and loaded["api_key_configured"] and loaded["settings"]["verification_token"] == token
    assert loaded["revision"] == 2 and secret not in json.dumps(loaded)
    status, _, cleared = request("PUT", "/settings", {"revision": 2, "settings": {"clear_api_key": True, "verification_token": ""}})
    assert status == 200 and not cleared["api_key_configured"]
    assert s.http("web", "GET", "/abuseipdb-verification.html")[0] == 404
    logs = "\n".join(path.read_text(encoding="utf-8") for path in (s.directory / "data/logs").glob("auth.jsonl*"))
    assert secret not in logs
    print("PASS AbuseIPDB private settings, revision conflicts, CSRF, scoped tools, public webmaster file and restart persistence", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("abuseipdb-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    finally:
        suite.close()
