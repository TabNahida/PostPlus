"""Native supervisor selective apply, restart jobs and systemd restart intent."""
import argparse
from http.client import HTTPException
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import time
from unittest.mock import patch

from integration import PASSWORD, ROOT, Suite
from setup_integration import (NativeServer, assert_ports_closed, child_processes,
                               http, request_stop, reserve_ports, verify_services)

SERVICES = {"auth", "storage", "filter", "transfer", "delivery", "smtp", "pop3", "imap", "web", "admin"}


def browser(port, context=None):
    status, headers, session = http(port, "POST", "/api/login", {"username": "admin@localhost", "password": PASSWORD}, context=context)
    assert status == 200, (status, session)
    return {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": session["csrf"]}


def tls_context():
    context = ssl.create_default_context(cafile=str(ROOT / "tests/fixtures/localhost-test-only.crt"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def provision(binaries, directory, label="selective", environment=None, tls=False):
    directory.mkdir(parents=True, exist_ok=True)
    ports = reserve_ports()
    path = directory / "config/postplus.json"
    path.parent.mkdir()
    with patch.dict(os.environ, environment or {}):
        server = NativeServer(binaries, path, ports["admin"], directory, label, ROOT / "web")
    try:
        server.wait(server.setup_ready)
        setup = {"X-Setup-Token": server.token}
        status, _, defaults = http(ports["admin"], "GET", "/api/setup", headers=setup)
        assert status == 200 and defaults["defaults"]["ports"]["smtp"] == 25
        values = defaults["defaults"]
        values.update(domain="localhost", admin_username="admin@localhost", admin_password=PASSWORD,
                      data_dir=str(directory / "data"), ports=ports, allow_insecure_auth=True)
        context = tls_context() if tls else None
        if tls:
            values.update(allow_insecure_auth=False, tls_certificate=str(ROOT / "tests/fixtures/localhost-test-only.crt"),
                          tls_private_key=str(ROOT / "tests/fixtures/localhost-test-only.key"))
        status, _, result = http(ports["admin"], "POST", "/api/setup", values, setup)
        assert status == 200 and result["ok"], (status, result)
        config = json.loads(path.read_text())
        token = Path(config["service_token_file"]).read_text().strip()
        verify_services(server, ports, token, "admin@localhost", tls=context)
        owner = browser(ports["admin"], context)
        status, _, issued = http(ports["admin"], "POST", "/api/admin/api-keys", {"name": "Restart integration"}, owner, context=context)
        assert status == 201 and issued["ok"], (status, issued)
        return server, ports, path, token, owner, {"Authorization": "Bearer " + issued["key"]}
    except BaseException:
        server.close()
        raise


def pids(server):
    children = child_processes(server.process.pid)
    assert set(children) == {"postplus-" + name for name in SERVICES}, children
    return children


def assert_changed(before, after, expected):
    assert set(before) == set(after), (before, after)
    actual = {name.removeprefix("postplus-") for name in before if before[name] != after[name]}
    assert actual == set(expected), ("unexpected child restart plan", sorted(actual), sorted(expected))


def fresh_port(ports):
    while True:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            value = reservation.getsockname()[1]
        if value not in ports.values():
            return value


def rpc(port, token, **payload):
    status, _, result = http(port, "POST", "/rpc", payload, {"Authorization": "Bearer " + token})
    assert status == 200 and result["ok"], (status, result)
    return result


def configuration(ports, headers):
    status, _, result = http(ports["admin"], "GET", "/api/admin/config", headers=headers)
    assert status == 200 and result["ok"], (status, result)
    return result


def wait_job(server, ports, headers, job, *, state="complete", timeout=50, context=None):
    identifier = job["job_id"]
    assert identifier and job["state"] in ("pending", "running", "complete"), job
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        assert server.process.poll() is None, "supervisor exited during restart: " + "".join(server.lines[-15:])
        try:
            status, _, result = http(ports["admin"], "GET", "/api/admin/restart?job_id=" + identifier, headers=headers, context=context)
        except (OSError, HTTPException):
            time.sleep(0.05)
            continue
        assert status == 200 and result["ok"] and result["job_id"] == identifier, (status, result)
        assert result["state"] in ("pending", "running", "complete", "failed"), result
        if result["state"] in ("complete", "failed"):
            assert result["state"] == state, result
            assert set(result["services"]) == set(job["services"]), result
            return result
        time.sleep(0.05)
    raise AssertionError("restart job timed out: " + "".join(server.lines[-20:]))


def restart_job(result):
    # Configuration responses include normal save metadata alongside the job.
    job = result.get("restart", result)
    assert job["ok"] and job["job_id"] and job["state"] in ("pending", "running", "complete"), result
    assert isinstance(job["services"], list), result
    return job


def save(ports, headers, values, *, apply=True):
    view = configuration(ports, headers)
    body = {"revision": view["revision"], "values": values}
    if not apply:
        body["apply"] = False
    status, _, result = http(ports["admin"], "POST", "/api/admin/config", body, headers)
    assert status in (200, 202) and result["ok"], (status, result)
    return result


def apply_and_check(server, ports, headers, values, expected, *, updates=None):
    before = pids(server)
    job = restart_job(save(ports, headers, values))
    assert set(job["services"]) == set(expected), job
    if updates:
        ports.update(updates)
    result = wait_job(server, ports, headers, job)
    assert_changed(before, pids(server), expected)
    assert not configuration(ports, headers)["restart_required"], "completed settings remained pending"
    return result


def selective(binaries, directory):
    server, ports, path, token, owner, external = provision(binaries, directory)
    original_supervisor = server.process.pid
    try:
        token_file = Path(json.loads(path.read_text())["service_token_file"])
        original_token = token_file.read_bytes()
        status, web_headers, web_session = http(ports["web"], "POST", "/api/login", {"username": "admin@localhost", "password": PASSWORD})
        assert status == 200
        web_cookie = {"Cookie": web_headers["Set-Cookie"].split(";", 1)[0]}
        assert http(ports["admin"], "POST", "/api/admin/restart", {"mode": "changed"})[0] == 401
        assert http(ports["admin"], "POST", "/api/admin/restart", {"mode": "changed"}, {"Cookie": owner["Cookie"]})[0] == 403
        assert http(ports["admin"], "GET", "/api/admin/restart?job_id=unknown")[0] == 401
        assert http(ports["admin"], "GET", "/api/admin/restart?job_id=unknown", headers=external)[0] == 404
        assert http(ports["admin"], "POST", "/api/admin/restart", {"mode": "invalid"}, external)[0] == 400
        assert http(ports["web"], "POST", "/api/admin/restart", {"mode": "changed"}, web_cookie)[0] == 404
        sample = "Subject: selective restart\r\n\r\nRestartBlockedSentinel\r\n"
        assert rpc(ports["filter"], token, op="scan", raw=sample)["action"] == "accept"
        before = pids(server)
        job = restart_job(save(ports, owner, {"blocked_terms": ["RestartBlockedSentinel"]}))
        assert job["services"] == ["filter"], job
        # The accepted response must arrive before the delayed supervisor job
        # consumes the request. Its reservation serializes all maintenance.
        assert http(ports["admin"], "POST", "/api/admin/restart", {"mode": "changed"}, external)[0] == 409
        revision = configuration(ports, external)["revision"]
        assert http(ports["admin"], "POST", "/api/admin/config", {"revision": revision, "values": {"blocked_terms": ["Overlap must not persist"]}}, external)[0] == 409
        assert http(ports["admin"], "POST", "/api/admin/backup", {}, external)[0] == 409
        assert http(ports["admin"], "POST", "/api/admin/shutdown", {}, external)[0] == 409
        wait_job(server, ports, external, job)
        assert_changed(before, pids(server), {"filter"})
        assert rpc(ports["filter"], token, op="scan", raw=sample)["action"] == "reject"
        assert json.loads(path.read_text())["blocked_terms"] == ["RestartBlockedSentinel"]
        assert http(ports["admin"], "GET", "/api/session", headers=owner)[0] == 200
        assert http(ports["web"], "GET", "/api/session", headers=web_cookie)[0] == 200
        assert not configuration(ports, external)["restart_required"]
        print("PASS filter-only autoapply changes live behavior, preserves sessions and serializes overlapping jobs", flush=True)

        old_smtp, new_smtp = ports["smtp"], fresh_port(ports)
        apply_and_check(server, ports, external, {"ports": {"smtp": new_smtp}}, {"smtp"}, updates={"smtp": new_smtp})
        assert_ports_closed({"old_smtp": old_smtp})
        with socket.create_connection(("127.0.0.1", new_smtp), timeout=5) as connection:
            assert connection.recv(1024).startswith(b"220 ")
        apply_and_check(server, ports, external, {"smarthost_port": 2525}, {"transfer"})
        # Delivery constructs its transfer RPC deadline from these settings;
        # restart it with transfer so the worker cannot retain an old budget.
        apply_and_check(server, ports, external, {"smarthost_timeout_seconds": 41}, {"transfer", "delivery"})
        apply_and_check(server, ports, external, {"direct_timeout_seconds": 131}, {"transfer", "delivery"})
        apply_and_check(server, ports, external, {"max_web_sessions": 1536}, {"web", "admin"})
        assert http(ports["admin"], "GET", "/api/session", headers=owner)[0] == 401
        assert http(ports["web"], "GET", "/api/session", headers=web_cookie)[0] == 401
        assert token_file.read_bytes() == original_token
        old_admin, new_admin = ports["admin"], fresh_port(ports)
        admin_job = apply_and_check(server, ports, external, {"ports": {"admin": new_admin}}, {"admin"}, updates={"admin": new_admin})
        assert admin_job["admin_url"] == f"http://127.0.0.1:{new_admin}/"
        assert_ports_closed({"old_admin": old_admin})
        print("PASS SMTP-only, transfer-only and frontend-owned changes; old listeners close after accepted responses", flush=True)

        old_filter, new_filter = ports["filter"], fresh_port(ports)
        apply_and_check(server, ports, external, {"ports": {"filter": new_filter}}, {"filter", "delivery", "web"}, updates={"filter": new_filter})
        assert_ports_closed({"old_filter": old_filter})
        assert rpc(new_filter, token, op="scan", raw=sample)["action"] == "reject"
        old_auth, new_auth = ports["auth"], fresh_port(ports)
        apply_and_check(server, ports, external, {"ports": {"auth": new_auth}},
                        {"auth", "delivery", "smtp", "pop3", "imap", "web", "admin"}, updates={"auth": new_auth})
        assert_ports_closed({"old_auth": old_auth})
        assert rpc(new_auth, token, op="exists", username="admin@localhost")["exists"]
        apply_and_check(server, ports, external, {"max_connections": 24}, SERVICES)
        apply_and_check(server, ports, external, {"domain": "changed.example"}, SERVICES)
        assert server.process.pid == original_supervisor and server.process.poll() is None
        assert token_file.read_bytes() == original_token
        print("PASS internal RPC dependency closures, global/domain consumers and persistent API/service credentials", flush=True)

        before = pids(server)
        saved = save(ports, external, {"blocked_terms": ["RestartBlockedSentinel", "ManualStagedSentinel"]}, apply=False)
        assert saved["restart_required"]
        time.sleep(0.6)
        assert pids(server) == before
        assert configuration(ports, external)["restart_required"]
        assert rpc(ports["filter"], token, op="scan", raw="Subject: manual\r\n\r\nManualStagedSentinel\r\n")["action"] == "accept"
        status, _, restarted = http(ports["admin"], "POST", "/api/admin/restart", {"mode": "changed"}, external)
        assert status == 202 and restarted["ok"], (status, restarted)
        job = restart_job(restarted)
        assert job["services"] == ["filter"]
        wait_job(server, ports, external, job)
        assert_changed(before, pids(server), {"filter"})
        assert not configuration(ports, external)["restart_required"]
        # Direct edits do not silently stop a running process or bypass the
        # explicit restart gate, including a valid manual configuration change.
        before = pids(server)
        edited = json.loads(path.read_text())
        edited["blocked_terms"].append("ManualFileSentinel")
        path.write_text(json.dumps(edited), encoding="utf-8")
        time.sleep(0.6)
        assert pids(server) == before and configuration(ports, external)["restart_required"]
        assert rpc(ports["filter"], token, op="scan", raw="Subject: manual\r\n\r\nManualFileSentinel\r\n")["action"] == "accept"
        status, _, result = http(ports["admin"], "POST", "/api/admin/restart", {"mode": "changed"}, external)
        assert status == 202
        wait_job(server, ports, external, restart_job(result))
        assert_changed(before, pids(server), {"filter"})
        assert rpc(ports["filter"], token, op="scan", raw="Subject: manual\r\n\r\nManualFileSentinel\r\n")["action"] == "reject"
        print("PASS explicit staged saves and direct file edits remain pending until an authorized affected restart", flush=True)

        old_smtp, reserved_smtp = ports["smtp"], fresh_port(ports)
        before = pids(server)
        job = restart_job(save(ports, external, {"ports": {"smtp": reserved_smtp}}))
        # Inject contention after validation and after receiving the save
        # response, before the supervisor's 300ms not-before gate.
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", reserved_smtp))
            occupied.listen()
            failed = wait_job(server, ports, external, job, state="failed")
            assert failed.get("error"), failed
            assert_changed(before, pids(server), {"smtp"})
            assert configuration(ports, external)["restart_required"]
            with socket.create_connection(("127.0.0.1", old_smtp), timeout=5) as connection:
                assert connection.recv(1024).startswith(b"220 "), "failed restart did not restore the previous SMTP listener"
        assert_ports_closed({"failed_new_smtp": reserved_smtp})
        status, _, recovered = http(ports["admin"], "POST", "/api/admin/restart", {"mode": "changed"}, external)
        assert status == 202
        ports["smtp"] = reserved_smtp
        wait_job(server, ports, external, restart_job(recovered))
        assert_ports_closed({"old_smtp": old_smtp})
        assert not configuration(ports, external)["restart_required"]
        print("PASS failed apply rolls back live listeners, retains pending settings and can be retried", flush=True)

        before = pids(server)
        status, _, full = http(ports["admin"], "POST", "/api/admin/restart", {"mode": "all"}, external)
        assert status == 202
        job = restart_job(full)
        assert set(job["services"]) == SERVICES
        wait_job(server, ports, external, job)
        assert_changed(before, pids(server), SERVICES)
        assert server.process.pid == original_supervisor
        logs = "".join(server.lines)
        assert external["Authorization"][7:] not in logs and token not in logs
        request_stop(server.process.pid)
        assert server.process.wait(timeout=45) == 0
        assert_ports_closed(ports)
        print("PASS full child-group restart keeps the native launcher and durable credentials; normal shutdown exits zero", flush=True)
    finally:
        server.close()


def standalone(binaries, directory):
    directory.mkdir(parents=True)
    suite = Suite(binaries, directory)
    try:
        suite.start("auth")
        suite.start("admin")
        assert suite.rpc("auth", op="create", username="admin@localhost", password=PASSWORD, admin=True)["ok"]
        owner = browser(suite.ports["admin"])
        before = {name: child.pid for name, child in suite.children.items()}
        saved = save(suite.ports, owner, {"blocked_terms": ["standalone staged"]})
        assert saved["restart_required"], saved
        assert configuration(suite.ports, owner)["restart_required"]
        assert {name: child.pid for name, child in suite.children.items()} == before
        status, _, result = suite.http("admin", "POST", "/api/admin/restart", {"mode": "changed"}, owner)
        assert status == 503 and not result["ok"], (status, result)
        print("PASS standalone service saves remain manual and do not claim an unavailable native restart succeeded", flush=True)
    finally:
        suite.close()


def managed_restart(binaries, directory):
    server, ports, path, token, owner, external = provision(binaries, directory, "managed", {"POSTPLUS_SERVICE_MANAGER": "systemd"})
    try:
        # This isolated manager marker exercises the process exit protocol; it
        # never calls systemctl or alters a real host service.
        status, _, result = http(ports["admin"], "POST", "/api/admin/restart", {"mode": "all"}, external)
        assert status == 202 and result["ok"], (status, result)
        assert set(restart_job(result)["services"]) == SERVICES
        assert server.process.wait(timeout=45) == 75, "managed full restart did not emit the dedicated restart intent"
        assert_ports_closed(ports)
    finally:
        server.close()
    with patch.dict(os.environ, {"POSTPLUS_SERVICE_MANAGER": "systemd"}):
        resumed = NativeServer(binaries, path, ports["admin"], directory, "managed-resumed")
    try:
        resumed.wait(resumed.services_ready)
        assert http(ports["admin"], "GET", "/api/admin/users", headers=external)[0] == 200
        status, _, completed = http(ports["admin"], "GET", "/api/admin/restart?job_id=" + result["job_id"], headers=external)
        assert status == 200 and completed["state"] == "complete", (status, completed)
        status, _, result = http(ports["admin"], "POST", "/api/admin/shutdown", {}, external)
        assert status == 202 and result["state"] == "shutting_down"
        assert resumed.process.wait(timeout=45) == 0, "normal managed shutdown requested an automatic restart"
        assert_ports_closed(ports)
    finally:
        resumed.close()
    if sys.platform.startswith("linux"):
        preview = subprocess.run(["bash", str(ROOT / "scripts/install-systemd.sh"), "--install-dir", str(binaries),
                                  "--working-dir", str(directory), "--config", str(path), "--dry-run"],
                                 capture_output=True, text=True, timeout=20, check=True)
        assert "Restart=on-failure" in preview.stdout and "RestartForceExitStatus=75" in preview.stdout
        assert "POSTPLUS_SERVICE_MANAGER=systemd" in preview.stdout
        assert "Restart=always" not in preview.stdout
    print("PASS managed full restart exits 75, relaunch preserves keys and ordinary managed shutdown exits zero", flush=True)


def managed_preflight_failure(binaries, directory):
    environment = {"POSTPLUS_SERVICE_MANAGER": "systemd"}
    server, ports, path, token, owner, external = provision(binaries, directory, "managed-failure", environment)
    try:
        status, _, job = http(ports["admin"], "POST", "/api/admin/restart", {"mode": "all"}, external)
        assert status == 202, (status, job)
        assert server.process.wait(timeout=45) == 75
        assert_ports_closed(ports)
    finally:
        server.close()
    state_directory = directory / "data/.restart-state"
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", ports["smtp"]))
        occupied.listen()
        with patch.dict(os.environ, environment):
            failed = NativeServer(binaries, path, ports["admin"], directory, "managed-preflight-failed")
        try:
            assert failed.process.wait(timeout=20) == 1
            state = json.loads((state_directory / "latest.json").read_text())
            assert state["job_id"] == job["job_id"] and state["state"] == "failed", state
            assert state.get("error") and not (state_directory / "reservation").exists(), state
            assert child_processes(failed.process.pid) == {}
        finally:
            failed.close()
    with patch.dict(os.environ, environment):
        recovered = NativeServer(binaries, path, ports["admin"], directory, "managed-preflight-recovered")
    try:
        recovered.wait(recovered.services_ready)
        status, _, state = http(ports["admin"], "GET", "/api/admin/restart?job_id=" + job["job_id"], headers=external)
        assert status == 200 and state["state"] == "failed", (status, state)
        assert http(ports["admin"], "POST", "/api/admin/shutdown", {}, external)[0] == 202
        assert recovered.process.wait(timeout=45) == 0
        assert_ports_closed(ports)
    finally:
        recovered.close()
    print("PASS manager relaunch port preflight failure persists an actionable failed job without stale reservations", flush=True)


def tls_restart(binaries, directory):
    server, ports, path, token, owner, external = provision(binaries, directory, "tls", tls=True)
    context = tls_context()
    try:
        assert http(ports["web"], "GET", "/health", context=context)[2] == {"ok": True, "service": "web"}
        assert http(ports["admin"], "GET", "/health", context=context)[2] == {"ok": True, "service": "admin"}
        before = pids(server)
        status, _, view = http(ports["admin"], "GET", "/api/admin/config", headers=external, context=context)
        assert status == 200
        status, _, result = http(ports["admin"], "POST", "/api/admin/config",
                                {"revision": view["revision"], "values": {"web_session_seconds": 5400}}, external, context=context)
        assert status == 200
        job = restart_job(result)
        assert set(job["services"]) == {"web", "admin"}
        wait_job(server, ports, external, job, context=context)
        assert_changed(before, pids(server), {"web", "admin"})
        assert http(ports["admin"], "GET", "/api/admin/users", headers=external, context=context)[0] == 200
        assert http(ports["web"], "GET", "/health", context=context)[0] == 200
        assert http(ports["admin"], "GET", "/health", context=context)[0] == 200
        assert http(ports["admin"], "GET", "/api/session", headers=owner, context=context)[0] == 401
        request_stop(server.process.pid)
        assert server.process.wait(timeout=45) == 0
        assert_ports_closed(ports)
        print("PASS native HTTPS launch and selective frontend restart verify health with a private certificate", flush=True)
    finally:
        server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    binaries = args.bin_dir.resolve()
    directory = ROOT / "build/test-runs" / ("restart-" + secrets.token_hex(6))
    selective(binaries, directory / "selective")
    standalone(binaries, directory / "standalone")
    managed_restart(binaries, directory / "managed")
    managed_preflight_failure(binaries, directory / "managed-failure")
    tls_restart(binaries, directory / "tls")
