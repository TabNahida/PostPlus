#!/usr/bin/env python3
"""Offline native update API, selective readiness and launcher recovery tests.

Every scenario copies the complete binary directory and web assets into a
private installation. The staged jobs are constructed locally; this suite never
calls a release check or a valid download endpoint and needs no GitHub access.
"""
import argparse
import ctypes
import hashlib
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
from unittest.mock import patch

import restart_integration as restart
from integration import PASSWORD, ROOT
from setup_integration import (NativeServer, assert_ports_closed, child_processes,
                               http, kill_test_child, request_stop, windows_kernel)

_version_match = re.search(r'^set_version\("(\d+)\.(\d+)\.(\d+)"\)',
                           (ROOT / "xmake.lua").read_text(encoding="utf-8"), re.MULTILINE)
assert _version_match, "cannot find the project version for the update fixture"
BASE_VERSION = ".".join(_version_match.groups())
_major, _minor, _patch = map(int, _version_match.groups())
VERSION = f"{_major}.{_minor}.{_patch + 1}"
SUFFIX = ".exe" if os.name == "nt" else ""
SERVICES = restart.SERVICES


def sha(value):
    return hashlib.sha256(value).hexdigest()


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def private_directory(path):
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)


def private_write(path, contents):
    path.write_bytes(contents)
    if os.name != "nt":
        path.chmod(0o600)


def write_json(path, value):
    private_write(path, json.dumps(value).encode("utf-8"))


def native_name(name):
    return "postplus" + ("-" + name if name else "") + SUFFIX


def installation_hashes(install):
    return {item.relative_to(install).as_posix(): file_hash(item)
            for item in install.rglob("*") if item.is_file()}


def assert_install_changes(before, install, expected):
    after = installation_hashes(install)
    changed = {name for name in before.keys() | after.keys()
               if before.get(name) != after.get(name)}
    assert changed == set(expected), ("unexpected installed file changes", changed, expected)


def normalized_image(path):
    return os.path.normcase(os.path.abspath(path))


def owned_processes(install, update_directory):
    """Select only images in this test's copied installation or private jobs.

    A Windows takeover launches a detached supervisor after the original Popen
    exits. Image paths, rather than names or stale parent IDs, retain ownership.
    """
    rows = []
    if os.name == "nt":
        from ctypes import wintypes as w

        class Entry(ctypes.Structure):
            _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("pid", w.DWORD),
                        ("heap", ctypes.c_size_t), ("module", w.DWORD), ("threads", w.DWORD),
                        ("parent", w.DWORD), ("priority", w.LONG), ("flags", w.DWORD),
                        ("name", w.WCHAR * 260)]

        kernel = windows_kernel()
        kernel.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
        kernel.CreateToolhelp32Snapshot.restype = w.HANDLE
        kernel.Process32FirstW.argtypes = [w.HANDLE, ctypes.POINTER(Entry)]
        kernel.Process32NextW.argtypes = [w.HANDLE, ctypes.POINTER(Entry)]
        kernel.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD)]
        kernel.QueryFullProcessImageNameW.restype = w.BOOL
        snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
        assert snapshot != ctypes.c_void_p(-1).value, "cannot enumerate test-owned images"
        try:
            entry = Entry()
            entry.size = ctypes.sizeof(entry)
            present = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
            while present:
                if entry.name.startswith("postplus"):
                    process = kernel.OpenProcess(0x1000, False, entry.pid)
                    if process:
                        try:
                            size, image = w.DWORD(32768), ctypes.create_unicode_buffer(32768)
                            if kernel.QueryFullProcessImageNameW(process, 0, image, ctypes.byref(size)):
                                rows.append((entry.pid, image.value))
                        finally:
                            kernel.CloseHandle(process)
                present = kernel.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel.CloseHandle(snapshot)
    elif sys.platform.startswith("linux"):
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                image = os.readlink(entry / "exe").removesuffix(" (deleted)")
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            rows.append((int(entry.name), image))
    else:
        output = subprocess.check_output(["ps", "-axo", "pid=,comm="], text=True)
        for row in output.splitlines():
            fields = row.strip().split(None, 1)
            if len(fields) == 2:
                rows.append((int(fields[0]), fields[1]))

    install = normalized_image(install)
    updates = normalized_image(update_directory)
    result = {}
    for pid, image in rows:
        path = normalized_image(image)
        parent, name = os.path.dirname(path), os.path.basename(path)
        installed = parent == install and (name == native_name("") or name.startswith("postplus-"))
        private_helper = (name == native_name("update") and
                          os.path.dirname(os.path.dirname(path)) == updates)
        if installed or private_helper:
            result[pid] = path
    return result


class Installation:
    def __init__(self, binaries, directory, *, managed=False):
        self.directory = directory.resolve()
        self.directory.mkdir(parents=True)
        self.install = self.directory / "install"
        shutil.copytree(binaries, self.install)
        shutil.copytree(ROOT / "web", self.install / "web", dirs_exist_ok=True)
        self.web = self.install / "web"
        self.updates = self.directory / "data/.updates"
        self.state = self.directory / "data/.restart-state"
        self.servers = []
        self.environment = {"POSTPLUS_SERVICE_MANAGER": "systemd" if managed else ""}
        # A known installed baseline makes failed commit/launcher recovery
        # assertions independent of release packaging files in the build tree.
        self.baseline = {"schema": 1, "repository": "TabNahida/PostPlus", "version": BASE_VERSION, "files": []}
        write_json(self.install / "postplus-update.json", self.baseline)
        try:
            with patch.object(restart, "ROOT", self.install):
                values = restart.provision(self.install, self.directory, "initial", self.environment)
            self.server, self.ports, self.path, self.token, self.owner, self.external = values
            self.servers.append(self.server)
            # Explicitly check the saved value: updating a copied executable
            # must never modify the repository's original web directory.
            config = json.loads(self.path.read_text())
            if normalized_image(config.get("web_root", "")) != normalized_image(self.web):
                restart.apply_and_check(self.server, self.ports, self.external,
                                        {"web_root": str(self.web)}, {"web", "admin"})
                self.owner = restart.browser(self.ports["admin"])
                config = json.loads(self.path.read_text())
            assert normalized_image(config["web_root"]) == normalized_image(self.web), config["web_root"]
            self.config_bytes = self.path.read_bytes()
            self.token_file = Path(config["service_token_file"])
            self.token_bytes = self.token_file.read_bytes()
            self.sentinel = self.directory / "data/update-preservation-sentinel.dat"
            private_write(self.sentinel, b"private update integration sentinel\x00\xff")
        except BaseException:
            self.close()
            raise

    def stage(self, replacements, services, *, launcher=False):
        identifier = secrets.token_hex(16)
        private_directory(self.updates)
        directory = self.updates / identifier
        for item in (directory, directory / "modules", directory / "backup"):
            private_directory(item)
        files = []
        for path, value in replacements.items():
            target = self.web / path[4:] if path.startswith("web/") else self.install / path
            original = target.read_bytes()
            file_id = sha(path.encode("utf-8"))
            private_write(directory / "modules" / file_id, value)
            files.append({"path": path, "id": file_id, "old_sha256": sha(original),
                          "sha256": sha(value), "fingerprint": sha(value), "size": len(value),
                          "executable": not path.startswith("web/")})
        job = {"ok": True, "schema": 1, "job_id": identifier, "state": "staged", "version": VERSION,
               "install_directory": str(self.install), "web_directory": str(self.web),
               "files": files, "services": sorted(services), "requires_launcher_restart": launcher,
               "download_bytes": sum(item["size"] for item in files),
               "downloaded_bytes": sum(item["size"] for item in files),
               "installation_manifest": {"schema": 1, "repository": "TabNahida/PostPlus", "version": VERSION,
                                         "files": [{key: value for key, value in item.items()
                                                    if key not in ("id", "old_sha256")} for item in files]}}
        write_json(directory / "job.json", job)
        public = {key: value for key, value in job.items()
                  if key not in ("install_directory", "web_directory", "installation_manifest")}
        write_json(self.state / "update.json", public)
        status, _, view = http(self.ports["admin"], "GET", "/api/admin/update?job_id=" + identifier,
                               headers=self.external)
        assert status == 200 and view["state"] == "staged" and view["available"], (status, view)
        return job, directory

    def apply(self, job, *, headers=None):
        status, _, result = http(self.ports["admin"], "POST", "/api/admin/update/apply",
                                 {"job_id": job["job_id"]}, headers or self.external)
        assert status == 202 and result["ok"] and result["state"] == "pending_apply", (status, result)
        assert result["job_id"] == job["job_id"] and set(result["services"]) == set(job["services"]), result
        return result

    def wait_job(self, job, *, expected="complete", timeout=150, running=None):
        deadline = time.monotonic() + timeout
        result = None
        while time.monotonic() < deadline:
            if running is not None:
                assert running.process.poll() is None, "supervisor exited during update: " + "".join(running.lines[-15:])
            try:
                status, _, result = http(self.ports["admin"], "GET", "/api/admin/update?job_id=" + job["job_id"],
                                         headers=self.external)
            except (OSError, HTTPException):
                time.sleep(0.05)
                continue
            if status in (404, 503):
                # A replacement admin listener can answer before the new
                # supervisor publishes its all-services-ready capability.
                time.sleep(0.05)
                continue
            assert status == 200 and result["ok"] and result["job_id"] == job["job_id"], (status, result)
            assert result["state"] in ("staged", "pending_apply", "applying", "complete", "failed"), result
            if result["state"] in ("complete", "failed"):
                assert result["state"] == expected, result
                if "services" in result:
                    assert set(result["services"]) == set(job["services"]), result
                # update_finished atomically publishes the terminal status,
                # then removes its reservation. A reader can observe the
                # published file between those two filesystem operations.
                # Wait briefly for that final cleanup, while still failing
                # explicitly if a completed job leaves maintenance locked.
                cleanup_deadline = min(deadline, time.monotonic() + 5)
                while (self.state / "reservation").exists():
                    if running is not None:
                        assert running.process.poll() is None, "supervisor exited while releasing the update reservation"
                    assert time.monotonic() < cleanup_deadline, (
                        "terminal update left its maintenance reservation", result)
                    time.sleep(0.01)
                return result
            time.sleep(0.05)
        diagnostics = "".join(line for server in self.servers for line in server.lines[-20:])
        launcher_log = self.updates / job["job_id"] / "launcher.log"
        if launcher_log.exists():
            diagnostics += launcher_log.read_text(encoding="utf-8", errors="replace")[-12000:]
        raise AssertionError(f"update job timed out: {result}\n{diagnostics}")

    def credentials_preserved(self):
        assert self.path.read_bytes() == self.config_bytes, "update changed configuration"
        assert self.token_file.read_bytes() == self.token_bytes, "update changed persistent service credentials"
        assert self.sentinel.read_bytes() == b"private update integration sentinel\x00\xff", "update changed unrelated private data"
        assert http(self.ports["admin"], "GET", "/api/admin/users", headers=self.external)[0] == 200
        assert not restart.configuration(self.ports, self.external)["restart_required"]

    def resume(self, label):
        with patch.dict(os.environ, self.environment):
            server = NativeServer(self.install, self.path, self.ports["admin"], self.directory, label)
        self.servers.append(server)
        return server

    def launcher_pid(self):
        owned = owned_processes(self.install, self.updates)
        launchers = [pid for pid, image in owned.items()
                     if image == normalized_image(self.install / native_name(""))]
        assert len(launchers) == 1, ("expected one test-owned launcher", owned)
        return launchers[0]

    def close(self):
        # Stop a private helper first on an assertion failure, so it cannot
        # create a replacement supervisor while the test is cleaning up.
        current = owned_processes(self.install, self.updates)
        for pid, image in current.items():
            if os.path.basename(image) == native_name("update"):
                if pid in owned_processes(self.install, self.updates):
                    try:
                        kill_test_child(pid)
                    except (AssertionError, OSError):
                        pass
        for pid, image in owned_processes(self.install, self.updates).items():
            if image == normalized_image(self.install / native_name("")):
                try:
                    request_stop(pid)
                except (AssertionError, OSError):
                    pass
        for server in self.servers:
            server.close()
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline and owned_processes(self.install, self.updates):
            time.sleep(0.05)
        for pid in owned_processes(self.install, self.updates):
            if pid in owned_processes(self.install, self.updates):
                try:
                    kill_test_child(pid)
                except (AssertionError, OSError):
                    pass
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and owned_processes(self.install, self.updates):
            time.sleep(0.05)
        assert not owned_processes(self.install, self.updates), "test-owned update processes survived cleanup"
        if hasattr(self, "ports"):
            assert_ports_closed(self.ports)


def service_pids(pid):
    values = child_processes(pid)
    assert set(values) == {"postplus-" + name for name in SERVICES}, values
    return values


def process_identity(pid):
    """Include process birth time: operating systems can reuse an exited PID."""
    if os.name == "nt":
        from ctypes import wintypes as w

        kernel = windows_kernel()
        kernel.GetProcessTimes.argtypes = [w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4
        kernel.GetProcessTimes.restype = w.BOOL
        process = kernel.OpenProcess(0x1000, False, pid)
        assert process, ("cannot query service process", pid, ctypes.get_last_error())
        try:
            created, exited, system, user = (w.FILETIME() for _ in range(4))
            ok = kernel.GetProcessTimes(process, ctypes.byref(created), ctypes.byref(exited),
                                        ctypes.byref(system), ctypes.byref(user))
            assert ok, ("cannot query service creation time", pid, ctypes.get_last_error())
            started = (created.dwHighDateTime << 32) | created.dwLowDateTime
        finally:
            kernel.CloseHandle(process)
    elif sys.platform.startswith("linux"):
        # The command name can itself contain spaces or parentheses. Field 22
        # is the start time in ticks since boot, following the final ')'.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        started = int(fields[19])
    else:
        started = subprocess.check_output(["ps", "-p", str(pid), "-o", "lstart="], text=True).strip()
        assert started, ("cannot query service creation time", pid)
    return pid, started


def service_identities(pid):
    return {name: process_identity(child) for name, child in service_pids(pid).items()}


def verify_restart_identities():
    # The same numeric PID may pass from delivery to web, or even be reused
    # by the same service. Both are restarts when the birth time changes.
    before = {"postplus-delivery": (688, 100), "postplus-web": (404, 200)}
    restart.assert_changed(before, {"postplus-delivery": (800, 300), "postplus-web": (688, 400)},
                           {"delivery", "web"})
    restart.assert_changed(before, {"postplus-delivery": (688, 300), "postplus-web": (404, 400)},
                           {"delivery", "web"})
    try:
        restart.assert_changed(before, {"postplus-delivery": (800, 300), "postplus-web": before["postplus-web"]},
                               {"delivery", "web"})
    except AssertionError:
        pass
    else:
        raise AssertionError("restart verification accepted a service that never restarted")
    identity = process_identity(os.getpid())
    assert identity[0] == os.getpid() and process_identity(os.getpid()) == identity
    print("PASS update restart identities accept PID reuse and reject unchanged processes", flush=True)


def live_services(installation):
    for service, greeting in (("smtp", b"220 "), ("pop3", b"+OK"), ("imap", b"* OK")):
        with socket.create_connection(("127.0.0.1", installation.ports[service]), timeout=5) as connection:
            assert connection.recv(1024).startswith(greeting), service
    for service in ("web", "admin"):
        assert http(installation.ports[service], "GET", "/health")[2] == {"ok": True, "service": service}
    assert restart.rpc(installation.ports["auth"], installation.token,
                       op="exists", username="admin@localhost")["exists"]


def auth_contract(installation):
    port, owner, external = installation.ports["admin"], installation.owner, installation.external
    unknown = "0" * 32
    assert http(port, "GET", "/api/admin/update")[0] == 401
    assert http(port, "POST", "/api/admin/update/apply", {"job_id": unknown})[0] == 401
    assert http(port, "POST", "/api/admin/update/apply", {"job_id": unknown}, {"Cookie": owner["Cookie"]})[0] == 403
    status, _, state = http(port, "GET", "/api/admin/update", headers=external)
    assert status == 200 and state["ok"] and state["available"] and state["state"] == "idle", (status, state)
    assert http(port, "GET", "/api/admin/update?job_id=" + unknown, headers=external)[0] == 404
    assert http(port, "POST", "/api/admin/update/apply", {"job_id": unknown}, external)[0] == 409
    # Both bodies fail before any release inspection/download can start.
    assert http(port, "POST", "/api/admin/update/check", {"url": "https://invalid.example/"}, external)[0] == 400
    assert http(port, "POST", "/api/admin/update/stage", {"version": VERSION, "url": "https://invalid.example/"}, external)[0] == 400
    restart.rpc(installation.ports["auth"], installation.token, op="create", username="update-user@localhost",
                password=PASSWORD, admin=False)
    status, user_headers, user_session = http(port, "POST", "/api/login",
                                              {"username": "update-user@localhost", "password": PASSWORD})
    assert status == 403, (status, user_session)
    status, user_headers, user_session = http(installation.ports["web"], "POST", "/api/login",
                                              {"username": "update-user@localhost", "password": PASSWORD})
    assert status == 200, (status, user_session)
    user_owner = {"Cookie": user_headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": user_session["csrf"]}
    assert http(installation.ports["web"], "GET", "/api/admin/update", headers=user_owner)[0] == 404
    status, headers, _ = http(installation.ports["web"], "POST", "/api/login",
                              {"username": "admin@localhost", "password": PASSWORD})
    assert status == 200
    web_cookie = {"Cookie": headers["Set-Cookie"].split(";", 1)[0]}
    assert http(installation.ports["web"], "GET", "/api/admin/update", headers=web_cookie)[0] == 404
    assert http(installation.ports["web"], "POST", "/api/admin/update/apply", {"job_id": unknown}, web_cookie)[0] == 404
    print("PASS update API administrator authentication, CSRF and admin-only routing without release network access", flush=True)


def selective_updates(binaries, directory):
    installation = Installation(binaries, directory)
    try:
        auth_contract(installation)
        server, ports = installation.server, installation.ports
        original_launcher = server.process.pid
        smtp = native_name("smtp")
        before = installation_hashes(installation.install)
        original = (installation.install / smtp).read_bytes()
        changed = original + b"\nPostPlus offline SMTP update integration overlay\n"
        pids_before = service_identities(server.process.pid)
        job, job_directory = installation.stage({smtp: changed}, {"smtp"})
        # Downloaded/staged metadata alone cannot mutate running modules.
        assert service_identities(server.process.pid) == pids_before and (installation.install / smtp).read_bytes() == original
        assert http(ports["admin"], "POST", "/api/admin/update/apply", {"job_id": job["job_id"]},
                    {"Cookie": installation.owner["Cookie"]})[0] == 403
        # Real runtime changes must still block both download and installation;
        # persisted DNS verification records must not require a restart first.
        saved = json.loads(installation.path.read_text())
        pending = dict(saved, blocked_terms=["UnappliedUpdateSentinel"])
        write_json(installation.path, pending)
        assert restart.configuration(ports, installation.external)["restart_required"]
        assert http(ports["admin"], "POST", "/api/admin/update/stage", {"version": VERSION}, installation.external)[0] == 409
        assert http(ports["admin"], "POST", "/api/admin/update/apply", {"job_id": job["job_id"]}, installation.external)[0] == 409
        assert service_identities(server.process.pid) == pids_before
        saved.setdefault("domain_registry", {}).setdefault("localhost", {"status": "active"})["dns"] = {
            "checked_at": "2026-10-23T12:00:00Z", "ready": False, "status": "incomplete"}
        write_json(installation.path, saved)
        installation.config_bytes = installation.path.read_bytes()
        assert not restart.configuration(ports, installation.external)["restart_required"]
        installation.apply(job, headers=installation.owner)
        assert http(ports["admin"], "POST", "/api/admin/restart", {"mode": "all"}, installation.external)[0] == 409
        assert http(ports["admin"], "POST", "/api/admin/update/apply", {"job_id": job["job_id"]}, installation.external)[0] == 409
        result = installation.wait_job(job, running=server)
        assert result["current_version"] == VERSION, result
        restart.assert_changed(pids_before, service_identities(server.process.pid), {"smtp"})
        assert server.process.pid == original_launcher and server.process.poll() is None
        assert (installation.install / smtp).read_bytes() == changed
        assert (job_directory / "backup" / sha(smtp.encode())).read_bytes() == original
        assert_install_changes(before, installation.install, {smtp, "postplus-update.json"})
        installation.credentials_preserved()
        live_services(installation)
        assert http(ports["admin"], "GET", "/api/session", headers=installation.owner)[0] == 200
        print("PASS staged SMTP module update changes only SMTP PID and module, preserving configuration and credentials", flush=True)

        before = installation_hashes(installation.install)
        pids_before = service_identities(server.process.pid)
        web_path = "web/style.css"
        web_body = (installation.web / "style.css").read_bytes() + b"\n/* offline web update sentinel */\n"
        job, _ = installation.stage({web_path: web_body}, {"web", "admin"})
        installation.apply(job)
        installation.wait_job(job, running=server)
        restart.assert_changed(pids_before, service_identities(server.process.pid), {"web", "admin"})
        assert http(ports["web"], "GET", "/style.css")[2] == web_body
        assert http(ports["admin"], "GET", "/style.css")[2] == web_body
        assert http(ports["admin"], "GET", "/api/session", headers=installation.owner)[0] == 401
        assert_install_changes(before, installation.install, {web_path, "postplus-update.json"})
        installation.credentials_preserved()
        live_services(installation)
        print("PASS copied web asset update refreshes web/admin only and persistent administrator API key reconnects", flush=True)

        before = installation_hashes(installation.install)
        pids_before = service_identities(server.process.pid)
        original = (installation.install / smtp).read_bytes()
        manifest = (installation.install / "postplus-update.json").read_bytes()
        job, job_directory = installation.stage({smtp: b"invalid service executable for readiness rollback\n"}, {"smtp"})
        installation.apply(job)
        failed = installation.wait_job(job, expected="failed", running=server)
        assert failed["rolled_back"] and failed.get("error"), failed
        restart.assert_changed(pids_before, service_identities(server.process.pid), {"smtp"})
        assert (installation.install / smtp).read_bytes() == original
        assert (installation.install / "postplus-update.json").read_bytes() == manifest
        assert (job_directory / "backup" / sha(smtp.encode())).read_bytes() == original
        assert_install_changes(before, installation.install, set())
        installation.credentials_preserved()
        live_services(installation)
        assert not (installation.state / "reservation").exists()
        assert server.process.poll() is None
        print("PASS invalid service executable readiness restores module/listener and baseline metadata without restarting unrelated services", flush=True)
    finally:
        installation.close()


def launcher_update(binaries, directory, *, failure=False):
    installation = Installation(binaries, directory, managed=os.name != "nt")
    try:
        server = installation.server
        old_pid = server.process.pid
        before = installation_hashes(installation.install)
        old_children = service_identities(server.process.pid)
        launcher = native_name("")
        original_launcher = (installation.install / launcher).read_bytes()
        replacements = {launcher: original_launcher + b"\nPostPlus offline launcher update integration overlay\n"}
        if failure:
            # The updated launcher is valid and starts; one installed service
            # cannot become ready, so takeover must restore the complete job.
            replacements[native_name("smtp")] = b"invalid service in launcher readiness recovery\n"
        job, job_directory = installation.stage(replacements, SERVICES, launcher=True)
        installation.apply(job)
        assert server.process.wait(timeout=60) == (0 if os.name == "nt" else 75)
        if os.name == "nt":
            result = installation.wait_job(job, expected="failed" if failure else "complete")
            new_pid = installation.launcher_pid()
            assert new_pid != old_pid
            assert (job_directory / "takeover.ready").exists()
            assert (job_directory / native_name("update")).is_file(), "takeover did not use a private helper"
            assert (job_directory / "launcher.log").is_file(), "detached startup output was not captured"
        else:
            # A fake systemd marker exercises exit 75 only. The Python driver
            # acts as the manager; no host service or systemctl is touched.
            assert_ports_closed(installation.ports)
            handoff = json.loads((installation.updates / "relaunch.json").read_text())
            assert handoff == {"job_id": job["job_id"], "config": str(installation.path)}, handoff
            resumed = installation.resume("updated-launcher")
            if failure:
                assert resumed.process.wait(timeout=60) == 75, "failed readiness did not request managed recovery"
                restored = json.loads((installation.state / "update.json").read_text())
                assert restored["state"] == "failed" and restored["rolled_back"], restored
                assert not (installation.updates / "relaunch.json").exists()
                resumed = installation.resume("restored-launcher")
            resumed.wait(resumed.services_ready)
            new_pid = resumed.process.pid
            result = installation.wait_job(job, expected="failed" if failure else "complete", running=resumed)
        assert not (installation.updates / "relaunch.json").exists(), "launcher readiness left a durable handoff"
        assert not (installation.state / "reservation").exists(), "launcher update left its maintenance reservation"
        new_children = service_identities(new_pid)
        restart.assert_changed(old_children, new_children, SERVICES)
        installation.credentials_preserved()
        live_services(installation)
        if failure:
            assert result["rolled_back"] and result.get("error"), result
            assert_install_changes(before, installation.install, set())
            assert (installation.install / launcher).read_bytes() == original_launcher
            assert json.loads((installation.install / "postplus-update.json").read_text()) == installation.baseline
            print("PASS launcher startup readiness failure restores previous launcher/services/metadata and reconnects with existing API credentials", flush=True)
        else:
            assert result["current_version"] == VERSION, result
            assert (installation.install / launcher).read_bytes() == replacements[launcher]
            assert_install_changes(before, installation.install, {launcher, "postplus-update.json"})
            assert json.loads((installation.install / "postplus-update.json").read_text())["version"] == VERSION
            print("PASS launcher update becomes complete only after replacement supervisor and every service are ready", flush=True)
        assert (job_directory / "backup" / sha(launcher.encode())).read_bytes() == original_launcher
        # Exercise normal shutdown on the replacement supervisor as well.
        status, _, stopped = http(installation.ports["admin"], "POST", "/api/admin/shutdown", {}, installation.external)
        assert status == 202 and stopped["state"] == "shutting_down", (status, stopped)
        if os.name != "nt":
            assert resumed.process.wait(timeout=45) == 0, "ordinary managed shutdown requested another restart"
        assert_ports_closed(installation.ports)
    finally:
        installation.close()


def launcher_execution_failure(binaries, directory):
    installation = Installation(binaries, directory)
    try:
        server = installation.server
        old_pid = server.process.pid
        old_children = service_identities(server.process.pid)
        before = installation_hashes(installation.install)
        launcher = native_name("")
        original = (installation.install / launcher).read_bytes()
        job, job_directory = installation.stage({launcher: b"\x00invalid launcher executable\n"}, SERVICES, launcher=True)
        installation.apply(job)
        if os.name == "nt":
            assert server.process.wait(timeout=60) == 0
            failed = installation.wait_job(job, expected="failed")
            new_pid = installation.launcher_pid()
            assert new_pid != old_pid
            assert (job_directory / "takeover.ready").is_file()
            assert (job_directory / native_name("update")).is_file()
        else:
            # The real direct exec path fails before a new process can run.
            # Its original inode remains executing, restores the journal and
            # execs the restored launcher without assistance from this driver.
            failed = installation.wait_job(job, expected="failed", running=server)
            new_pid = server.process.pid
            assert new_pid == old_pid and server.process.poll() is None
            assert "new launcher could not execute; restored previous modules" in "".join(server.lines)
        assert failed["rolled_back"] and failed.get("error"), failed
        new_children = service_identities(new_pid)
        restart.assert_changed(old_children, new_children, SERVICES)
        assert (installation.install / launcher).read_bytes() == original
        assert (job_directory / "backup" / sha(launcher.encode())).read_bytes() == original
        assert_install_changes(before, installation.install, set())
        installation.credentials_preserved()
        live_services(installation)
        assert not (installation.updates / "relaunch.json").exists()
        assert not (installation.state / "reservation").exists()
        assert http(installation.ports["admin"], "POST", "/api/admin/shutdown", {}, installation.external)[0] == 202
        if os.name != "nt":
            assert server.process.wait(timeout=45) == 0
        assert_ports_closed(installation.ports)
        print("PASS invalid launcher execution restores journaled modules and starts every original service before reporting failure", flush=True)
    finally:
        installation.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--case", choices=("all", "selective", "launcher-success", "launcher-failure", "launcher-exec-failure"), default="all")
    args = parser.parse_args()
    verify_restart_identities()
    binaries = args.bin_dir.resolve()
    for name in {"", "update"} | SERVICES:
        assert (binaries / native_name(name)).is_file(), "missing update integration binary: " + native_name(name)
    directory = ROOT / "build/test-runs" / ("update-" + secrets.token_hex(6))
    if args.case in ("all", "selective"):
        selective_updates(binaries, directory / "selective")
    if args.case in ("all", "launcher-success"):
        launcher_update(binaries, directory / "launcher-success")
    if args.case in ("all", "launcher-failure"):
        launcher_update(binaries, directory / "launcher-failure", failure=True)
    if args.case in ("all", "launcher-exec-failure"):
        launcher_execution_failure(binaries, directory / "launcher-exec-failure")


if __name__ == "__main__":
    main()
