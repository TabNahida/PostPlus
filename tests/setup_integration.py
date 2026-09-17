#!/usr/bin/env python3
"""First-run setup and native supervisor regressions; standard library only.

Python is only the test driver. Every service in this suite is launched and
stopped by the C++ postplus executable.
"""
import argparse
import copy
import ctypes
from http.client import HTTPConnection, HTTPSConnection
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import traceback

from integration import PASSWORD, ROOT


def windows_kernel():
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    kernel.OpenEventW.argtypes = [w.DWORD, w.BOOL, w.LPCWSTR]
    kernel.OpenEventW.restype = w.HANDLE
    kernel.SetEvent.argtypes = [w.HANDLE]
    kernel.SetEvent.restype = w.BOOL
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
    kernel.TerminateProcess.restype = w.BOOL
    return kernel


def child_processes(parent):
    """Read only direct children of the test-owned supervisor."""
    if os.name != "nt":
        rows = subprocess.check_output(["ps", "-axo", "pid=,ppid=,comm="], text=True)
        result = {}
        for row in rows.splitlines():
            fields = row.strip().split(None, 2)
            if len(fields) != 3 or int(fields[1]) != parent:
                continue
            pid = int(fields[0])
            if sys.platform.startswith("linux"):
                # Linux comm is limited to 15 bytes (postplus-storage becomes
                # postplus-storag). Resolve only our selected children's image.
                try:
                    name = Path(os.readlink(f"/proc/{pid}/exe")).name
                except FileNotFoundError:
                    continue  # Child exited between ps and readlink.
            else:
                # macOS comm contains the executable path. Keep its complete
                # remainder above, including spaces; never parse process args.
                name = Path(fields[2]).name
            if name.startswith("postplus-"):
                result[name] = pid
        return result
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
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    assert snapshot != ctypes.c_void_p(-1).value, "cannot enumerate test child processes"
    try:
        entry = Entry()
        entry.size = ctypes.sizeof(entry)
        result = {}
        present = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while present:
            if entry.parent == parent and entry.name.startswith("postplus-"):
                result[entry.name.removesuffix(".exe")] = entry.pid
            present = kernel.Process32NextW(snapshot, ctypes.byref(entry))
        return result
    finally:
        kernel.CloseHandle(snapshot)


def request_stop(pid):
    if os.name != "nt":
        os.kill(pid, signal.SIGTERM)
        return
    kernel = windows_kernel()
    event = kernel.OpenEventW(2, False, f"Local\\PostPlus.Stop.{pid}")
    assert event, "native supervisor shutdown event is missing"
    try:
        assert kernel.SetEvent(event), "cannot signal native supervisor shutdown"
    finally:
        kernel.CloseHandle(event)


def kill_test_child(pid):
    if os.name != "nt":
        os.kill(pid, signal.SIGKILL)
        return
    kernel = windows_kernel()
    process = kernel.OpenProcess(1, False, pid)
    assert process, "cannot open the test-owned child process"
    try:
        assert kernel.TerminateProcess(process, 91), "cannot inject child-process failure"
    finally:
        kernel.CloseHandle(process)


def assert_private(path):
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, f"private file mode is not 0600: {path.name}"
        return
    from ctypes import wintypes as w
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    security.GetFileSecurityW.argtypes = [w.LPCWSTR, w.DWORD, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)]
    security.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, ctypes.POINTER(w.WORD), ctypes.POINTER(w.DWORD)]
    security.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(w.BOOL), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(w.BOOL)]
    security.GetAce.argtypes = [ctypes.c_void_p, w.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    security.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    kernel = windows_kernel()
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    size = w.DWORD()
    security.GetFileSecurityW(str(path), 4, None, 0, ctypes.byref(size))
    descriptor = ctypes.create_string_buffer(size.value)
    assert security.GetFileSecurityW(str(path), 4, descriptor, size, ctypes.byref(size))
    control, revision = w.WORD(), w.DWORD()
    assert security.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision))
    assert control.value & 0x1000, "private file inherits a directory DACL"
    present, defaulted, acl = w.BOOL(), w.BOOL(), ctypes.c_void_p()
    assert security.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(acl), ctypes.byref(defaulted))
    assert present.value and acl.value, "private file has no restrictive DACL"
    count = ctypes.c_ushort.from_address(acl.value + 4).value
    assert count == 2, "private file must allow only its account and SYSTEM"
    sids = set()
    for index in range(count):
        ace, sid = ctypes.c_void_p(), ctypes.c_void_p()
        assert security.GetAce(acl, index, ctypes.byref(ace))
        assert ctypes.c_ubyte.from_address(ace.value).value == 0, "unexpected ACL entry"
        assert security.ConvertSidToStringSidW(ace.value + 8, ctypes.byref(sid))
        try:
            sids.add(ctypes.wstring_at(sid))
        finally:
            kernel.LocalFree(sid)
    assert "S-1-5-18" in sids, "SYSTEM access is missing"
    assert not sids.intersection({"S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-544"}), "private file grants broad access"


def http(port, method, path, body=None, headers=None, context=None):
    connection = (HTTPSConnection("localhost", port, timeout=25, context=context) if context else
                  HTTPConnection("127.0.0.1", port, timeout=25))
    try:
        payload = None if body is None else json.dumps(body).encode()
        connection.request(method, path, payload, {"Content-Type": "application/json", **(headers or {})})
        response = connection.getresponse()
        content = response.read()
        result = json.loads(content) if "json" in response.getheader("Content-Type", "") else content
        return response.status, dict(response.getheaders()), result
    finally:
        connection.close()


class NativeServer:
    def __init__(self, binaries, config, port, directory, label, web_root=None, extra_args=None):
        self.token = None
        self.setup_ready = threading.Event()
        self.services_ready = threading.Event()
        self.lines = []
        self.log_path = directory / f"{label}.log"
        env = dict(os.environ)
        env.pop("POSTPLUS_SERVICE_TOKEN", None)  # Exercise the generated token file.
        binary = binaries / ("postplus.exe" if os.name == "nt" else "postplus")
        arguments = [str(binary), "--config", str(config), "--setup-port", str(port)]
        if web_root is not None:
            arguments.extend(["--web-root", str(web_root)])
        arguments.extend(extra_args or [])
        self.process = subprocess.Popen(
            arguments,
            cwd=directory, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        self.reader = threading.Thread(target=self.read_output, daemon=True)
        self.reader.start()

    def read_output(self):
        with self.log_path.open("w", encoding="utf-8") as output:
            for line in self.process.stdout:
                match = re.search(r"One-time setup password: ([0-9a-f]{64})", line)
                if match:
                    self.token = match.group(1)
                    line = line.replace(self.token, "[REDACTED]")
                self.lines.append(line)
                output.write(line)
                output.flush()
                # The password appears before the rest of the setup banner and
                # before the listener is bound. Publish readiness only after its
                # listening line is captured, so callers can inspect all output
                # and connect without depending on process/thread scheduling.
                if self.token and "[web] [info] listening on " in line:
                    self.setup_ready.set()
                if "all services are ready" in line:
                    self.services_ready.set()

    def wait(self, event, timeout=40):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError("native supervisor exited early: " + "".join(self.lines[-12:]))
            if event.wait(0.05):
                return
        raise AssertionError("native supervisor readiness timed out: " + "".join(self.lines[-12:]))

    def close(self):
        if self.process.poll() is None:
            try:
                request_stop(self.process.pid)
                self.process.wait(timeout=45)
            except (AssertionError, OSError, subprocess.TimeoutExpired):
                # Emergency test cleanup, never the passing graceful-stop path.
                for pid in child_processes(self.process.pid).values():
                    try:
                        kill_test_child(pid)
                    except (AssertionError, OSError):
                        pass
                self.process.kill()
                self.process.wait(timeout=10)
        self.reader.join(timeout=3)
        self.process.stdout.close()


def reserve_ports():
    names = ("auth", "storage", "filter", "transfer", "delivery_lock", "smtp", "pop3", "imap", "web", "admin")
    reservations = [socket.socket() for _ in names]
    try:
        for item in reservations:
            item.bind(("127.0.0.1", 0))
        return {name: item.getsockname()[1] for name, item in zip(names, reservations)}
    finally:
        for item in reservations:
            item.close()


def assert_ports_closed(ports):
    remaining = []
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        remaining = []
        for service, port in ports.items():
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    remaining.append(service)
            except OSError:
                pass
        if not remaining:
            return
        time.sleep(0.1)
    raise AssertionError(f"service listeners survived supervisor shutdown: {remaining}")


def verify_services(server, ports, token, admin, tls=None):
    server.wait(server.services_ready)
    children = child_processes(server.process.pid)
    expected = {"postplus-" + name for name in ("auth", "storage", "filter", "transfer", "delivery", "smtp", "pop3", "imap", "web", "admin")}
    assert set(children) == expected, ("native supervisor did not own all ten services", children)
    authorization = {"Authorization": "Bearer " + token}
    for service, body in (("auth", {"op": "exists", "username": admin}), ("storage", {"op": "stats"}),
                          ("filter", {"op": "health"}), ("transfer", {"op": "health"})):
        status, _, result = http(ports[service], "POST", "/rpc", body, authorization)
        assert status == 200 and isinstance(result.get("ok"), bool), (service, status)
    for service, greeting in (("smtp", b"220 "), ("pop3", b"+OK"), ("imap", b"* OK")):
        with socket.create_connection(("127.0.0.1", ports[service]), timeout=5) as sock:
            assert sock.recv(1024).startswith(greeting), f"missing {service} greeting"
    assert http(ports["web"], "GET", "/health", context=tls)[2] == {"ok": True, "service": "web"}
    assert http(ports["admin"], "GET", "/health", context=tls)[2] == {"ok": True, "service": "admin"}
    status, headers, login = http(ports["admin"], "POST", "/api/login", {"username": admin, "password": PASSWORD}, context=tls)
    assert status == 200, ("provisioned admin cannot sign in", status)
    cookie = {"Cookie": headers["Set-Cookie"].split(";", 1)[0]}
    status, _, accounts = http(ports["admin"], "GET", "/api/admin/users", headers=cookie, context=tls)
    assert status == 200 and accounts["users"] == [{"username": admin, "admin": True}], "provisioned account lacks administrator access"
    assert http(ports["web"], "GET", "/api/setup", context=tls)[0] != 200, "first-run API remains enabled after setup"
    assert http(ports["admin"], "GET", "/api/setup", context=tls)[0] != 200, "first-run API remains enabled after setup"
    status, web_headers, _ = http(ports["web"], "POST", "/api/login", {"username": admin, "password": PASSWORD}, context=tls)
    assert status == 200
    assert http(ports["web"], "GET", "/api/admin/users", headers={"Cookie": web_headers["Set-Cookie"].split(";",1)[0]}, context=tls)[0] == 404
    return children


def settings_roundtrip(server, ports, config_path, token, admin):
    original = config_path.read_bytes()
    status, headers, session = http(ports["admin"], "POST", "/api/login", {"username": admin, "password": PASSWORD})
    assert status == 200
    cookie = {"Cookie": headers["Set-Cookie"].split(";", 1)[0]}
    authorized = {**cookie, "X-CSRF-Token": session["csrf"]}
    assert http(ports["admin"], "GET", "/api/admin/config")[0] == 401
    status, _, settings = http(ports["admin"], "GET", "/api/admin/config", headers=cookie)
    assert status == 200 and settings["ok"] and re.fullmatch("[0-9a-f]{64}", settings["revision"])
    schema = {entry["key"]: entry for entry in settings["schema"]}
    assert schema["data_dir"]["readonly"] and schema["ports.admin"]["default"] == 8081
    assert schema["allow_insecure_auth"]["default"] is False
    assert schema["web_session_seconds"]["min"] == 60
    assert "service_token_file" not in settings["values"] and "service_token_env" not in settings["values"]
    assert token not in json.dumps(settings) and settings["values"]["smarthost_password"] == ""
    request = {"revision": settings["revision"], "values": {"log_level": "debug"}}
    assert http(ports["admin"], "POST", "/api/admin/config", request, cookie)[0] == 403
    assert http(ports["admin"], "POST", "/api/admin/config", {**request,"revision":"stale"}, authorized)[0] == 409
    cases = [
        {"data_dir": str(config_path.parent / "moved-mail")},
        {"service_token_file": "new-token"}, {"unknown_option": True},
        {"ports": {"admin": ports["web"]}}, {"ports": {"admin": 65536}},
        {"admin_bind": "0.0.0.0"}, {"allow_insecure_auth": False},
        {"max_connections": "32"}, {"max_mailbox_bytes": 1024},
        {"log_level": "verbose"}, {"blocked_terms": [""]},
        {"spam_rules": [{"term": "term", "weight": -1}]},
        {"smarthost_username": "relay-user", "smarthost_tls": "none"},
        {"clear_smarthost_password": "yes"},
        {"tls_certificate": "absent.pem", "tls_private_key": "absent.key"},
    ]
    for values in cases:
        status, _, result = http(ports["admin"], "POST", "/api/admin/config", {"revision":settings["revision"],"values":values}, authorized)
        assert status == 400 and result.get("code") == "invalid_configuration", (values, status, result)
        assert config_path.read_bytes() == original, "invalid settings modified the configuration"
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        status, _, result = http(ports["admin"], "POST", "/api/admin/config", {
            "revision":settings["revision"], "values":{"ports":{"admin":occupied.getsockname()[1]}}}, authorized)
        assert status == 400 and result["field"] == "ports.admin"
    # Ordinary mail users cannot authenticate to the administration service.
    user = "reader@" + admin.split("@", 1)[1]
    assert http(ports["auth"], "POST", "/rpc", {"op":"create","username":user,"password":PASSWORD,"admin":False}, {"Authorization":"Bearer "+token})[2]["ok"]
    assert http(ports["admin"], "POST", "/api/login", {"username":user,"password":PASSWORD})[0] == 403

    new_admin = reserve_ports()["admin"]
    while new_admin in ports.values():
        new_admin = reserve_ports()["admin"]
    old_admin = ports["admin"]
    old_children = child_processes(server.process.pid)
    secret_value = "relay-test-password-" + secrets.token_hex(12)
    values = {"ports":{"admin":new_admin}, "log_level":"debug", "smarthost_password":secret_value,
              "blocked_terms":["test blocked phrase"], "web_session_seconds":7200}
    status, _, saved = http(old_admin, "POST", "/api/admin/config", {"revision":settings["revision"],"values":values}, authorized)
    assert status == 200 and saved["restart_required"] and saved["admin_url"] == f"http://127.0.0.1:{new_admin}/", (status,saved)
    assert http(old_admin, "POST", "/api/admin/config", request, authorized)[0] == 409, "stale form silently overwrote settings"
    new_config = json.loads(config_path.read_text())
    assert secret_value not in config_path.read_text() and "smarthost_password" not in new_config
    secret_file = Path(new_config["smarthost_password_file"])
    assert secret_file.read_text() == secret_value
    assert_private(secret_file)
    assert_private(config_path)
    backups = list(config_path.parent.glob(config_path.name + ".backup-*"))
    assert backups and any(path.read_bytes() == original for path in backups)
    for backup in backups:
        assert_private(backup)
    # Saved settings are pending until the operator explicitly restarts.
    time.sleep(3)
    assert child_processes(server.process.pid) == old_children, "saving settings unexpectedly restarted services"
    pending = http(old_admin,"GET","/api/admin/config",headers=cookie)
    assert pending[0] == 200 and pending[2]["restart_required"], "saved settings were not marked pending"
    revision = pending[2]["revision"]
    assert http(old_admin,"POST","/api/admin/config",{"revision":revision,"values":{"smarthost_password":""}},authorized)[0]==200
    assert json.loads(config_path.read_text())["smarthost_password_file"]==str(secret_file), "blank relay password replaced the stored credential"
    revision = http(old_admin,"GET","/api/admin/config",headers=cookie)[2]["revision"]
    assert http(old_admin,"POST","/api/admin/config",{"revision":revision,"values":{"clear_smarthost_password":True,"smarthost_password":"conflict"}},authorized)[0]==400
    assert http(old_admin,"POST","/api/admin/config",{"revision":revision,"values":{"clear_smarthost_password":True}},authorized)[0]==200
    cleared = http(old_admin,"GET","/api/admin/config",headers=cookie)[2]
    assert not cleared["secret_status"]["smarthost_password"] and "smarthost_password_file" not in json.loads(config_path.read_text())
    assert secret_file.is_file(), "password removal broke a configuration backup"
    assert http(old_admin,"POST","/api/admin/config",{"revision":cleared["revision"],"values":{"smarthost_password":secret_value}},authorized)[0]==200
    new_config=json.loads(config_path.read_text())
    assert_ports_closed({"pending_admin":new_admin})
    request_stop(server.process.pid)
    assert server.process.wait(timeout=45)==0
    assert_ports_closed(ports)
    server.close()
    ports["admin"] = new_admin
    server = NativeServer(
        Path(server.process.args[0]).parent,config_path,new_admin,server.log_path.parent,"settings-manual-restart")
    try:
        server.wait(server.services_ready)
        children = child_processes(server.process.pid)
        assert len(children) == 10 and all(children[name] != pid for name,pid in old_children.items()), "manual restart did not launch all services"
        assert_ports_closed({"old_admin":old_admin})
        status, headers, _ = http(new_admin, "POST", "/api/login", {"username":admin,"password":PASSWORD})
        assert status == 200
        cookie = {"Cookie":headers["Set-Cookie"].split(";",1)[0]}
        current = http(new_admin,"GET","/api/admin/config",headers=cookie)[2]
        assert current["values"]["ports"]["admin"] == new_admin and current["values"]["web_session_seconds"] == 7200
        assert current["restart_required"] is False
        assert current["values"]["smarthost_password"] == "" and current["secret_status"]["smarthost_password"]
        assert secret_value not in json.dumps(current) and token not in json.dumps(current)
        for logfile in Path(new_config["log_dir"]).glob("*.jsonl*"):
            contents = logfile.read_text(encoding="utf-8")
            assert secret_value not in contents and token not in contents
            if server.token:
                assert server.token not in contents
        print("PASS admin settings authorization, CSRF, validation, revisions, private backups/secrets and explicit manual restart", flush=True)
        return server, children
    except BaseException:
        server.close()
        raise


def legacy_setup(binaries, directory):
    ports = reserve_ports()
    path = directory / "legacy" / "postplus.json"
    path.parent.mkdir()
    values = {"domain":"legacy.example", "bind":"127.0.0.1", "allow_insecure_auth":True,
              "data_dir":"../legacy-mail", "web_root":str(ROOT / "web"),
              "service_token_env":"POSTPLUS_SERVICE_TOKEN", "log_level":"warn",
              "max_recipients":12, "delivery_lock_port":ports["delivery_lock"],
              "ports":{key:value for key,value in ports.items() if key != "delivery_lock"}}
    original = (json.dumps(values,indent=2)+"\n").encode()
    path.write_bytes(original)
    server = NativeServer(binaries,path,ports["admin"],directory,"legacy-setup")
    try:
        server.wait(server.setup_ready)
        headers = {"X-Setup-Token":server.token}
        deadline = time.monotonic()+10
        while True:
            try:
                status, _, data = http(ports["admin"],"GET","/api/setup",headers=headers)
                break
            except ConnectionRefusedError:
                assert time.monotonic()<deadline
                time.sleep(0.05)
        assert status==200 and data["completing_existing"] is True
        assert data["defaults"]["domain"]=="legacy.example" and data["defaults"]["max_recipients"]==12
        assert path.read_bytes()==original, "opening legacy setup rewrote its configuration"
        payload = {**data["defaults"],"admin_username":"admin@legacy.example","admin_password":PASSWORD}
        bad = {**payload,"data_dir":str(directory / "unsafe-new-mail-location")}
        assert http(ports["admin"],"POST","/api/setup",bad,headers)[0]==400
        assert path.read_bytes()==original
        status, _, result = http(ports["admin"],"POST","/api/setup",payload,headers)
        assert status==200 and result["ok"], (status,result)
        saved = json.loads(path.read_text())
        assert saved["max_recipients"]==12 and saved["log_level"]=="warn" and saved["setup_complete"] is True
        assert Path(saved["data_dir"])==(directory / "legacy-mail")
        backups = list(path.parent.glob(path.name+".backup-*"))
        assert len(backups)==1 and backups[0].read_bytes()==original
        assert_private(backups[0])
        assert_private(path)
        token = Path(saved["service_token_file"]).read_text().strip()
        # Existing log level warn intentionally suppresses service readiness info.
        deadline = time.monotonic()+40
        while True:
            try:
                if http(ports["admin"],"GET","/health")[0]==200:
                    break
            except OSError:
                pass
            assert server.process.poll() is None and time.monotonic()<deadline, "legacy setup did not start services"
            time.sleep(0.05)
        server.services_ready.set()
        verify_services(server,ports,token,"admin@legacy.example")
        request_stop(server.process.pid)
        assert server.process.wait(timeout=45)==0
        assert_ports_closed(ports)
        print("PASS incomplete legacy configuration completes through setup, preserves values and data, and creates private backup",flush=True)
    finally:
        server.close()

    # A configured secret-file path that is broken must fail visibly; never
    # silently treat an installed server as a fresh setup instance.
    saved["service_token_file"]=str(path.parent / "absent-token-file")
    path.write_text(json.dumps(saved),encoding="utf-8")
    broken = NativeServer(binaries,path,ports["admin"],directory,"broken-token")
    try:
        assert broken.process.wait(timeout=10)!=0
        assert not broken.setup_ready.is_set()
        assert_ports_closed(ports)
    finally:
        broken.close()


def run(binaries, directory):
    # Resolve relative --config from the project directory through the actual
    # xmake command. A deliberately absent web root makes the wrong-CWD path
    # fail immediately instead of leaving a setup server running on failure.
    malformed_relative = directory / "relative-config.json"
    malformed_relative.write_text("[]", encoding="utf-8")
    launch = subprocess.run(
        ["xmake", "run", "postplus", "--config", os.path.relpath(malformed_relative, ROOT),
         "--web-root", str(directory / "absent-web")],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    assert launch.returncode != 0 and "config must be a JSON object" in launch.stdout + launch.stderr, (launch.stdout, launch.stderr)
    assert malformed_relative.read_text() == "[]"
    print("PASS xmake run resolves relative configuration from the repository root", flush=True)

    # The native launcher must discover a complete build-side web bundle from
    # an unrelated working directory, without an explicit --web-root override.
    for asset in (ROOT / "web").iterdir():
        if asset.is_file():
            assert (binaries / "web" / asset.name).read_bytes() == asset.read_bytes(), f"missing or stale bundled asset: {asset.name}"
    ports = reserve_ports()
    config_path = directory / "first run" / "config" / "postplus.json"
    config_path.parent.mkdir(parents=True)
    server = NativeServer(binaries, config_path, ports["admin"], directory, "setup")
    try:
        server.wait(server.setup_ready)
        headers = {"X-Setup-Token": server.token}
        # The URL is printed before the acceptor starts; wait for HTTP readiness.
        deadline = time.monotonic() + 10
        while True:
            try:
                status, _, defaults = http(ports["admin"], "GET", "/api/setup", headers=headers)
                break
            except OSError:
                assert time.monotonic() < deadline, "setup listener did not start"
                time.sleep(0.05)
        assert status == 200 and defaults["ok"] is True
        assert any("setup is required" in line for line in server.lines)
        assert any(f"http://127.0.0.1:{ports['admin']}/setup" in line for line in server.lines)
        assert not any("/setup#token=" in line for line in server.lines)
        assert http(ports["admin"], "GET", "/api/setup")[0] == 403
        assert http(ports["admin"], "POST", "/api/setup", {}, {"X-Setup-Token": "wrong"})[0] == 403
        assert http(ports["admin"], "GET", "/api/setup", headers={**headers, "Host": "evil.example"})[0] == 403
        assert http(ports["admin"], "POST", "/api/setup", {}, {**headers, "Origin": "https://evil.example"})[0] == 403
        assert http(ports["admin"], "GET", "/api/setup?token=" + server.token)[0] == 404
        for path in ("/setup", "/setup.js", "/i18n.js", "/settings.js", "/favicon.svg", "/style.css"):
            status, policy, body = http(ports["admin"], "GET", path)
            assert status == 200 and body
            assert policy["Cache-Control"] == "no-store" and "frame-ancestors 'none'" in policy["Content-Security-Policy"]
        assert http(ports["admin"], "GET", "/../config/postplus.json")[0] == 404
        payload = defaults["defaults"]
        payload.update(domain="setup.example", admin_username="admin@setup.example", admin_password=PASSWORD,
                       data_dir=str(directory / "mail data"), ports=ports, allow_insecure_auth=True)
        cases = (
            ({"domain": "bad domain"}, "invalid_domain"),
            ({"admin_username": "admin@elsewhere.example"}, "invalid_admin"),
            ({"admin_password": "short"}, "weak_password"),
            ({"bind": "not-an-ip"}, "invalid_bind"),
            ({"bind": "0.0.0.0"}, "tls_required"),
            ({"allow_insecure_auth": False}, "tls_required"),
            ({"tls_certificate": str(directory / "absent.pem"), "tls_private_key": str(directory / "absent.key")}, "invalid_tls"),
            ({"ports": {**ports, "smtp": ports["pop3"]}}, "duplicate_port"),
            ({"ports": {**ports, "smtp": 65536}}, "invalid_port"),
            ({"ports": {**ports, "auth": ports["admin"], "admin": ports["auth"]}}, "setup_port_conflict"),
        )
        for changes, code in cases:
            invalid = copy.deepcopy(payload)
            invalid.update(changes)
            status, _, error = http(ports["admin"], "POST", "/api/setup", invalid, headers)
            assert status == 400 and error.get("code") == code, (code, status, error)
            assert not config_path.exists(), "invalid setup created a configuration"
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            invalid = {**payload, "ports": {**ports, "smtp": occupied.getsockname()[1]}}
            assert http(ports["admin"], "POST", "/api/setup", invalid, headers)[2]["code"] == "port_unavailable"
        sentinel = b'{"test_owned_sentinel":true}\n'
        config_path.write_bytes(sentinel)
        assert http(ports["admin"], "POST", "/api/setup", payload, headers)[0] == 409
        assert config_path.read_bytes() == sentinel, "setup replaced an existing configuration"
        config_path.unlink()  # Only this exact test-created sentinel is removed.
        print("PASS setup token/Origin/Host, asset policy, field/TLS/port validation and no-overwrite protection", flush=True)

        status, _, result = http(ports["admin"], "POST", "/api/setup", payload, headers)
        assert status == 200 and result["ok"] is True, (status, result)
        assert result["web_url"] == f"http://127.0.0.1:{ports['web']}/"
        assert result["admin_url"] == f"http://127.0.0.1:{ports['admin']}/"
        saved_bytes = config_path.read_bytes()
        config = json.loads(saved_bytes)
        assert b"admin_password" not in saved_bytes and PASSWORD.encode() not in saved_bytes
        assert "service_token" not in config and Path(config["data_dir"]).is_absolute()
        assert Path(config["web_root"]).is_absolute() and config["delivery_lock_port"] == ports["delivery_lock"]
        assert Path(config["web_root"]) == binaries / "web", "setup failed to discover bundled web assets"
        secret = Path(config["service_token_file"])
        token = secret.read_text().strip()
        assert re.fullmatch("[0-9a-f]{64}", token) and token.encode() not in saved_bytes
        assert_private(config_path)
        assert_private(secret)
        assert not list(config_path.parent.glob("*.setup-*.tmp")), "successful setup left a staging file"
        verify_services(server, ports, token, payload["admin_username"])
        setup_log = Path(config["log_dir"]) / "setup.jsonl"
        assert setup_log.is_file(), "first-run setup did not persist a log file"
        setup_entries = [json.loads(line) for line in setup_log.read_text(encoding="utf-8").splitlines() if line]
        assert any(entry.get("service") == "setup" and entry.get("level") == "info" and
                   entry.get("message") == "initial configuration and administrator created"
                   for entry in setup_entries), "successful first-run provisioning was not logged"
        for logfile in Path(config["log_dir"]).glob("*.jsonl*"):
            contents = logfile.read_text(encoding="utf-8")
            assert PASSWORD not in contents and token not in contents and server.token not in contents, "credentials reached persistent logs"
        request_stop(server.process.pid)
        assert server.process.wait(timeout=45) == 0, "supervisor shutdown was not graceful"
        assert_ports_closed(ports)
        print("PASS first-run provisioning, private token/config, ten native child services, admin login and graceful shutdown", flush=True)
    finally:
        server.close()

    restarted = NativeServer(binaries, config_path, ports["admin"], directory, "restart")
    try:
        children = verify_services(restarted, ports, token, payload["admin_username"])
        assert not restarted.setup_ready.is_set(), "existing configuration reopened setup"
        assert config_path.read_bytes() == saved_bytes, "restart rewrote the configuration"
        restarted, children = settings_roundtrip(restarted, ports, config_path, token, payload["admin_username"])
        active_bytes = config_path.read_bytes()
        start = len(restarted.lines)
        config_path.write_bytes(b'{invalid manual edit "secret-that-must-not-be-logged"\n')
        time.sleep(3)
        assert child_processes(restarted.process.pid)==children, "invalid manual edit restarted or stopped services"
        assert http(ports["admin"],"GET","/health")[0]==200
        assert not any("secret-that-must-not-be-logged" in line for line in restarted.lines[start:])
        config_path.write_bytes(active_bytes)
        # Inject a real child crash. The supervisor must fail and stop its peers.
        kill_test_child(children["postplus-smtp"])
        assert restarted.process.wait(timeout=45) != 0, "child failure was not surfaced by the supervisor"
        assert_ports_closed(ports)
        print("PASS existing-config restart and child-crash shutdown of all native services", flush=True)
    finally:
        restarted.close()

    before = config_path.read_bytes()
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1",0))
        occupied.listen()
        changed = json.loads(before)
        changed["ports"]["admin"] = occupied.getsockname()[1]
        config_path.write_text(json.dumps(changed),encoding="utf-8")
        conflict = NativeServer(binaries,config_path,ports["admin"],directory,"startup-port-conflict")
        try:
            assert conflict.process.wait(timeout=45)!=0, "startup port conflict did not report failure"
            assert_ports_closed(ports)
        finally:
            conflict.close()
            config_path.write_bytes(before)
    print("PASS manual file edits stay pending; unavailable port at explicit restart fails without leaving child services",flush=True)

    legacy_setup(binaries,directory)

    malformed = directory / "malformed.json"
    malformed.write_bytes(b"{broken configuration\n")
    refused = NativeServer(binaries, malformed, ports["admin"], directory, "malformed")
    try:
        assert refused.process.wait(timeout=10) != 0
        assert not refused.setup_ready.is_set(), "malformed config incorrectly opened setup"
        assert malformed.read_bytes() == b"{broken configuration\n", "malformed config was replaced"
        assert_ports_closed(ports)
        print("PASS malformed existing configuration fails without entering setup or overwriting files", flush=True)
    finally:
        refused.close()

    # Use the existing local fixture trust root to verify that HTTPS startup
    # works without relaxing the supervisor's or client's public trust policy.
    tls_ports = reserve_ports()
    tls_path = directory / "tls" / "postplus.json"
    secure = NativeServer(binaries, tls_path, tls_ports["admin"], directory, "tls-setup", web_root=ROOT / "web")
    try:
        secure.wait(secure.setup_ready)
        certificate = ROOT / "tests/fixtures/localhost-test-only.crt"
        private_key = ROOT / "tests/fixtures/localhost-test-only.key"
        tls_payload = {"domain": "localhost", "admin_username": "admin@localhost", "admin_password": PASSWORD,
                       "data_dir": str(directory / "tls-mail"), "ports": tls_ports, "allow_insecure_auth": False,
                       "bind": "127.0.0.1", "tls_certificate": str(certificate), "tls_private_key": str(private_key)}
        deadline = time.monotonic() + 10
        while True:
            try:
                status, _, result = http(tls_ports["admin"], "POST", "/api/setup", tls_payload, {"X-Setup-Token": secure.token})
                break
            except ConnectionRefusedError:
                assert time.monotonic() < deadline
                time.sleep(0.05)
        assert status == 200 and result["web_url"] == f"https://localhost:{tls_ports['web']}/", (status, result)
        tls_config = json.loads(tls_path.read_text())
        tls_token = Path(tls_config["service_token_file"]).read_text().strip()
        context = ssl.create_default_context(cafile=str(certificate))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        verify_services(secure, tls_ports, tls_token, "admin@localhost", tls=context)
        request_stop(secure.process.pid)
        assert secure.process.wait(timeout=45) == 0
        assert_ports_closed(tls_ports)
        print("PASS TLS first-run configuration, native HTTPS readiness and verified admin login", flush=True)
    finally:
        secure.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True, type=Path)
    args = parser.parse_args()
    directory = (ROOT / "build/test-runs" / ("setup-" + secrets.token_hex(6))).resolve()
    directory.mkdir(parents=True)
    try:
        run(args.bin_dir.resolve(), directory)
        print("All setup and native supervisor tests passed", flush=True)
    except BaseException:
        print(f"Logs: {directory}", flush=True)
        traceback.print_exc()
        raise


if __name__ == "__main__":
    main()
