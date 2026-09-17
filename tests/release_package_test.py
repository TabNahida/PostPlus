#!/usr/bin/env python3
"""Verify an actual distribution archive, then start its native supervisor."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import struct
import subprocess
import sys
import tarfile
import zipfile

from integration import PASSWORD, ROOT
from setup_integration import (NativeServer, assert_ports_closed, http,
                               request_stop, reserve_ports, verify_services)

sys.path.insert(0, str(ROOT / "scripts"))
from release_manifest import version

BINARIES = ("postplus", "postplus-admin", "postplus-web", "postplus-auth",
            "postplus-storage", "postplus-filter", "postplus-smtp", "postplus-pop3",
            "postplus-imap", "postplus-delivery", "postplus-transfer", "postplus-ctl",
            "postplus-clean-data")


def unpack(archive, destination, prefix):
    def check(name):
        path = PurePosixPath(name)
        assert not path.is_absolute() and ".." not in path.parts and "\\" not in name, name
        assert path.parts[0] == prefix, f"unexpected archive prefix: {name}"

    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as source:
            for item in source.infolist():
                check(item.filename)
                assert item.external_attr >> 16 & 0o170000 != 0o120000, "archive contains a symlink"
            source.extractall(destination)
    else:
        with tarfile.open(archive, "r:gz") as source:
            for item in source.getmembers():
                check(item.name)
                assert item.isfile() or item.isdir(), "archive contains a link or special file"
            source.extractall(destination, filter="data")
    return destination / prefix


def windows_imports(binary):
    """Read the PE import directory without requiring Visual Studio on PATH."""
    data = binary.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe:pe + 4] == b"PE\0\0"
    sections, optional_size = struct.unpack_from("<H12xH", data, pe + 6)
    optional = pe + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    assert magic == 0x20B, "Windows release must be a 64-bit PE executable"
    import_rva = struct.unpack_from("<I", data, optional + 120)[0]
    section_table = optional + optional_size

    def offset(rva):
        for i in range(sections):
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", data, section_table + i * 40 + 8)
            if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
                return raw_offset + rva - virtual_address
        raise AssertionError(f"invalid PE RVA {rva}")

    names = []
    entry = offset(import_rva)
    while any(data[entry:entry + 20]):
        name = offset(struct.unpack_from("<I", data, entry + 12)[0])
        names.append(data[name:data.index(b"\0", name)].decode("ascii").lower())
        entry += 20
    return names


def dependencies(binary):
    if os.name == "nt":
        imports = windows_imports(binary)
        forbidden = ("vcruntime", "msvcp", "ucrtbased", "libssl", "libcrypto", "sqlite")
        assert not any(name.startswith(forbidden) for name in imports), (binary.name, imports)
    elif sys.platform == "darwin":
        output = subprocess.check_output(["otool", "-L", str(binary)], text=True)
        libraries = [line.strip().split(" (", 1)[0] for line in output.splitlines()[1:]]
        assert all(name.startswith(("/usr/lib/", "/System/Library/")) for name in libraries), output
    else:
        output = subprocess.check_output(["ldd", str(binary)], text=True)
        assert "not found" not in output, output
        assert not any(name in output for name in ("libssl", "libcrypto", "libsqlite", ".xmake")), output


def verify_inventory(root, platform):
    suffix = ".exe" if platform == "windows" else ""
    expected = {name + suffix for name in BINARIES}
    document_files = [ROOT / name for name in ("README.md", "LICENSE", "THIRD_PARTY_NOTICES.md",
                                               "config/postplus.example.json")]
    for directory in ("docs", "web", "licenses"):
        document_files.extend(path for path in (ROOT / directory).rglob("*") if path.is_file())
    for source in document_files:
        relative = source.relative_to(ROOT).as_posix()
        expected.add(relative)
        assert (root / relative).read_bytes() == source.read_bytes(), f"missing/stale file: {relative}"
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    assert actual == expected, ("archive file allowlist mismatch", sorted(actual - expected), sorted(expected - actual))
    for name in BINARIES:
        binary = root / (name + suffix)
        assert binary.stat().st_size > 0
        if os.name != "nt":
            assert os.access(binary, os.X_OK), f"executable bit was lost: {name}"
        dependencies(binary)


def native_smoke(root, directory):
    binary = root / ("postplus.exe" if os.name == "nt" else "postplus")
    help_result = subprocess.run([str(binary), "--help"], cwd=directory, capture_output=True,
                                 text=True, encoding="utf-8", timeout=15, check=True)
    assert "--setup-port" in help_result.stdout
    ports = reserve_ports()
    config_path = directory / "smoke-config" / "postplus.json"
    server = NativeServer(root, config_path, ports["admin"], directory, "release-package")
    try:
        server.wait(server.setup_ready)
        for path in ("/setup", "/i18n.js", "/preferences.js", "/preferences.css", "/favicon.svg"):
            status, _, body = http(ports["admin"], "GET", path)
            assert status == 200 and body, path
        headers = {"X-Setup-Token": server.token}
        status, _, defaults = http(ports["admin"], "GET", "/api/setup", headers=headers)
        assert status == 200
        payload = defaults["defaults"]
        payload.update(domain="package.example", admin_username="admin@package.example",
                       admin_password=PASSWORD, data_dir=str(directory / "smoke-mail"),
                       ports=ports, allow_insecure_auth=True)
        status, _, result = http(ports["admin"], "POST", "/api/setup", payload, headers)
        assert status == 200 and result["ok"], result
        config = json.loads(config_path.read_text(encoding="utf-8"))
        assert Path(config["web_root"]) == root / "web"
        token = Path(config["service_token_file"]).read_text().strip()
        verify_services(server, ports, token, payload["admin_username"])
        for service in ("web", "admin"):
            for path in ("/", "/icons.svg", "/preferences.js", "/preferences.css"):
                assert http(ports[service], "GET", path)[0] == 200, (service, path)
        request_stop(server.process.pid)
        assert server.process.wait(timeout=45) == 0
        assert_ports_closed(ports)
    finally:
        server.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--platform", choices=("linux", "windows", "macosx"), required=True)
    parser.add_argument("--arch", required=True)
    args = parser.parse_args()
    release = version()
    extension = "zip" if args.platform == "windows" else "tar.gz"
    archive = args.packages / f"postplus-{release}-{args.platform}-{args.arch}.{extension}"
    assert archive.is_file(), archive
    directory = ROOT / "build/test-runs" / ("package-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    try:
        root = unpack(archive, directory, "postplus-" + release)
        verify_inventory(root, args.platform)
        native_smoke(root, directory)
    except BaseException:
        print(f"Package test diagnostics: {directory}", flush=True)
        raise
    print(f"PASS {archive.name}: exact inventory, runtime dependencies, setup, all services and graceful stop")


if __name__ == "__main__":
    main()
