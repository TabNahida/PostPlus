#!/usr/bin/env python3
"""Offline release-module, source-fingerprint and archive-safety regressions."""
import hashlib
import io
import json
from pathlib import Path
import secrets
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import release_manifest as release


def archive(directory, platform, arch, extension, unsafe=False):
    version = release.version()
    prefix = "postplus-" + version + "/"
    suffix = ".exe" if platform == "windows" else ""
    entries = {name + suffix: (name + " native binary fixture").encode() for name in release.BINARIES}
    entries.update({"web/style.css": b"body{color:black}", "web/app.js": b"console.log('app')",
                    "README.md": b"documentation", "config/postplus.example.json": b"{}"})
    path = directory / f"postplus-{version}-{platform}-{arch}.{extension}"
    if extension == "zip":
        with zipfile.ZipFile(path, "w") as output:
            for name, body in entries.items():
                output.writestr(prefix + name, body)
            if unsafe:
                output.writestr(prefix + "../escape", b"escape")
    else:
        with tarfile.open(path, "w:gz") as output:
            for name, body in entries.items():
                item = tarfile.TarInfo(prefix + name)
                item.size = len(body)
                item.mode = 0o755 if name.startswith("postplus") else 0o644
                output.addfile(item, io.BytesIO(body))
            if unsafe:
                item = tarfile.TarInfo(prefix + "linked")
                item.type = tarfile.SYMTYPE
                item.linkname = "/etc/passwd"
                output.addfile(item)
    return path


def fingerprint_test(directory):
    sources = directory / "sources"
    for folder in ("src/core", "include/postplus", "src/services"):
        (sources / folder).mkdir(parents=True)
    (sources / "xmake.lua").write_text('set_version("0.2.1")\nset_languages("c++20")\nadd_requires("openssl3 3.6.1")\nadd_defines(\'POSTPLUS_VERSION="0.2.1"\')\n')
    for name, value in {"src/core/core.cpp": "shared", "include/postplus/core.hpp": "header",
                        "src/services/smtp.cpp": "SMTP", "src/services/auth.cpp": "AUTH"}.items():
        (sources / name).write_text(value)
    original = release.ROOT
    try:
        release.ROOT = sources
        smtp, auth = release.fingerprint("postplus-smtp"), release.fingerprint("postplus-auth")
        path = sources / "xmake.lua"
        path.write_text(path.read_text().replace("0.2.1", "0.2.2"))
        assert (smtp, auth) == (release.fingerprint("postplus-smtp"), release.fingerprint("postplus-auth")), "release version changed component identity"
        (sources / "src/services/auth.cpp").write_text("new AUTH")
        assert smtp == release.fingerprint("postplus-smtp") and auth != release.fingerprint("postplus-auth"), "one module invalidated unrelated module"
        (sources / "src/core/core.cpp").write_text("new shared core")
        assert smtp != release.fingerprint("postplus-smtp"), "common code change omitted a consumer"
        smtp = release.fingerprint("postplus-smtp")
        (sources / "src/core/private.hpp").write_text("private shared declarations")
        assert smtp != release.fingerprint("postplus-smtp"), "private shared header change omitted a consumer"
    finally:
        release.ROOT = original


def verify_mode(directory, legacy):
    packages = directory / ("bridge-packages" if legacy else "archive-packages")
    packages.mkdir()
    for platform, arch, extension in release.PLATFORMS:
        package = archive(packages, platform, arch, extension)
        release.installed(package, platform, arch)
        files = release.archive_files(package, release.version())
        baseline = json.loads(files["postplus-update.json"])
        assert baseline == release.installed_manifest(files, platform, arch)
        assert baseline["platform"] == platform and baseline["arch"] == arch
        assert not any(item["path"] == "postplus-update.json" for item in baseline["files"])
        # Regeneration replaces the baseline instead of adding a duplicate.
        release.installed(package, platform, arch)
        release.modules(packages, platform, arch)
        manifest = json.loads((packages / f"postplus-update-{platform}-{arch}.json").read_text())
        assert manifest["download"] == "archive"
        assert len(manifest["files"]) == len(release.BINARIES) + 2
        assert not any(item["path"].startswith(("config/", "docs/")) or item["path"] == "README.md" for item in manifest["files"])
        for item in manifest["files"]:
            assert ("asset" in item) == legacy
            raw = ((packages / item["asset"]).read_bytes() if legacy else files[item["path"]])
            assert len(raw) == item["size"] and hashlib.sha256(raw).hexdigest() == item["sha256"]
            assert len(item["fingerprint"]) == 64
    release.checksums(packages)
    merged = json.loads((packages / "postplus-update.json").read_text())
    assert merged["repository"] == "TabNahida/PostPlus" and len(merged["targets"]) == 3
    assert merged["minimum_updater"] == (1 if legacy else 2)
    if not legacy:
        assert len(list(packages.iterdir())) == 8, "archive release still has per-module files"
    sums = dict((line[66:], line[:64]) for line in (packages / "SHA256SUMS").read_text().splitlines())
    assert sums["postplus-update.json"] == hashlib.sha256((packages / "postplus-update.json").read_bytes()).hexdigest()
    sidecar = packages / "postplus-update-linux-x86_64.json"
    original = sidecar.read_bytes()
    descriptor = json.loads(original)
    descriptor["archive"]["sha256"] = "0" * 64
    sidecar.write_text(json.dumps(descriptor))
    try:
        release.checksums(packages)
    except ValueError:
        pass
    else:
        raise AssertionError("incorrect full-package digest accepted")
    sidecar.write_bytes(original)


def main():
    directory = ROOT / "build/test-runs" / ("release-manifest-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    fingerprint_test(directory)
    original = release.legacy_assets
    try:
        for legacy in (True, False):
            release.legacy_assets = lambda: legacy
            verify_mode(directory, legacy)
    finally:
        release.legacy_assets = original
    bad = directory / "unsafe"
    bad.mkdir()
    for platform, arch, extension in release.PLATFORMS[:2]:
        archive(bad, platform, arch, extension, unsafe=True)
        try:
            release.modules(bad, platform, arch)
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe archive path or link accepted")
    print("PASS release fingerprints, legacy migration bridge, eight-asset archive release, aggregate checksums, preserved config/docs and archive traversal/link rejection")


if __name__ == "__main__":
    main()
