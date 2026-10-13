#!/usr/bin/env python3
"""Validate releases and publish hash-addressed native updater modules."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tarfile
import tempfile
import zipfile

REPOSITORY = "TabNahida/PostPlus"
PLATFORMS = (("linux", "x86_64", "tar.gz"), ("windows", "x64", "zip"), ("macosx", "arm64", "tar.gz"))
BINARIES = {"postplus", "postplus-admin", "postplus-web", "postplus-auth", "postplus-storage",
            "postplus-filter", "postplus-smtp", "postplus-pop3", "postplus-imap", "postplus-delivery",
            "postplus-transfer", "postplus-ctl", "postplus-clean-data", "postplus-update"}

ROOT = Path(__file__).resolve().parents[1]


def version():
    match = re.search(r'^set_version\("([0-9]+\.[0-9]+\.[0-9]+)"\)',
                      (ROOT / "xmake.lua").read_text(encoding="utf-8"), re.MULTILINE)
    if not match:
        raise ValueError("Cannot find the project release version")
    result = match.group(1)
    ref = os.environ.get("GITHUB_REF", "")
    if ref.startswith("refs/tags/") and ref != f"refs/tags/v{result}":
        raise ValueError(f"Tag {ref!r} does not match project version {result}")
    if not (ROOT / "docs/releases" / f"{result}.md").is_file():
        raise ValueError(f"Release notes are missing for {result}")
    return result


def digest(value):
    return hashlib.sha256(value).hexdigest()


def fingerprint(name):
    if name.startswith("web/"):
        return digest((ROOT / name).read_bytes())
    module = name.removesuffix(".exe")
    own = {"postplus": "src/tools/main.cpp", "postplus-admin": "src/services/web.cpp",
           "postplus-ctl": "src/tools/ctl.cpp", "postplus-clean-data": "src/tools/clean_data.cpp",
           "postplus-update": "src/tools/update.cpp"}.get(module, f"src/services/{module.removeprefix('postplus-')}.cpp")
    sources = sorted([*(ROOT / "src/core").glob("*.cpp"), *(ROOT / "include/postplus").glob("*.hpp"), ROOT / own])
    # Version and unrelated targets are metadata. Actual common dependency and
    # compiler policy changes remain component inputs, without build timestamps.
    settings = "\n".join(line.strip() for line in (ROOT / "xmake.lua").read_text().splitlines()
                         if re.search(r"\b(?:add_requires|set_languages|add_defines|add_cxflags|add_syslinks|add_frameworks)\(", line)
                         and "POSTPLUS_VERSION" not in line)
    state = hashlib.sha256(settings.encode())
    for source in sources:
        state.update(source.relative_to(ROOT).as_posix().encode() + b"\0" + source.read_bytes() + b"\0")
    state.update(module.encode())  # admin/web compile the same file with distinct roles
    return state.hexdigest()


def update_path(name, platform):
    suffix = ".exe" if platform == "windows" else ""
    return name in {item + suffix for item in BINARIES} or (
        name.startswith("web/") and name.count("/") == 1 and
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.(?:html|js|css|svg|txt)", name[4:]) is not None)


def archive_files(archive, release):
    prefix = "postplus-" + release + "/"
    result = {}
    def add(name, contents):
        if (not name.startswith(prefix) or "\\" in name or
                any(part in ("", ".", "..") for part in name.rstrip("/").split("/"))):
            raise ValueError(f"Unsafe archive path: {name}")
        relative = name[len(prefix):]
        if relative in result:
            raise ValueError(f"Duplicate archive path: {name}")
        result[relative] = contents
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as source:
            for item in source.infolist():
                if item.external_attr >> 16 & 0o170000 not in (0, 0o040000, 0o100000):
                    raise ValueError("Links and special files cannot enter a release")
                if item.is_dir():
                    continue
                add(item.filename, source.read(item))
    else:
        with tarfile.open(archive, "r:gz") as source:
            for item in source.getmembers():
                if item.isdir():
                    continue
                if not item.isfile():
                    raise ValueError("Links and special files cannot enter a release")
                add(item.name, source.extractfile(item).read())
    return result


def module_inventory(files, platform):
    suffix = ".exe" if platform == "windows" else ""
    required = {name + suffix for name in BINARIES}
    if not required <= files.keys() or not any(name.startswith("web/") for name in files):
        raise ValueError("Release is missing native updater modules or web assets")
    inventory = []
    for name, contents in sorted(files.items()):
        if not update_path(name, platform):
            continue
        if not contents or len(contents) > 128 * 1024 * 1024:
            raise ValueError(f"Invalid update module size: {name}")
        inventory.append({"path": name, "sha256": digest(contents),
                          "fingerprint": digest(contents) if name.startswith("web/") else fingerprint(name),
                          "size": len(contents), "executable": name in required})
    return inventory


def installed_manifest(files, platform, arch):
    return {"schema": 1, "repository": REPOSITORY, "version": version(),
            "platform": platform, "arch": arch,
            "files": [{key: item[key] for key in ("path", "sha256", "fingerprint", "size")}
                      for item in module_inventory(files, platform)]}


def installed(archive, platform, arch):
    """Add the actual installed baseline without unpacking paths onto disk."""
    if (platform, arch) not in [(plat, cpu) for plat, cpu, _ in PLATFORMS]:
        raise ValueError("Unsupported release platform or architecture")
    release = version()
    files = archive_files(archive, release)
    contents = (json.dumps(installed_manifest(files, platform, arch), sort_keys=True, indent=2) + "\n").encode()
    metadata_path = f"postplus-{release}/postplus-update.json"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=archive.parent, prefix=".baseline-",
                                         suffix=".zip" if archive.suffix == ".zip" else ".tar.gz", delete=False) as output:
            temporary = Path(output.name)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as source, zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as output:
                output.comment = source.comment
                for item in source.infolist():
                    if item.filename != metadata_path:
                        output.writestr(item, source.read(item))
                output.writestr(metadata_path, contents)
        else:
            with tarfile.open(archive, "r:gz") as source, tarfile.open(temporary, "w:gz") as output:
                for item in source.getmembers():
                    if item.name != metadata_path:
                        output.addfile(item, source.extractfile(item) if item.isfile() else None)
                item = tarfile.TarInfo(metadata_path)
                item.mode, item.size = 0o644, len(contents)
                output.addfile(item, io.BytesIO(contents))
        # Validate the replacement before the original is atomically replaced.
        verified = archive_files(temporary, release)
        if (verified.get("postplus-update.json") != contents or
                {name: body for name, body in verified.items() if name != "postplus-update.json"} !=
                {name: body for name, body in files.items() if name != "postplus-update.json"}):
            raise ValueError("Adding component metadata changed package files")
        os.replace(temporary, archive)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print(f"PASS packaged installed component metadata for {platform}/{arch}")


def modules(directory, platform, arch):
    release = version()
    extension = next(ext for plat, cpu, ext in PLATFORMS if (plat, cpu) == (platform, arch))
    archive = directory / f"postplus-{release}-{platform}-{arch}.{extension}"
    files = archive_files(archive, release)
    inventory = module_inventory(files, platform)
    if json.loads(files.get("postplus-update.json", b"{}")) != installed_manifest(files, platform, arch):
        raise ValueError("Full release package is missing its correct installed component metadata")
    for entry in inventory:
        # Including the digest avoids collisions and makes repeated packaging
        # deterministic. Assets are raw files; the server never extracts ZIPs.
        sha256 = entry["sha256"]
        asset = f"postplus-{release}-{platform}-{arch}-{sha256}.module"
        (directory / asset).write_bytes(files[entry["path"]])
        entry["asset"] = asset
    manifest = {"platform": platform, "arch": arch, "service_contract": 1,
                "minimum_version": "0.2.1", "files": inventory,
                "archive": {"asset": archive.name, "size": archive.stat().st_size,
                            "sha256": digest(archive.read_bytes())}}
    target = directory / f"postplus-update-{platform}-{arch}.json"
    target.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"PASS generated {len(inventory)} updater modules for {platform}/{arch}")


def checksums(directory):
    release = version()
    expected = {f"postplus-{release}-linux-x86_64.tar.gz",
                f"postplus-{release}-windows-x64.zip",
                f"postplus-{release}-macosx-arm64.tar.gz"}
    targets = []
    for platform, arch, extension in PLATFORMS:
        sidecar = directory / f"postplus-update-{platform}-{arch}.json"
        target = json.loads(sidecar.read_text(encoding="utf-8"))
        if (target["platform"], target["arch"]) != (platform, arch) or target["service_contract"] != 1:
            raise ValueError("Platform module manifest identity mismatch")
        archive = directory / f"postplus-{release}-{platform}-{arch}.{extension}"
        if (target["archive"]["asset"] != archive.name or target["archive"]["size"] != archive.stat().st_size or
                target["archive"]["sha256"] != digest(archive.read_bytes())):
            raise ValueError("Release archive checksum or size mismatch")
        files = archive_files(archive, release)
        baseline = installed_manifest(files, platform, arch)
        if json.loads(files.get("postplus-update.json", b"{}")) != baseline:
            raise ValueError("Release package installed baseline does not match its files")
        seen = set()
        for entry in target["files"]:
            if not update_path(entry["path"], platform) or entry["path"] in seen:
                raise ValueError("Invalid or duplicate update path")
            seen.add(entry["path"])
            if entry["asset"] != f"postplus-{release}-{platform}-{arch}-{entry['sha256']}.module":
                raise ValueError("Module asset is not its hash-addressed release file")
            contents = (directory / entry["asset"]).read_bytes()
            if contents != files[entry["path"]] or digest(contents) != entry["sha256"] or len(contents) != entry["size"]:
                raise ValueError("Module differs from the verified distribution")
            expected.add(entry["asset"])
        if seen != {name for name in files if update_path(name, platform)}:
            raise ValueError("Module inventory omits release files")
        if [{key: entry[key] for key in ("path", "sha256", "fingerprint", "size")}
                for entry in target["files"]] != baseline["files"]:
            raise ValueError("Module manifest differs from the packaged component baseline")
        targets.append(target)
        expected.add(sidecar.name)
    manifest = {"schema": 1, "repository": REPOSITORY, "version": release,
                "minimum_updater": 1, "targets": targets}
    (directory / "postplus-update.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    expected.add("postplus-update.json")
    actual = {path.name for path in directory.iterdir() if path.is_file() and path.name != "SHA256SUMS"}
    if actual != expected:
        raise ValueError(f"Incomplete or unexpected release assets: {sorted(actual ^ expected)}")
    lines = []
    for filename in sorted(expected):
        with (directory / filename).open("rb") as stream:
            checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        lines.append(f"{checksum}  {filename}\n")
    (directory / "SHA256SUMS").write_text("".join(lines), encoding="ascii", newline="\n")
    print("".join(lines), end="")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("version", "installed", "modules", "checksums"))
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--packages", type=Path, default=ROOT / "build/packages")
    parser.add_argument("--platform", choices=[item[0] for item in PLATFORMS])
    parser.add_argument("--arch")
    args = parser.parse_args()
    if args.command == "version":
        print(version())
    elif args.command == "installed":
        if not args.archive or not args.platform or not args.arch:
            parser.error("installed requires --archive, --platform and --arch")
        installed(args.archive, args.platform, args.arch)
    elif args.command == "modules":
        modules(args.packages, args.platform, args.arch)
    else:
        checksums(args.packages)


if __name__ == "__main__":
    main()
