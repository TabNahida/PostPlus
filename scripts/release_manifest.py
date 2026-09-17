#!/usr/bin/env python3
"""Validate a release version and write SHA-256 checksums (build tooling only)."""
import argparse
import hashlib
import os
from pathlib import Path
import re

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


def checksums(directory):
    release = version()
    expected = {f"postplus-{release}-linux-x86_64.tar.gz",
                f"postplus-{release}-windows-x64.zip",
                f"postplus-{release}-macosx-arm64.tar.gz"}
    actual = {path.name for path in directory.iterdir() if path.is_file() and path.name != "SHA256SUMS"}
    if actual != expected:
        raise ValueError(f"Incomplete or unexpected release assets: expected {expected}, got {actual}")
    lines = []
    for filename in sorted(expected):
        with (directory / filename).open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        lines.append(f"{digest}  {filename}\n")
    (directory / "SHA256SUMS").write_text("".join(lines), encoding="ascii", newline="\n")
    print("".join(lines), end="")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("version", "checksums"))
    parser.add_argument("--packages", type=Path, default=ROOT / "build/packages")
    args = parser.parse_args()
    if args.command == "version":
        print(version())
    else:
        checksums(args.packages)


if __name__ == "__main__":
    main()
