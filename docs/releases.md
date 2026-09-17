# Binary releases

Download an archive for your computer from [GitHub Releases](https://github.com/TabNahida/PostPlus/releases).
Each archive contains the native launcher, its service executables, web pages,
documentation, the example configuration, and license notices. No compiler,
xmake, Python, Node.js, or separate OpenSSL/SQLite installation is needed to run
an official package.

## Supported packages

| Archive suffix | System |
| --- | --- |
| `windows-x64.zip` | 64-bit Windows 10 or newer |
| `linux-x86_64.tar.gz` | Ubuntu 24.04 or a compatible 64-bit Linux distribution with glibc 2.39+ and the GCC 13 C++ runtime |
| `macosx-arm64.tar.gz` | Apple Silicon, macOS 15 or newer |

Other architectures and older Linux/macOS versions can build from source. The
macOS package is unsigned and not notarized; macOS may require permission to
open the downloaded executable under **System Settings → Privacy & Security**.

## Verify and start

Download the archive and `SHA256SUMS` from the same release. Check the archive's
SHA-256 value against its entry before extracting it:

```powershell
# Windows PowerShell
Get-FileHash .\postplus-0.1.0-windows-x64.zip -Algorithm SHA256
Expand-Archive .\postplus-0.1.0-windows-x64.zip -DestinationPath .
Set-Location .\postplus-0.1.0
.\postplus.exe
```

```sh
# Linux
sha256sum postplus-0.1.0-linux-x86_64.tar.gz
tar -xzf postplus-0.1.0-linux-x86_64.tar.gz
cd postplus-0.1.0
./postplus
```

```sh
# macOS
shasum -a 256 postplus-0.1.0-macosx-arm64.tar.gz
tar -xzf postplus-0.1.0-macosx-arm64.tar.gz
cd postplus-0.1.0
./postplus
```

Keep the entire extracted directory together. Run from a writable location.
Open the setup URL printed in the terminal and enter its one-time password.
The [getting started guide](getting-started.md) and
[中文入门指南](getting-started.zh-CN.md) explain the configuration process.
Use `./postplus --setup-port 9081` (Windows: `.\postplus.exe --setup-port 9081`)
if the first-run administration port is already in use.

## Reproduce an archive

Use the matching release tag. Dependencies are pinned by `xmake.lua`.

```sh
xmake f -m release -y
xmake build -y
xmake test -v
xmake pack -f targz --autobuild=n -o build/packages postplus
python tests/release_package_test.py --packages build/packages --platform linux --arch x86_64
```

For Windows configure with `--runtimes=MT`, select `-f zip`, and use
`--platform windows --arch x64` for the archive check. macOS uses `-f targz` and
`--platform macosx --arch arm64`. Package verification requires Python 3.12+.
The check validates the complete archive file list and dependencies, extracts it
into a fresh directory, opens browser setup, provisions an isolated account,
starts all ten services, checks both web interfaces, and stops the native server.

## Release process

The [release workflow](../.github/workflows/release.yml) runs the complete
Debug/Release test matrix on Linux, Windows, and macOS. Separate native jobs
build the three release packages and run the extracted-package checks.
Only when every job passes does the publication job calculate `SHA256SUMS`
and publish the version tag with all three archives. Only that final job has
repository write permission.

A manual run on a branch uploads tested packages as workflow artifacts without
publishing a release. To publish, update `set_version` and add matching release
notes in `docs/releases/<version>.md`, then push a tag named `v<version>`.
The workflow rejects a tag that does not match the project version.
