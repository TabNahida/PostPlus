# Build dependencies

Build from the repository root with a C++20 toolchain and Xmake 2.9.8 or newer:

```sh
xmake f -m release -y
xmake build -y
```

The first configuration can compile third-party dependencies. The installed
PostPlus executables do not require Xmake, CMake, or the package cache at runtime.

## PACE configuration

`xmake.lua` uses the upstream package repository and a pinned version:

```lua
add_repositories("tab-repo https://github.com/TabNahida/repo-xmake.git")
add_requires("pace 0.1.1", {system = false, configs = {
    tls = true, dns = true, http1 = true, websocket = false, shared = false
}})
add_requireconfs("pace.openssl3", {override = true, version = "3.6.1",
    system = false, configs = {shared = false}})
add_requireconfs("pace.c-ares", {override = true, system = false,
    configs = {shared = false}})
```

The selected modules are `pace_runtime`, `pace_net`, `pace_http1`, `pace_tls`, and
`pace_dns`. WebSocket, HTTP/2, QUIC, HTTP/3, and intrusive profiling are disabled.
c-ares 1.34.8 is the pinned DNS dependency from the PACE recipe; Xmake resolves its
CMake build tooling automatically. The dependency graph overrides PACE's default
OpenSSL requirement with PostPlus's OpenSSL 3.6.1, keeping one static implementation
for transport, certificate management, signing, and cryptographic operations.
Do not remove that override or separately link another OpenSSL version.

Asio is used only by the independent TLS peer in `postplus-domain-tls-tests`;
production targets do not include or link it. JSON for Modern C++, SQLite, and zlib retain their existing pinned
versions. See [third-party notices](../THIRD_PARTY_NOTICES.md) for versions and
licenses; package archives include the `licenses` directory.

Inspect the resolved package graph without building PostPlus:

```sh
xmake require --info
```

## Repository troubleshooting

If Xmake reports that c-ares 1.34.8 is unavailable, the official package-recipe
cache may predate that version. Update the official repository specifically:

```sh
xmake repo --update xmake-repo
xmake repo --update tab-repo
xmake f -m release -y
```

An unrelated globally configured repository can delay Xmake's initial automatic
repository update. For a machine with the required recipe repositories already
cached, configuration can temporarily skip remote recipe updates at project scope:

```sh
xmake f -m release -y --policies=network.mode:private
```

This requires the pinned recipes to be present locally. It does not provide missing
recipes, and dependency source archives still need to be available or downloadable.
Use the normal configuration command after resolving repository access, or restore
public recipe updates explicitly with `--policies=network.mode:public`. No global
proxy settings or unrelated repositories need to be removed.
