# Third-party notices

PostPlus is licensed under GPL-3.0. The released executable archives also contain
or incorporate the following dependencies. Their license texts are included in
the `licenses` directory or beside the corresponding web assets.

| Component | Version | License | Source |
| --- | --- | --- | --- |
| PACE | 0.2.0 | MIT | <https://github.com/TabNahida/PACE/tree/v0.2.0> |
| c-ares | 1.34.8 | MIT | <https://github.com/c-ares/c-ares/tree/v1.34.8> |
| JSON for Modern C++ | 3.12.0 | MIT | <https://github.com/nlohmann/json/tree/v3.12.0> |
| OpenSSL | 3.6.1 | Apache-2.0 | <https://github.com/openssl/openssl/tree/openssl-3.6.1> |
| SQLite | 3.51.3 | Public domain | <https://www.sqlite.org/2026/sqlite-autoconf-3510300.tar.gz> |
| zlib | 1.3.1 | zlib License | <https://github.com/madler/zlib/tree/v1.3.1> |
| Tabler Icons | 3.34.1 | MIT | <https://github.com/tabler/tabler-icons/tree/v3.34.1> |

PACE copyright (c) 2026 Tab Nahida. Its complete MIT license is in
`licenses/pace-0.2.0.txt`.
c-ares copyright (c) 1998 Massachusetts Institute of Technology and
copyright (c) 2007–2023 Daniel Stenberg with many contributors. Its complete
MIT license is in `licenses/c-ares-1.34.8.txt`.
The independent TLS interoperability test uses Standalone Asio 1.34.2
(copyright (c) 2003–2025 Christopher M. Kohlhoff and contributors), under the
Boost Software License in `licenses/asio-1.34.2.txt`. Production targets do not
include Asio; its license is retained for source and test distributions.
Tabler attribution and license are in `web/icons-LICENSE.txt`.

Windows release executables use the statically linked Microsoft C/C++ runtime.
Linux and macOS packages use their operating system's C/C++ runtime and system
libraries; these system libraries are not redistributed in the archives.
PACE, c-ares, OpenSSL, SQLite and zlib are linked statically in the official packages.
PACE and PostPlus share the same pinned OpenSSL 3.6.1 libraries.

The matching PostPlus source and build instructions are available from each
release's source archive and version tag at <https://github.com/TabNahida/PostPlus>.
