# Third-party notices

PostPlus is licensed under GPL-3.0. The released executable archives also contain
or incorporate the following dependencies. Their license texts are included in
the `licenses` directory or beside the corresponding web assets.

| Component | Version | License | Source |
| --- | --- | --- | --- |
| Standalone Asio | 1.34.2 | Boost Software License 1.0 | <https://github.com/chriskohlhoff/asio/tree/asio-1-34-2> |
| JSON for Modern C++ | 3.12.0 | MIT | <https://github.com/nlohmann/json/tree/v3.12.0> |
| OpenSSL | 3.6.1 | Apache-2.0 | <https://github.com/openssl/openssl/tree/openssl-3.6.1> |
| SQLite | 3.51.3 | Public domain | <https://www.sqlite.org/2026/sqlite-autoconf-3510300.tar.gz> |
| Tabler Icons | 3.34.1 | MIT | <https://github.com/tabler/tabler-icons/tree/v3.34.1> |

Asio copyright (c) 2003–2025 Christopher M. Kohlhoff and contributors.
The complete Boost Software License is in `licenses/asio-1.34.2.txt`.
Tabler attribution and license are in `web/icons-LICENSE.txt`.

Windows release executables use the statically linked Microsoft C/C++ runtime.
Linux and macOS packages use their operating system's C/C++ runtime and system
libraries; these system libraries are not redistributed in the archives.
OpenSSL and SQLite are linked statically in the official packages.

The matching PostPlus source and build instructions are available from each
release's source archive and version tag at <https://github.com/TabNahida/PostPlus>.
