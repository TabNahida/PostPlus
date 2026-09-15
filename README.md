# PostPlus

A modular C++20 mail server for Linux, Windows, and macOS. PostPlus uses **standalone Asio**, **OpenSSL 3**, **SQLite**, and **xmake**, with separate processes for authentication, storage, mail protocols, delivery, filtering, and the web interface.

## Features

- SMTP submission and reception, POP3, an IMAP subset, and shared MIME parsing.
- A native C++ supervisor that starts, monitors, and stops all nine services.
- Browser setup for a new installation: domain, administrator account, ports, TLS, relay, and ClamAV settings.
- Webmail and web administration with account management, queue inspection, and service logs. Accounts are created by administrators; there is no public registration.
- English interfaces with a Simplified Chinese language switch on setup, sign-in, Webmail, and administration pages.
- Persistent mailboxes and delivery queues, per-recipient retries, local delivery deduplication, and quarantine for rejected mail.
- Structured, rotating logs with administrator-only access through the web interface and API.
- GitHub Actions builds and tests for all three platforms in Debug and Release.

PostPlus is under active development. Version 0.1 supports local mail workflows and delivery through an SMTP relay; it does not yet provide complete IMAP compatibility or a production capacity guarantee. See [Current scope](#current-scope).

## Quick start

Install a C++20 compiler and [xmake](https://xmake.io/) 2.9.8 or newer:

- **Windows:** Visual Studio 2022 or newer with Desktop development with C++.
- **Linux:** GCC 12 or newer, or a Clang toolchain with C++20 coroutine support.
- **macOS:** Xcode Command Line Tools with C++20 support.

From the repository root:

```sh
xmake f -m release -y
xmake build -y
xmake run postplus
```

xmake installs the pinned Asio, nlohmann/json, OpenSSL, and SQLite dependencies. **Python is only needed for integration tests.** The server and its launcher are native C++ programs.

When `config/postplus.json` does not exist, the launcher prints a local setup URL. Open the **complete URL**, including its `#token=...` fragment, in a browser on the server machine. The setup page listens on `127.0.0.1:8080` by default.

1. Choose the mail domain and create the first administrator. Use a full email address in that domain and a password of at least 12 bytes.
2. Select local development mode, or provide a matching PEM certificate and unencrypted private key for TLS. Public listening addresses require TLS.
3. Review the storage directory and service ports. Optionally configure an SMTP relay and ClamAV.
4. Save the configuration, then open Webmail from the success page. Sign in as the administrator to create accounts and inspect the server.

Setup generates a private service-token file beside the configuration, provisions the administrator through the authentication service, and starts the normal service group. No service-token environment variable is needed for this workflow. Press **Ctrl+C** in the launcher terminal to stop the group; running the same command again loads the saved configuration.

An existing configuration is never replaced by the wizard. To change an established installation, stop PostPlus, edit its configuration, and restart it.

### Launcher options

```sh
xmake run postplus --config "config/postplus.json" --setup-port 8080 --web-root "web"
xmake run postplus --help
```

`--config` defaults to `config/postplus.json`. `--setup-port` selects the temporary setup listener. `--web-root` selects setup assets and the web root saved by the wizard; discovery checks a `web` directory beside the executable, then `./web`. Existing installations use their configured `web_root`.

Build outputs are in `build/<platform>/<arch>/<mode>/`. For a standalone installation, keep `postplus` and all `postplus-*` service executables together, supply the `web` assets, and run the launcher directly with an appropriate configuration path. Paths with spaces are supported. OS service installation and automatic boot integration are not bundled.

## Services

| Executable | Responsibility | Default listener |
| --- | --- | --- |
| `postplus` | First-run setup and service supervision | Setup only: loopback 8080 |
| `postplus-auth` | Accounts, password verification, administrator roles | Loopback 18081 |
| `postplus-storage` | Mailboxes, persistent UIDs, raw MIME, delivery queue | Loopback 18082 |
| `postplus-filter` | MIME inspection, spam rules, EICAR detection, ClamAV | Loopback 18083 |
| `postplus-transfer` | Outbound SMTP through a configured relay | Loopback 18084 |
| `postplus-delivery` | Queue processing, retries, local delivery, quarantine | Loopback 18085, instance lock only |
| `postplus-smtp` | ESMTP reception and authenticated submission | 2525 |
| `postplus-pop3` | POP3 mailbox access | 1110 |
| `postplus-imap` | IMAP mailbox access | 1143 |
| `postplus-web` | Webmail, administration, HTTP API | 8080 |
| `postplus-ctl` | Command-line administration | None |

The public-facing listeners default to loopback. Internal JSON RPC always uses IPv4 loopback and a shared service token. Authentication and storage each own their SQLite database; the other services access them through RPC.

Mail clients use full email addresses as usernames. SMTP supports STARTTLS, POP3 supports STLS, and IMAP supports STARTTLS. Configuring a TLS certificate enables HTTPS for the web listener. Unencrypted authentication is allowed only when explicitly enabled and the client connects over loopback.

## Configuration and administration

[config/postplus.example.json](config/postplus.example.json) documents the configuration shape. Relative filesystem paths resolve from the configuration file's directory.

For manually managed installations, `service_token_env` names the shared-token environment variable, defaulting to `POSTPLUS_SERVICE_TOKEN`. When that variable is unset or empty, `service_token_file` supplies the token. Tokens must contain at least 32 characters. Keep the token file, configuration, databases, and TLS private keys accessible only to the service account and trusted administrators.

Accounts can also be managed from the terminal:

```sh
xmake run postplus-ctl create-user user@localhost --config config/postplus.json
xmake run postplus-ctl create-user admin@localhost --admin --config config/postplus.json
xmake run postplus-ctl password user@localhost --config config/postplus.json
xmake run postplus-ctl users --config config/postplus.json
xmake run postplus-ctl stats --config config/postplus.json
xmake run postplus-ctl queue --config config/postplus.json
```

Replace `localhost` with the configured domain. Password commands prompt through standard input rather than command-line arguments. The services must already be running.

### Logs

Open **Administration → Service logs** to view recent events and filter by service or level. Each JSON Lines entry contains a UTC timestamp, service name, severity, process ID, and message.

| Setting | Default | Meaning |
| --- | --- | --- |
| `log_dir` | `<data_dir>/logs` | Directory for per-service `.jsonl` files |
| `log_level` | `info` | Minimum severity: `debug`, `info`, `warn`, or `error` |
| `log_max_bytes` | `5242880` | Rotation size per file, in bytes |
| `log_backups` | `3` | Rotated files retained per service |

For example, `smtp.jsonl` rotates to `smtp.jsonl.1`, with older files numbered consecutively. The web viewer reads bounded recent tails; use the files for a complete retained history. Passwords, setup credentials, and message bodies are excluded from service log events. Language selection changes interface labels; stored event messages remain in English.

### Outbound mail and filtering

External recipients require `smarthost_host` and `smarthost_port`. Relay TLS supports `starttls` and `implicit`; configure `smarthost_username` and the environment variable named by `smarthost_password_env` when relay authentication is required. Outbound TLS validates the certificate chain and hostname. OpenSSL's `SSL_CERT_FILE` and `SSL_CERT_DIR` can provide a trust store. Unencrypted relay connections are restricted to loopback and cannot authenticate.

The built-in filter provides baseline spam rules and the EICAR test signature. Full antivirus scanning requires a separately maintained ClamAV service configured through `clamav_host` and `clamav_port`. Scanner failures defer delivery for retry; explicit rejection keeps the message in the quarantine queue.

## Build and test

```sh
xmake f -m debug -y
xmake build -y
xmake test -v
node tests/web_test.js
python tests/integration.py --build-dir build --mode debug
```

Web language and asset checks require Node.js 22 or newer. Integration tests require Python 3.10 or newer. They exercise real service processes, mail protocols, persistence, TLS relay behavior, HTTP security, first-run setup, and native supervisor shutdown. Tests use isolated data directories, temporary accounts, local ports, and a simulated SMTP relay; they do not send public email. Diagnostics are written under `build/test-runs/`.

[GitHub Actions](.github/workflows/ci.yml) runs the build, C++ tests, web checks, and integration suite on Linux, Windows, and macOS in both build modes.

## Current scope

- IMAP implements a single `INBOX` with a documented command subset. Folders, APPEND, COPY, IDLE, ENVELOPE, and BODYSTRUCTURE are not implemented. POP3 does not yet provide an exclusive maildrop lock.
- Webmail supports plain-text reading and composition. Attachment upload/download, HTML mail rendering, and a Sent folder are not implemented.
- Outbound mail uses a configured SMTP relay. Direct MX delivery, SPF, DKIM, DMARC, DSN generation, multiple domains, and multi-host high availability are not implemented.
- SMTP queues mail transactionally. Local delivery is idempotent; an outbound retry after an interrupted acknowledgement can produce a duplicate, as with other at-least-once SMTP delivery systems.
- Sessions use bounded worker pools, SQLite serializes writes, and delivery uses one worker. Capacity for hundreds or thousands of active users requires workload testing and further development.

Protocol compatibility and security are the development priorities. See the [protocol support matrix](docs/protocols.md), [architecture](docs/architecture.md), [HTTP API](docs/api.md), and [internal RPC contracts](docs/internal-contract.md).

## Repository layout

```text
include/postplus/       Shared networking, MIME, setup, and process interfaces
src/core/              Asio/TLS/HTTP, logging, MIME, setup, process management
src/services/          Nine independent service entry points
src/tools/             Native launcher and administration CLI
config/                Example configuration
web/                   Static Webmail, administration, setup, and translations
tests/                 C++ tests, web checks, and Python integration suites
.github/workflows/     Cross-platform CI
```

## License

PostPlus is licensed under the [GNU General Public License v3.0](LICENSE).
