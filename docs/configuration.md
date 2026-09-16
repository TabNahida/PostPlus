# Configuration reference

[Beginner guide](getting-started.md) · [中文入门指南](getting-started.zh-CN.md) · [HTTP API](api.md) · [Example file](../config/postplus.example.json)

For a new installation, run `postplus` and use the browser wizard. For an initialized installation, use **Administration → Server settings** for routine changes. This reference also covers manual configuration and recovery.

## Configuration location and lifecycle

The launcher's default path is `config/postplus.json`, relative to its working directory. `xmake run postplus` uses the repository root. Select another path explicitly:

```sh
xmake run postplus --config "/srv/postplus/config/postplus.json"
```

On Windows, for example:

```powershell
.\postplus.exe --config "D:\Mail Server\config\postplus.json"
```

A missing file opens setup. A regular JSON configuration without an active service-token environment value, without a `service_token_file` path, and without `setup_complete: true` can enter setup to finish an uninitialized installation. An established installation with a broken credential file fails explicitly; it is not silently reinitialized. Correct malformed or unreadable configurations before trying again.

Setup prints its temporary password only in the terminal and listens on `127.0.0.1:8081` by default. `--setup-port` changes that temporary listener. The final administration port is the separate `ports.admin` setting; Webmail uses `ports.web`. Setup completion preserves the selected data directory of an existing configuration and saves a private backup before replacing it.

### Browser saves

The settings page reads the current values and a revision of the file. A save:

1. Verifies the administrator session, CSRF token, and configuration revision.
2. Checks supported fields, types, ranges, domain, listener addresses, distinct ports, TLS files, and related resource limits.
3. Writes any new relay password into a private secret file.
4. Creates a private configuration backup named `<config filename>.backup-<random suffix>` beside the configuration, then replaces the file atomically.
5. Reports that a manual restart is required and returns the admin and Webmail URLs that will apply afterward. Current services continue running with their existing settings.

A concurrent edit returns a conflict; reload the settings before saving again. Configuration paths (`data_dir`, `web_root`, `log_dir`) are displayed read-only, and service-token configuration is not editable through the API. Save-generated backups and superseded relay-secret files are not automatically pruned. Keep the secrets needed by retained backups; remove obsolete copies deliberately after verifying recovery needs.

To apply a saved change, press **Ctrl+C** in the launcher terminal, wait for all children to exit, then run the same launch command with the same configuration path. That restart closes connections and clears Web sessions. If a changed port is occupied or a dependency fails during startup, the launcher reports the error and stops. Restore the backup or correct the file and run again; automatic rollback is not provided. If you run service executables independently, restart them manually after a save.

### Manual editing

Stop the whole service group before editing the file. Keep a protected copy of the old configuration, edit valid JSON, then restart with the same `--config` path. JSON uses double-quoted keys/strings and does not allow comments or trailing commas. Numbers and booleans are unquoted. The example file is a reference, not a replacement for an initialized installation's credentials and paths.

Relative filesystem paths resolve from the **configuration file's directory**, including `data_dir`, `web_root`, `log_dir`, TLS paths, and secret-file paths. For `config/postplus.json`, `"data_dir": "../data"` points at the repository's `data` directory. On Windows, use forward slashes (`D:/Mail/data`) or escaped backslashes (`D:\\Mail\\data`) inside JSON strings. Wizard-created configurations may store absolute paths.

## Identity, paths, and listeners

| Field | Default | Meaning |
| --- | --- | --- |
| `domain` | `localhost` | Single local mailbox domain, such as `example.com`. It is the part after `@`, not necessarily the TLS hostname. Use an ASCII DNS name. Changing it does not rename accounts or migrate mailboxes. |
| `bind` | `127.0.0.1` | Address for SMTP, POP3, IMAP, and Webmail. Accepts an IPv4 or IPv6 address, not a hostname. `0.0.0.0` listens on all IPv4 interfaces. |
| `admin_bind` | `127.0.0.1` | Independent administration listener address. Keep it on loopback for local or SSH-tunnel access. |
| `data_dir` | `../data` beside the configuration directory | Authentication/storage databases and default logs. Read-only in the installed web settings. |
| `web_root` | Selected by setup or supplied in the configuration | Static application assets. Setup discovers `web` beside the executable, then `./web`; `--web-root` overrides discovery. Read-only in installed settings. |
| `log_dir` | `<data_dir>/logs` | Structured log files. Read-only in installed settings. |
| `setup_complete` | Absent in manual files | Set by the wizard to identify a completed installation. Do not clear it to reset a server. |

### Ports

Each PostPlus port must be a distinct integer from **1 to 65535**, even when listeners use different addresses. The administration port cannot equal the Webmail port. Low ports can require OS permissions. Internal listeners always use IPv4 loopback; do not publish them through a proxy or firewall.

| Configuration field | Default | Listener and intended clients |
| --- | --- | --- |
| `ports.admin` | `8081` | Administration HTTP/HTTPS; only administrators can sign in. |
| `ports.web` | `8080` | Webmail HTTP/HTTPS; regular users and administrators. |
| `ports.smtp` | `2525` | SMTP reception and authenticated submission. Supports STARTTLS. |
| `ports.pop3` | `1110` | POP3 access; supports STLS. |
| `ports.imap` | `1143` | IMAP command subset; supports STARTTLS. |
| `ports.auth` | `18081` | Internal authentication RPC. |
| `ports.storage` | `18082` | Internal mailbox and queue RPC. |
| `ports.filter` | `18083` | Internal filtering RPC. |
| `ports.transfer` | `18084` | Internal outbound transfer RPC. |
| `delivery_lock_port` | `18085` | Loopback instance lock for the delivery worker; has no API. This is a top-level field in the saved file. |

The setup API uses `ports.delivery_lock` for the form and translates it to `delivery_lock_port`. Installed settings and configuration files use the top-level field.

Changing a port does not enable another protocol mode. The server's SMTP/POP3/IMAP listeners support TLS upgrades, not implicit TLS. Enabling the certificate changes both browser interfaces to HTTPS. To receive mail directly from internet senders, arrange inbound TCP 25: DNS MX does not specify a custom port. See the [domain setup guide](getting-started.md#6-move-from-a-local-trial-to-a-real-domain).

## TLS and account security

| Field | Default | Accepted value / effect |
| --- | --- | --- |
| `allow_insecure_auth` | `false`; explicit local wizard mode selects `true` | Allows unencrypted authentication only when the client connects over loopback. It never permits public plaintext authentication. |
| `tls_certificate` | Empty | Readable PEM certificate-chain file on the server. |
| `tls_private_key` | Empty | Matching, readable, unencrypted PEM private-key file on the server. |
| `max_auth_attempts` | `5` | Integer 1–20; failed login attempts allowed per mail-protocol connection. |
| `auth_pbkdf2_iterations` | `600000` | Integer 600000–2000000; PBKDF2-HMAC-SHA256 password work factor. Applies to new/changed passwords and upgrades lower-work-factor hashes after successful authentication. |
| `max_password_bytes` | `1024` | Integer 12–4096; maximum authentication password size in bytes. Minimum accepted password length is 12 bytes. |
| `web_session_seconds` | `3600` | Integer 60–86400; session lifetime, in seconds, for each browser service. |
| `max_web_sessions` | `1024` | Integer 1–10000; maximum in-memory sessions per browser service. |

Browser setup/settings require a valid matching certificate/key pair when either the mail/Webmail bind or admin bind is non-loopback, and require insecure authentication to be disabled. For a certificate-free local trial, both binds must be loopback and local plaintext authentication must be explicitly enabled.

One certificate/key pair is shared across the TLS listeners. Access the server through a hostname covered by the certificate. The generated link is a convenience based on configured addresses; if a wildcard bind or separate mailbox domain produces a different name, use the actual certificate hostname. Certificate issuance, renewal, DNS, and firewall changes are administered outside PostPlus. Replace renewed files and restart the service group.

Administration and Webmail have separate processes, ports, session stores, and cookie names (`pp_admin_session` and `pp_session`). Cookies are HttpOnly and SameSite=Strict, and Secure over HTTPS. A browser still scopes cookies by hostname rather than port; avoid hosting untrusted applications on the same hostname and treat separate ports as routing separation, not a complete browser security boundary.

## Message, connection, and storage limits

Sizes are bytes, not decimal megabytes. **1 MiB = 1048576 bytes**; **1 GiB = 1073741824 bytes**. These limits do not reserve disk space or establish a supported user count.

| Field | Default | Browser-validated range | Meaning |
| --- | --- | --- | --- |
| `max_message_bytes` | `10485760` (10 MiB) | 1024–104857600 | Maximum raw message size. MIME/Base64 encoding can make messages larger than their original attachments. |
| `max_recipients` | `100` | 1–100 | Maximum SMTP recipients per message. |
| `max_connections` | `32` | 1–1024 | Concurrent sessions per listening service; each active connection consumes a worker. Excess sessions are closed. |
| `timeout_seconds` | `30` | 1–300 | General network timeout, in seconds. |
| `smtp_data_timeout_seconds` | `120` | 1–3600 | Total SMTP DATA upload deadline, in seconds. |
| `max_mailbox_bytes` | `1073741824` (1 GiB) | 1024–2147483647 | Byte limit per mailbox; must be at least `max_message_bytes`. |
| `max_mailbox_messages` | `10000` | 1–100000 | Message-count limit per mailbox. |
| `max_queue_bytes` | `1073741824` (1 GiB) | 1024–2147483647 | Queue byte limit; must be at least `max_message_bytes`. A separate recipient job accounts for its own copy. |
| `max_queue_messages` | `100000` | 1–1000000 | Maximum queued recipient jobs. |

Lowering a limit does not remove existing mail or shrink databases. New writes can fail once a mailbox or queue reaches its limit. Monitor queue age, free disk space, authentication latency, and memory before raising concurrency substantially. The current implementation has a single delivery worker and serialized SQLite writes.

## Outgoing SMTP relay

An empty relay host permits local-domain mail only. External recipients require a configured relay that accepts your sender domain.

| Field | Default | Meaning |
| --- | --- | --- |
| `smarthost_host` | Empty | Relay hostname. Use the provider's certificate hostname. |
| `smarthost_port` | `587` | Integer 1–65535. Use the provider's documented port. |
| `smarthost_tls` | `starttls` | `starttls`, `implicit`, or `none`. STARTTLS is commonly on 587; implicit TLS commonly on 465. `none` is limited to loopback and cannot authenticate. |
| `smarthost_timeout_seconds` | `30` | Integer 1–300; total outbound transfer deadline in seconds. |
| `smarthost_username` | Empty | Relay account, if authentication is required. |
| `smarthost_password_env` | `POSTPLUS_SMARTHOST_PASSWORD` | Name of the environment variable supplying a relay password. A nonempty value overrides the saved password file. |
| `smarthost_password_file` | Empty | Private relay-password file. Generated when a password is entered in the setup/settings page; not exposed for editing through that page. |

The browser-only field `smarthost_password` writes a new secret file named `<config filename>.relay-password-<random suffix>`. It is never stored as a plaintext value in the JSON configuration and never returned by the settings API. Leaving the password input blank keeps the saved password. The page also supports clearing the saved password (`clear_smarthost_password: true` in a settings request). This removes the active file reference and retains the old file for backups. Clearing and entering a new password in one request is rejected. To stop using relay authentication altogether, clear the relay username as well. Do not delete secrets still referenced by the active configuration or retained backups.

The saved password file is protected, but it is still a recoverable credential. Back it up securely. If your environment variable overrides it, changes to the saved value do not change the effective password until you unset/update that variable and restart the launcher.

Outbound TLS checks certificate trust and hostname. `SSL_CERT_FILE` or `SSL_CERT_DIR` can configure OpenSSL's trust store. Domain verification and any SPF/DKIM policy supplied by your relay are external setup steps. PostPlus does not currently implement direct MX delivery, SPF, DKIM signing, or DMARC processing.

## Mail filtering

| Field | Default | Meaning |
| --- | --- | --- |
| `clamav_host` | Empty | Host of a separately running ClamAV `clamd`; empty disables ClamAV scanning. |
| `clamav_port` | `3310` | Integer 1–65535; clamd INSTREAM listener. |
| `clamav_timeout_seconds` | `15` | Integer 1–120; scan deadline shared by the message's MIME parts. |
| `spam_threshold` | `5` | Integer 1–1000; a score at or above this value rejects the message. |
| `blocked_terms` | `[]` | Up to 1000 nonempty strings, each at most 256 bytes. A match rejects the message. In the browser, enter one term per line. |
| `spam_rules` | Built-in weighted rules below | Up to 1000 objects with `term` and positive `weight` no greater than 1000. Supplying an array replaces the built-in rules. |

Default rules:

```json
[
  {"term": "lottery winner", "weight": 3},
  {"term": "urgent money transfer", "weight": 3},
  {"term": "free money", "weight": 2},
  {"term": "viagra", "weight": 2},
  {"term": "click here", "weight": 1}
]
```

Rules examine decoded text and headers; each matching weighted rule contributes once. Baseline EICAR test-signature detection is always present. It is not a full antivirus engine. ClamAV installation, daemon access control, and signature updates are separate operational tasks. Scanner errors defer delivery; explicit rejections are retained in quarantine. There is no quarantine-release interface yet.

## Logging

| Field | Default | Accepted value |
| --- | --- | --- |
| `log_dir` | `<data_dir>/logs` | Directory for per-service JSON Lines files; read-only through installed web settings. |
| `log_level` | `info` | Minimum severity: `debug`, `info`, `warn`, `error`. |
| `log_max_bytes` | `5242880` (5 MiB) | Integer 1024–104857600; maximum size per active file before rotation. |
| `log_backups` | `3` | Integer 1–10; rotated files retained per service. |

For example, `smtp.jsonl` rotates to `smtp.jsonl.1`, `.2`, and so on. Entries contain UTC `timestamp`, `service`, `level`, `pid`, and `message`. Service names include the separate `admin` and `web` processes. The CLI writes into the `postplus` log.

**Service logs** in administration shows bounded recent entries with service and exact-level filters. It is a diagnostic viewer, not an export of all retained history. Use the log files for longer investigations. Stored event text remains English regardless of the browser's language. Credentials and message bodies are excluded from logged events; protect the directory because operational metadata can still be sensitive.

## Internal service credentials

| Field | Default | Meaning |
| --- | --- | --- |
| `service_token_env` | `POSTPLUS_SERVICE_TOKEN` | Name of an environment variable containing the shared internal RPC token. |
| `service_token_file` | Empty in the manual example | Fallback token file generated by setup. A nonempty environment value takes precedence. |

Internal tokens must be 32–1024 bytes and contain no embedded CR, LF, or NUL. The token file must be a regular, readable file; the loader rejects symlinked or oversized secret files. The wizard creates private files using owner-only permissions on Unix and restrictive ACLs on Windows. Keep configuration, secrets, databases, and TLS private keys accessible only to the service account and trusted administrators.

An environment variable present in your terminal is inherited by child service processes. To change such a value, stop the **launcher** and run it again in the updated environment.

Do not send the internal token to mail clients or use it as an administrator password. It grants access to internal RPC, so every process in one installation must use the same effective token. The administration page intentionally cannot rotate or reveal it.

## Example: local development

For a new server, use the wizard instead of hand-creating this file. This abbreviated example explains the shape; replace `service_token_file` with an existing private credential generated for the installation.

```json
{
  "domain": "localhost",
  "bind": "127.0.0.1",
  "admin_bind": "127.0.0.1",
  "data_dir": "../data",
  "web_root": "../web",
  "service_token_file": "postplus.json.service-token-REPLACE_WITH_ACTUAL_SUFFIX",
  "allow_insecure_auth": true,
  "ports": {
    "admin": 8081,
    "web": 8080,
    "smtp": 2525,
    "pop3": 1110,
    "imap": 1143,
    "auth": 18081,
    "storage": 18082,
    "filter": 18083,
    "transfer": 18084
  },
  "delivery_lock_port": 18085
}
```

## Example: TLS and external relay changes

The following is an illustrative **set of changes**, not a complete replacement configuration. Apply it through Server settings or merge it into the existing file while PostPlus is stopped. Preserve data paths and service credentials. The example uses a real mailbox domain, shared public mail/Webmail bind, local-only administration, and a STARTTLS relay:

```json
{
  "domain": "example.com",
  "bind": "0.0.0.0",
  "admin_bind": "127.0.0.1",
  "allow_insecure_auth": false,
  "tls_certificate": "../certs/fullchain.pem",
  "tls_private_key": "../certs/privkey.pem",
  "smarthost_host": "smtp.provider.example",
  "smarthost_port": 587,
  "smarthost_tls": "starttls",
  "smarthost_username": "provider-account",
  "smarthost_password_env": "POSTPLUS_SMARTHOST_PASSWORD"
}
```

Replace the illustrative hostnames and paths with your own. Supply the relay password in the browser or through the named environment variable. DNS, inbound TCP 25, certificate naming, relay domain verification, and firewall rules remain necessary; see the [beginner guide](getting-started.md#6-move-from-a-local-trial-to-a-real-domain).

## Move data or restore a backup

1. Stop the native launcher and wait for all children to exit.
2. Back up configuration, every referenced secret, TLS files, and the complete data directory together.
3. Copy the complete data directory to its new location, preserving service-account permissions. Do not mix authentication and storage databases from different snapshots.
4. Edit `data_dir` and, if needed, `log_dir` and other paths. Changing `data_dir` alone does not update an explicitly configured `log_dir`.
5. Start using the explicit configuration path. Check login, mailbox contents, UIDs, queue state, and logs before accepting new mail.

There is no automated data-migration or online-backup facility. Follow [Backup and recovery](architecture.md#backup-and-recovery) for SQLite WAL considerations.
