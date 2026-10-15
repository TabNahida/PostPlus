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

Setup prints its temporary password only in the terminal. On an interactive first launch, choose `127.0.0.1` for local setup or `0.0.0.0` for remote setup, then enter the browser-facing hostname/IP for remote access. Non-interactive launches default to `127.0.0.1:8081`. `--setup-port` changes that temporary listener. The final administration port is the separate `ports.admin` setting; Webmail uses `ports.web`. Setup completion preserves the selected data directory of an existing configuration and saves a private backup before replacing it.

### First-run command-line options

Setup listener options apply only while the wizard is open. They are not configuration-file or web settings:

| Option | Meaning |
| --- | --- |
| `--setup-bind IP` | IPv4/IPv6 listening address. Skips the interactive address choice; non-interactive default is `127.0.0.1`. |
| `--setup-port PORT` | Temporary listening port, 1–65535; default 8081. |
| `--setup-host HOST` | Advertised hostname/IP without scheme or port. Required with `0.0.0.0` or `::`. Host/Origin checks accept this host. |
| `--setup-tls-certificate PATH` | PEM chain for the wizard's HTTPS listener. |
| `--setup-tls-private-key PATH` | Matching unencrypted PEM key. Both TLS options must be supplied together. |

```sh
xmake run postplus --setup-bind 127.0.0.1 --setup-port 9081
```

For direct remote setup without an existing certificate:

```sh
postplus --setup-bind 0.0.0.0 --setup-host mail.example.com
```

For optional HTTPS setup with an existing certificate:

```sh
postplus --setup-bind 0.0.0.0 --setup-port 9443 --setup-host mail.example.com \
  --setup-tls-certificate /srv/certs/fullchain.pem --setup-tls-private-key /srv/certs/privkey.pem
```

Remote HTTP setup does not require a certificate. HTTP sends the temporary setup password and administrator credentials without encryption; use a trusted network, the optional HTTPS listener, or an SSH tunnel (`ssh -L 8081:127.0.0.1:8081 user@server`) when encryption is needed. You can request a certificate inside the wizard. Configure the permanent service addresses separately in the form; their network TLS requirements still apply.

### Reset mail data

Stop PostPlus before running:

```sh
xmake clean-data --config=config/postplus.json --dry-run
xmake clean-data --config=config/postplus.json
```

The native cleanup tool removes `auth.sqlite3`, `storage.sqlite3`, and their SQLite `-wal`, `-shm`, and `-journal` files from the configured data directory. This deletes accounts, mail, drafts, folder state, user quotas, delivery queues, and quarantine. It preserves the configuration, logs, certificate files, and unrelated files. It refuses symlink targets and data directories held by running authentication/storage processes.

The retained configuration is marked `setup_required: true`; the next normal launch prints a fresh setup password and lets you create an administrator while keeping saved settings. The wizard clears that marker after successful provisioning. Review `--dry-run` and back up anything you need before resetting. `xmake clean` still cleans build output only.

### Browser saves

The settings page reads the current values and a revision of the file. A save:

1. Verifies the administrator session, CSRF token, and configuration revision.
2. Checks supported fields, types, ranges, domain, listener addresses, distinct ports, TLS files, and related resource limits.
3. Writes any new relay password into a private secret file.
4. Creates a private configuration backup named `<config filename>.backup-<random suffix>` beside the configuration, then replaces the file atomically.
5. Schedules an automatic restart of only the affected services when the native supervisor is available, and returns progress metadata plus the updated admin and Webmail URLs. Unaffected services continue running. Standalone service executables report that a manual restart is required.

A concurrent edit returns a conflict; reload the settings before saving again. Configuration paths (`data_dir`, `web_root`, `log_dir`) are displayed read-only, and service-token configuration is not editable through the API. Save-generated backups and superseded relay-secret files are not automatically pruned. Keep the secrets needed by retained backups; remove obsolete copies deliberately after verifying recovery needs.

Watch the service-restart panel after saving. Only affected services close their connections and restart. An administration-service restart ends the administration browser session; open its updated address and sign in again to inspect the result. Other service restarts preserve that session. A failed restart is reported without claiming the saved configuration is active. The native supervisor attempts to restore the previous snapshots of affected services, reporting `rolled_back: true` if they are restored; the saved file still contains the new settings, which remain pending. Correct those settings or restore the backup before retrying. If restoration also fails, the group stops. A full systemd relaunch cannot restore the previous process configuration after the supervisor exits.

**Server maintenance → Restart all services** restarts the complete group with the saved configuration. It does not save unsaved form edits. The supplied systemd installation automatically brings PostPlus back after this action. **Save and shut down** saves with automatic application disabled, then stops the service group without restarting it. Independently launched service executables have no supervisor, so restart them manually after a save using the same configuration path.

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

Each enabled PostPlus port must be a distinct integer from **1 to 65535**, even when listeners use different addresses. The four optional client ports (`submission`, `smtps`, `pop3s`, `imaps`) also accept **0** to disable their listeners. The administration port cannot equal the Webmail port. Low ports can require OS permissions. Internal listeners always use IPv4 loopback; do not publish them through a proxy or firewall.

| Configuration field | Default | Listener and intended clients |
| --- | --- | --- |
| `ports.admin` | `8081` | Administration HTTP/HTTPS; only administrators can sign in. |
| `ports.web` | `80` or `443` | Webmail HTTP, or HTTPS when TLS is configured. Explicit saved ports remain unchanged. |
| `ports.smtp` | `25` | SMTP reception and authenticated submission. Supports STARTTLS. |
| `ports.pop3` | `110` | POP3 access; supports STLS. |
| `ports.imap` | `143` | IMAP command subset; supports STARTTLS. |
| `ports.submission` | `587` | SMTP submission with STARTTLS and required mailbox authentication. |
| `ports.smtps` | `465` | SMTP submission with implicit TLS and required mailbox authentication. |
| `ports.pop3s` | `995` | POP3 over implicit TLS. |
| `ports.imaps` | `993` | IMAP over implicit TLS. |
| `ports.auth` | `18081` | Internal authentication RPC. |
| `ports.storage` | `18082` | Internal mailbox and queue RPC. |
| `ports.filter` | `18083` | Internal filtering RPC. |
| `ports.transfer` | `18084` | Internal outbound transfer RPC. |
| `delivery_lock_port` | `18085` | Loopback instance lock for the delivery worker; has no API. This is a top-level field in the saved file. |

The setup API uses `ports.delivery_lock` for the form and translates it to `delivery_lock_port`. Installed settings and configuration files use the top-level field.

SMTP 25, POP3 110 and IMAP 143 support TLS upgrades. The four dedicated client listeners start only when a certificate and private key are configured; set any to `0` to disable it. Their protocol mode follows the listener name, so changing its port preserves its TLS mode. Enabling the certificate changes both browser interfaces to HTTPS. Use **Apply standard ports** and save to replace old defaults in an existing configuration. Incoming Internet mail requires public TCP 25 because MX records cannot select a custom port. See [mail client settings](mail-clients.md).

## TLS and account security

| Field | Default | Accepted value / effect |
| --- | --- | --- |
| `allow_insecure_auth` | `false`; explicit local wizard mode selects `true` | Allows unencrypted authentication only when the client connects over loopback. It never permits public plaintext authentication. |
| `tls_certificate` | Empty | Readable PEM certificate-chain file on the server. |
| `tls_private_key` | Empty | Matching, readable, unencrypted PEM private-key file on the server. |
| `max_auth_attempts` | `5` | Integer 1–20; failed login attempts allowed per mail-protocol connection. |
| `auth_pbkdf2_iterations` | `600000` | Integer 600000–2000000; PBKDF2-HMAC-SHA256 password work factor. Applies to new/changed passwords and upgrades lower-work-factor hashes after successful authentication. |
| `max_password_bytes` | `1024` | Integer 12–4096; maximum authentication password size in UTF-8 bytes. The minimum and optional diversity rules are a separate live account policy, described below. |
| `web_session_seconds` | `3600` | Integer 60–86400; session lifetime, in seconds, for each browser service. |
| `max_web_sessions` | `1024` | Integer 1–10000; maximum in-memory sessions per browser service. |

Browser setup/settings require a valid matching certificate/key pair when either the mail/Webmail bind or admin bind is non-loopback, and require insecure authentication to be disabled. For a certificate-free local trial, both binds must be loopback and local plaintext authentication must be explicitly enabled.

One certificate/key pair is shared across the TLS listeners. Access the server through a hostname covered by the certificate. The generated link is based on configured addresses; if a wildcard bind or mailbox domain produces a different name, use the actual certificate hostname.

### Account password policy

Open **Administration → User accounts → Account password policy** to change requirements for new passwords. This policy is independent of server connection settings: it is stored in `auth.sqlite3`, applies immediately, and does not require a restart or rewrite `postplus.json`. Back up the authentication database to preserve it. Existing passwords still work after the policy changes; existing sessions remain valid. Creating an account or resetting its password must satisfy the current policy through every entry point, including the CLI. Resetting an actual password still revokes that account's sessions.

| Policy field | Default | Meaning |
| --- | --- | --- |
| `min_length` | `8` | Integer 8–128, at most the running `max_password_bytes`. Counts Unicode code points. |
| `require_uppercase` | `false` | Require at least one ASCII uppercase letter, `A–Z`. |
| `require_lowercase` | `false` | Require at least one ASCII lowercase letter, `a–z`. |
| `require_digit` | `false` | Require at least one ASCII digit, `0–9`. |
| `require_symbol` | `false` | Require at least one printable ASCII punctuation character, such as `!`, `@`, `-`, or `_`; spaces and emoji do not qualify. |

Non-ASCII characters count toward the minimum but not toward the optional ASCII categories. A code point is not always a visible character: combining marks count separately, and one emoji outside the BMP counts as one code point. Passwords are never trimmed or normalized. The maximum remains a separate byte limit, so 12 Chinese characters typically occupy 36 UTF-8 bytes. Fresh setup requires at least 8 code points and accepts at most 1024 bytes for its first administrator.

Saving a policy cannot set its minimum above the running byte cap. Before lowering `max_password_bytes` in server settings or a configuration file, ensure it still accommodates the policy and existing passwords; lowering that cap affects which existing passwords can be submitted on login after restart. If a manually reduced cap is below the stored minimum, lower the live minimum or restore the cap before creating or resetting accounts. Browser API details and stale-edit conflict handling are in the [password policy API](api.md#account-password-policy).

### Let's Encrypt certificates

Setup and **Administration → Server settings** include an ACME HTTP-01 certificate request panel. Enter a public DNS hostname and contact email, load/read the authority's terms, and explicitly accept them before requesting a certificate. Start with **Staging** to verify DNS and reachability, then select **Production** and accept its terms for a trusted certificate. Staging certificates are not trusted by mail clients or browsers.

The hostname's public A/AAAA records must reach this server and public **TCP port 80** must reach the temporary PostPlus challenge listener. Open/forward that port and stop any conflicting HTTP server before applying. HTTP-01 does not issue wildcard certificates. Domain/DNS records, firewall rules, privileged-port permissions, and NAT forwarding remain administrator responsibilities. On Linux/macOS, the process account needs permission to bind port 80.

ACME account credentials and issued PEM files are stored privately under `certificates/` beside the configuration file. Private-key contents are never returned through the API. After production issuance, use the returned file paths and save your settings. First-run setup starts the services with those paths; an existing supervised installation automatically restarts the affected services when the new paths are saved. Independently launched services require a manual restart. A failed request leaves the active certificate unchanged. Request a replacement before expiry, save the new paths and restart; scheduled automatic renewal is not implemented. Use separate parent directories for independent installations' certificate stores.

Administration and Webmail have separate processes, ports, session stores, and cookie names (`pp_admin_session` and `pp_session`). Cookies are HttpOnly and SameSite=Strict, and Secure over HTTPS. A browser still scopes cookies by hostname rather than port; avoid hosting untrusted applications on the same hostname and treat separate ports as routing separation, not a complete browser security boundary.

## Message, connection, and storage limits

The web form provides B, KiB, MiB, GiB, and TiB selectors. Configuration files and API payloads store integer bytes. **1 MiB = 1048576 bytes**; **1 GiB = 1073741824 bytes**. Switching display units preserves the exact byte count. Fractional amounts must convert to a whole number of bytes. These limits do not reserve disk space or establish a supported user count.

**Administration → User accounts → Storage quota** supports independent user quotas. An inherited quota follows `max_mailbox_bytes`; a custom quota (1–1125899906842624 bytes) overrides it immediately and is stored in SQLite. All six folders, including Trash and Sent, count toward usage. Moving mail does not free space; permanently deleting it from Trash does. Lowering a quota below existing usage preserves mail and blocks further growth. Saving global defaults automatically restarts affected services when supervised; standalone services require a manual restart.

| Field | Default | Browser-validated range | Meaning |
| --- | --- | --- | --- |
| `max_message_bytes` | `10485760` (10 MiB) | 1024–104857600 | Maximum raw message size. MIME/Base64 encoding can make messages larger than their original attachments. |
| `max_recipients` | `100` | 1–100 | Maximum SMTP recipients per message. |
| `max_connections` | `32` | 1–1024 | Concurrent sessions per listening service; each active connection consumes a worker. Excess sessions are closed. |
| `timeout_seconds` | `30` | 1–300 | General network timeout, in seconds. |
| `smtp_data_timeout_seconds` | `120` | 1–3600 | Total SMTP DATA upload deadline, in seconds. |
| `max_mailbox_bytes` | `1073741824` (1 GiB) | 1024–1125899906842624 | Default byte limit per user across all folders; must be at least `max_message_bytes`. |
| `max_mailbox_messages` | `10000` | 1–100000 | Message-count limit per mailbox. |
| `max_queue_bytes` | `1073741824` (1 GiB) | 1024–1125899906842624 | Queue byte limit; must be at least `max_message_bytes`. A separate recipient job accounts for its own copy. |
| `max_queue_messages` | `100000` | 1–1000000 | Maximum queued recipient jobs. |

Lowering a limit does not remove existing mail or shrink databases. New writes can fail once a mailbox or queue reaches its limit. Monitor queue age, free disk space, authentication latency, and memory before raising concurrency substantially. The current implementation has a single delivery worker and serialized SQLite writes.

## Built-in direct delivery and DKIM

Select **Outgoing delivery mode → direct** to send without a relay. PostPlus resolves recipient MX records, connects to public destination addresses on TCP 25, and signs outgoing mail with RSA-SHA256 DKIM (2048-bit key, relaxed/relaxed canonicalization). Null MX and nonexistent recipient domains fail permanently; absent MX falls back to the recipient domain's A/AAAA records. MX preference and alternate addresses are tried within a bounded deadline. Private, loopback and special-use destination addresses are rejected.

| Field | Default | Meaning |
| --- | --- | --- |
| `outbound_mode` | `disabled` for new setups | `disabled`, `direct`, or `relay`. Older files without this field use relay when `smarthost_host` is present, otherwise disabled. |
| `mail_hostname` | Mail domain for older files | Public SMTP EHLO hostname, normally `mail.example.com`. Publish its A/AAAA; ask your server provider to set matching PTR. |
| `dkim_selector` | `postplus` | DNS selector, up to 63 letters, digits and hyphens. |
| `dkim_private_key` | Empty | Private PEM path, relative to the configuration. Setup generates and persists it before showing its public TXT record. Never publish this file. |
| `direct_tls` | `starttls` | Use verified STARTTLS when offered. `required` also defers delivery to destinations without STARTTLS. TLS negotiation failures do not retry in plaintext. |
| `direct_timeout_seconds` | `120` | Total DNS and SMTP budget per recipient, 1–300 seconds. |
| `delivery_max_age_seconds` | `432000` | Retry temporary failures for up to five days. Permanent failures and expired jobs remain in quarantine with a diagnostic. |

In first-run setup, choose direct delivery, enter the actual outbound public IP addresses, generate the DKIM record, and publish the displayed SPF/DKIM/DMARC records. The generated key is reused across retries and restarts. Saved backups include the active DKIM key. Changing the domain or selector requires updating DNS before sending again.

For an existing installation, use **Server settings → Outgoing mail → Generate / load DKIM public record** and save direct mode with a public mail hostname. The offline command `postplus-ctl dkim --config config/postplus.json` also prepares a key for the saved mail domain/selector and prints only its public record; enabling direct mode through settings selects that prepared key. Manual configuration must set `dkim_private_key` to the generated file beside the configuration.

Allow outbound TCP 25 and DNS UDP/TCP 53 to the resolver (1.1.1.1). Configure PTR at the hosting provider and use an IP permitted to send mail. DNS matches alone do not prove deliverability or inbox placement. Authenticated submission is required for external recipients. Received messages are not DKIM/SPF/DMARC verified, and automatic DSN/bounce generation, DANE and MTA-STS are not implemented. An interrupted connection after DATA can leave acceptance unknown; the queue retries such failures and cannot guarantee exactly-once Internet delivery.

## Outgoing SMTP relay

Select `outbound_mode: "relay"` to use an SMTP relay that accepts your sender domain. The relay can be hosted by you or a provider. Disabled outgoing delivery still permits Internet mail to existing accounts in your domain with correct DNS and reachable inbound TCP 25, and mail between local accounts.

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

Outbound TLS checks certificate trust and hostname. `SSL_CERT_FILE` or `SSL_CERT_DIR` can configure OpenSSL's trust store. Follow your relay's domain verification and SPF/DKIM instructions. An optional configured local DKIM key also signs messages sent through the relay.

## Mail filtering

| Field | Default | Meaning |
| --- | --- | --- |
| `clamav_host` | Empty | Host of a separately running ClamAV `clamd`; empty disables ClamAV scanning. |
| `clamav_port` | `3310` | Integer 1–65535; clamd INSTREAM listener. |
| `clamav_timeout_seconds` | `15` | Integer 1–120; scan deadline shared by the message's MIME parts. |
| `spam_threshold` | `5` | Integer 1–1000; inbound mail at or above this score is delivered to Junk. |
| `spam_allow_senders` | `[]` | Up to 1000 envelope email addresses or exact domains (an initial `@` is optional). Bypasses inbound spam scoring, but never malware or blocked-term checks. |
| `spam_block_senders` | `[]` | Same address/domain format. Matching inbound mail goes to Junk. Block rules override allow rules; domains do not implicitly match subdomains. |
| `rspamd_enabled` | `false` | Enable a separately installed local Rspamd worker for inbound mail. |
| `rspamd_host` | `127.0.0.1` | A literal loopback IPv4/IPv6 address; remote scanner hosts are not accepted. |
| `rspamd_port` | `11333` | Rspamd HTTP worker port, using `POST /checkv2`; this is not its controller port. |
| `rspamd_timeout_seconds` | `5` | Integer 1–30; one deadline covers connection, request and bounded response. |
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

Rules examine decoded MIME text and headers; each matching weighted rule contributes once. Inbound heuristics also add 2 points for HTML forms/inputs, 1 for a known shortened HTML link, and 3 for an executable attachment filename. An attachment filename alone does not establish that its content is malware. Ordinary spam remains readable in Junk with its score and reasons. Malformed MIME, configured blocked terms and detected malware remain in quarantine. Filtering preserves the original signed message bytes.

Only unauthenticated SMTP mail receives inbound spam scoring; TLS by itself is not sender authentication. Authenticated SMTP and Webmail submissions still receive MIME, blocked-term and malware checks. Sender policies use the SMTP envelope sender, never the display From header. Envelope addresses can be spoofed: an allow rule is an explicit administrator override, not an SPF/DKIM guarantee. Do not broadly allow trusted-looking domains.

PostPlus does not implement native SPF, DKIM or DMARC verification. Sender-supplied `Authentication-Results`, `ARC-Authentication-Results`, `X-Spam-*`, `Received` and DKIM-signature headers cannot bypass or add local spam scores. With Rspamd enabled, PostPlus sends the original message plus separately captured peer IP, HELO and envelope addresses to the local worker. Rspamd's configured DNS/authentication and other checks provide its verdict; its score is added to the local score. Rspamd reject/add-header/rewrite-subject/discard/quarantine verdicts go to Junk, while soft-reject/greylist requests are deferred. Unknown or incomplete verdicts also defer. Secure the worker listener and configure its policies/signature data separately.

Baseline EICAR test-signature detection is always present. It is not a full antivirus engine. ClamAV installation, daemon access control, and signature updates are separate operational tasks. Configured scanner failures, invalid responses and deadlines defer delivery for retry; they never report a clean scan or permanently quarantine a message solely because a scanner is unavailable. There is no quarantine-release interface yet.

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
    "web": 80,
    "smtp": 25,
    "pop3": 110,
    "imap": 143,
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
  "outbound_mode": "relay",
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
