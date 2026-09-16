# Web and administration API

The mailbox JSON API shares an origin with Webmail, normally port 8080. The administration API shares a separate origin with the dedicated administration service, normally port 8081. Requests with JSON bodies use `Content-Type: application/json`. A configured certificate enables HTTPS on both listeners. There is no public registration endpoint.

`postplus-web` exposes mailbox routes and rejects `/api/admin/*`. `postplus-admin` exposes administration routes and rejects mailbox/send routes. Both services provide their own login/session/logout routes. Only administrator accounts may log in to the administration service.

## Sessions

`POST /api/login` accepts:

```json
{"username":"user@localhost","password":"your-password"}
```

It returns `ok`, `username`, `admin`, `csrf`, and `expires_in`, and sets the `pp_session` cookie for Webmail or `pp_admin_session` for administration. Send the appropriate cookie on subsequent requests. Sessions and CSRF tokens are held independently by each process. All state-changing requests except login also require `X-CSRF-Token: <csrf>`.

`GET /api/session` returns the current account and CSRF token. `POST /api/logout` revokes the session and clears its cookie. Cookies are HttpOnly and SameSite=Strict, with Secure added over HTTPS. Sessions are kept in web-process memory, last one hour by default, and expire on restart.

## Mailbox

| Method and path | Request or response |
| --- | --- |
| GET `/api/folders` | Six folders with `name`, `messages`, `unseen`, `bytes` (also `total`/`unread` aliases), and the current user's `usage`. |
| GET `/api/messages?folder=INBOX` | The selected folder (defaults to INBOX). Entries include id, uid, size, seen, and internal_date; up to the newest 100 include optional subject/from/date summaries. |
| GET `/api/messages/{id}` | `raw` text and decoded `message` fields: subject, from, to, date, text. Marks the message as seen. |
| DELETE `/api/messages/{id}` | Moves the current user's message to Trash. Explicit `?permanent=true` permanently deletes a message already in Trash, with a folder/UID guard. |
| POST `/api/messages/{id}/move` | `{ "folder": "Archive" }`; moves between supported folders. |
| POST `/api/drafts` | `to` array, `subject`, `text`, and optional existing draft `id`. Empty recipients and content are allowed. Returns id/uid/folder. |
| POST `/api/send` | `to` address array, `subject`, `text`, optional `draft_id`. Returns 202 after atomically queueing, storing a Sent copy and consuming the draft. |

Example send body:

```json
{"to":["friend@localhost"],"subject":"Hello","text":"A message from PostPlus."}
```

Storage and the mail protocols preserve original message bytes. Web JSON replaces bytes that cannot be represented as UTF-8 for display. Binary attachment download and HTML rendering are not implemented. Reading a message updates its Seen flag, so this endpoint should not be treated as a side-effect-free prefetch API.

## Administration

These routes require an administrator session. Ordinary users receive 403.

| Method and path | Request or response |
| --- | --- |
| GET `/api/admin/users` | Usernames and administrator flags; no password material. |
| GET `/api/admin/messages?username=user%40example.com&folder=Sent` | Read-only view of a selected user's folder. |
| GET `/api/admin/messages/{id}?username=user%40example.com` | Original and decoded message. Does not mark Seen. Inspection is audited without logging message contents. |
| GET `/api/admin/quota?username=user%40example.com` | `bytes`, `messages`, effective `max_bytes`/`max_messages`, nullable override `quota_bytes`/`quota_messages`. |
| POST `/api/admin/quota` | `username`, `quota_bytes` (null to inherit, integer 1..2^50 to override); applies immediately. |
| POST `/api/admin/users` | `username`, `password`, `admin`. The address must use the configured domain. Returns 201. |
| POST `/api/admin/password` | `username`, `password`. Invalidates that user's existing sessions in both administration and Webmail. |
| GET `/api/admin/stats` | messages, bytes, queued, queued_bytes, quarantined. |
| GET `/api/admin/queue` | Up to 100 jobs with state and errors; no message bodies. |
| GET `/api/admin/logs` | Recent structured events, filtered as described below. |
| GET `/api/admin/config` | Sanitized settings, editable-field schema, file revision, saved-secret status, and interface URLs. |
| POST `/api/admin/config` | `revision` and `values`; validates/saves settings and reports that a manual restart is required. |

Folder names are `INBOX`, `Sent`, `Trash`, `Drafts`, `Junk`, and `Archive`. URL-encode query values, especially a username containing `+`. Administrator inspection is read-only; mailbox mutation routes remain exclusive to Webmail and its current user.

### Certificate requests

The following paths use the `/api/admin/acme` prefix in administration, or `/api/setup/acme` during first-run setup. Administration requires its session and CSRF token for mutations; setup requires `X-Setup-Token` on all ACME endpoints and validates Host/Origin. Only predefined Let's Encrypt staging/production directory names are accepted.

| Method and suffix | Contract |
| --- | --- |
| GET `/terms?directory=staging` | `ok`, `directory`, `terms_of_service`; read-only authority metadata. |
| POST `/start` | `domain`, `email`, `directory` (`staging`/`production`), `agree_terms: true`, `terms_of_service` (the exact displayed URL). Returns 202 with job_id/state. |
| GET `/status?job_id=...` | Current/latest job state and progress; success includes `result.tls_certificate`, `result.tls_private_key`, `result.expires_at`, `result.staging`. |
| POST `/cancel` | `{ "job_id": "..." }`; requests cancellation. |

Issuance does not save server settings or restart services. On an existing installation, save the returned file paths through the settings API, then manually restart. During first-run setup, include the paths in the setup submission; successful setup starts the services with that configuration. Private keys never leave the server. Terms are checked again before issuance and changed terms require fresh consent. See [certificate deployment prerequisites](configuration.md#lets-encrypt-certificates).

Passwords must contain at least 12 bytes. Both browser services check each authenticated request against the current credential version through authentication RPC. A password change through administration or the CLI invalidates older sessions on their next authenticated request, without requiring a service restart. A change to administrator status likewise invalidates a session whose stored role no longer matches. Credential-version values stay inside the service processes and are not returned to the browser.

### Server settings

`GET /api/admin/config` returns:

```json
{
  "ok": true,
  "values": {
    "domain": "localhost",
    "bind": "127.0.0.1",
    "admin_bind": "127.0.0.1",
    "ports": {"admin": 8081, "web": 8080},
    "smarthost_password": ""
  },
  "revision": "opaque-file-revision",
  "schema": [],
  "secret_status": {"smarthost_password": false},
  "admin_url": "http://127.0.0.1:8081/",
  "web_url": "http://127.0.0.1:8080/"
}
```

This is an abbreviated example. The actual `values` includes all supported settings. Each `schema` entry has `key`, `group`, `type`, `default`, `label`, and `help`, plus `min`/`max` for numbers, `options` for selections, or `readonly` for immutable paths. A dotted schema key such as `ports.admin` maps to the nested `values.ports.admin` JSON property. Types are `text`, `number`, `boolean`, `select`, `password`, `lines`, and `json`; `lines` and `json` values are arrays on the wire.

Save with `POST /api/admin/config`, the administration cookie, and its CSRF token:

```json
{
  "revision": "revision-returned-by-GET",
  "values": {"log_level": "warn", "ports": {"admin": 8082}}
}
```

`values` may contain a supported subset. Omit read-only fields, even when unchanged. `data_dir`, `web_root`, and `log_dir` are view-only after setup. Service-token paths/settings and the raw relay-password file path cannot be changed through this API. Unsupported fields are rejected. The [configuration reference](configuration.md) lists fields, defaults, ranges, and cross-field constraints.

Send a nonempty `smarthost_password` to save a new relay password in a private file; omission or an empty string keeps the previous secret. Send `clear_smarthost_password: true` inside `values` to remove the active saved-password reference. Clearing and setting a new password in the same request is rejected. The old file is retained so configuration backups remain usable. An environment-provided password still takes precedence and is not cleared by this operation. Secrets are never returned. `secret_status.smarthost_password` indicates a configured saved-secret file, not the validity of that credential or whether an environment override exists.

Successful saves create a private backup, atomically replace the configuration, and return `ok`, `restart_required: true`, `admin_url`, and `web_url`. Saving does not restart any service or clear current sessions. The returned URLs describe the saved configuration and may not be reachable until the operator stops the launcher and runs it again with the same configuration path. After that manual restart, clients must sign in again. Individually launched services also require manual restart. A startup failure is reported by the launcher; automatic rollback is not provided.

Revision conflicts return 409. Validation failures return 400 with a field identifier and error; filesystem failures can return 503. Fetch fresh values before retrying a conflict. Do not repeatedly overwrite a concurrent administrator's changes.

### Service logs

Example request:

```http
GET /api/admin/logs?service=smtp&level=warn&limit=100 HTTP/1.1
```

Optional query parameters:

| Parameter | Accepted values | Default |
| --- | --- | --- |
| `service` | `postplus`, `setup`, `auth`, `storage`, `filter`, `transfer`, `delivery`, `smtp`, `pop3`, `imap`, `web`, `admin` | All services |
| `level` | `debug`, `info`, `warn`, `error` | All levels |
| `limit` | Integer from 1 to 500 | 100 |

The level filter selects an exact severity. Empty service/level values also select all. Unknown or duplicate parameters, unknown services/levels, and invalid limits return 400. Arbitrary file paths are not accepted.

Example response:

```json
{
  "ok": true,
  "entries": [
    {
      "timestamp": "2026-09-15T09:30:00.123Z",
      "service": "smtp",
      "level": "warn",
      "pid": 1234,
      "message": "authentication failed"
    }
  ],
  "services": ["postplus", "setup", "auth", "storage", "filter", "transfer", "delivery", "smtp", "pop3", "imap", "web", "admin"],
  "truncated": false
}
```

Entries are ordered newest first. Reads scan only bounded tails of current and rotated files; `truncated` reports omitted history or results. Rotation can make a tail unavailable during a read. This endpoint provides a diagnostic snapshot, not pagination over a complete audit history. Log messages remain in their recorded language regardless of the browser's interface language.

## First-run setup API

The native `postplus` launcher exposes this temporary API while the requested configuration is missing, while completing an eligible uninitialized configuration without a service-token source or completed-setup marker, or when the offline cleanup tool has marked the retained configuration with `setup_required: true`. It listens on `127.0.0.1:8081` by default. The CLI options `--setup-bind`, `--setup-port`, and `--setup-host` select another temporary listener and advertised hostname. A non-loopback listener requires `--setup-tls-certificate` and `--setup-tls-private-key`; a wildcard bind also requires `--setup-host`. Host/Origin validation applies to both HTTP and HTTPS setup. This API is separate from normal browser sessions and is unavailable once regular services start. See the [setup option reference](configuration.md#first-run-command-line-options).

The launcher prints the HTTP or HTTPS setup URL, normally `http://127.0.0.1:8081/setup`, and a random one-time setup password. Enter it in the browser gate. Browser code keeps it in memory and sends it as `X-Setup-Token` with every setup API request. The password is not a permanent administrator password or the persistent internal service token; it expires when setup completes or the process stops.

| Method and path | Request or response |
| --- | --- |
| GET `/api/setup` | Returns `ok`, `defaults`, `schema`, and `completing_existing` for the form. Requires `X-Setup-Token`. |
| POST `/api/setup` | Validates configuration, creates the administrator, and commits configuration. Requires `X-Setup-Token`; returns `ok`, `admin_url`, and `web_url` on success. |

POST fields:

| Field | Meaning |
| --- | --- |
| `domain` | A valid ASCII mail domain. |
| `admin_username`, `admin_password` | Administrator email in that domain and password of at least 12 bytes. |
| `bind` | IPv4 or IPv6 listener address; defaults to loopback. |
| `admin_bind` | Separate administration listener address; defaults to loopback. |
| `data_dir` | Mail data directory; relative paths resolve beside the configuration. |
| `allow_insecure_auth` | Required boolean: explicitly select loopback development mode or TLS. |
| `tls_certificate`, `tls_private_key` | Matching readable PEM files; the private key must be unencrypted. Required for public listeners. |
| `ports` | Object containing auth, storage, filter, transfer, smtp, pop3, imap, web, admin, and delivery_lock. Values are distinct integers in 1..65535. |
| `smarthost_host`, `smarthost_port`, `smarthost_tls` | Optional SMTP relay. TLS mode is starttls, implicit, or none. |
| `smarthost_username`, `smarthost_password_env` | Optional relay account and the environment variable overriding its saved password. |
| `smarthost_password` | Optional new relay password, saved in a private file; never retained as a JSON config value. |
| `clamav_host`, `clamav_port` | Optional separately deployed ClamAV service. |
| Advanced schema fields | Supported resource, session, filtering, and logging settings; use the returned schema and [configuration reference](configuration.md). |

Public listening requires TLS with insecure authentication disabled. The auth port must differ from the active setup port because setup temporarily launches auth to provision the administrator. The API uses `ports.delivery_lock`; the saved configuration uses top-level `delivery_lock_port`.

For a new configuration, setup commits without replacing a competing destination. For completion of an eligible existing configuration, it verifies the original contents are unchanged, retains the same data directory, and creates a private backup before replacement. Established configurations enter this completion path only when marked `setup_required: true` by the offline reset workflow; successful setup clears that marker.

A failed provisioning/commit may leave an administrator in the data directory; retry with the same credentials. Existing users are accepted only after successful password verification and an administrator-role check. Setup errors return `ok: false`, a stable `code`, and an English `error` string; the UI translates known error codes. General configuration changes after setup use `/api/admin/config` on the administrator listener.

## Status codes and health

Common status codes are 400 for invalid input, 401 for authentication/session failure, 403 for role/CSRF/transport restrictions, 404 for missing resources, 409 for conflicts, 413 for oversized requests, 415 for unsupported setup content type, 429 for rate limits, and 503 for unavailable dependencies or setup provisioning failure.

`GET /health` indicates that the selected browser service is responding. It does not establish the health of the other services, the SMTP relay, or ClamAV. UI language selection does not change JSON field names or API semantics.
