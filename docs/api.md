# Web and administration API

The JSON API shares an origin with Webmail. Requests with JSON bodies use `Content-Type: application/json`. A configured certificate enables HTTPS for the entire normal web listener. There is no public registration endpoint.

## Sessions

`POST /api/login` accepts:

```json
{"username":"user@localhost","password":"your-password"}
```

It returns `ok`, `username`, `admin`, `csrf`, and `expires_in`, and sets the `pp_session` cookie. Send that cookie on subsequent requests. All state-changing requests except login also require `X-CSRF-Token: <csrf>`.

`GET /api/session` returns the current account and CSRF token. `POST /api/logout` revokes the session and clears its cookie. Cookies are HttpOnly and SameSite=Strict, with Secure added over HTTPS. Sessions are kept in web-process memory, last one hour by default, and expire on restart.

## Mailbox

| Method and path | Request or response |
| --- | --- |
| GET `/api/messages` | The current mailbox. Entries include id, uid, size, seen, and internal_date; up to the newest 100 include optional subject/from/date summaries. |
| GET `/api/messages/{id}` | `raw` text and decoded `message` fields: subject, from, to, date, text. Marks the message as seen. |
| DELETE `/api/messages/{id}` | Deletes a message belonging to the current user. |
| POST `/api/send` | Accepts `to` as an address array, `subject`, and `text`. Returns 202 after queueing. |

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
| POST `/api/admin/users` | `username`, `password`, `admin`. The address must use the configured domain. Returns 201. |
| POST `/api/admin/password` | `username`, `password`. Revokes that user's in-memory Web sessions. |
| GET `/api/admin/stats` | messages, bytes, queued, queued_bytes, quarantined. |
| GET `/api/admin/queue` | Up to 100 jobs with state and errors; no message bodies. |
| GET `/api/admin/logs` | Recent structured events, filtered as described below. |

Passwords must contain at least 12 bytes. A password change through the CLI does not notify the web process to revoke sessions; those sessions expire normally, or all can be revoked by restarting the web service.

### Service logs

Example request:

```http
GET /api/admin/logs?service=smtp&level=warn&limit=100 HTTP/1.1
```

Optional query parameters:

| Parameter | Accepted values | Default |
| --- | --- | --- |
| `service` | `postplus`, `setup`, `auth`, `storage`, `filter`, `transfer`, `delivery`, `smtp`, `pop3`, `imap`, `web` | All services |
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
  "services": ["postplus", "setup", "auth", "storage", "filter", "transfer", "delivery", "smtp", "pop3", "imap", "web"],
  "truncated": false
}
```

Entries are ordered newest first. Reads scan only bounded tails of current and rotated files; `truncated` reports omitted history or results. Rotation can make a tail unavailable during a read. This endpoint provides a diagnostic snapshot, not pagination over a complete audit history. Log messages remain in their recorded language regardless of the browser's interface language.

## First-run setup API

The native `postplus` launcher exposes this temporary API only while the requested configuration is missing. It listens on `127.0.0.1`, defaults to port 8080, and checks Host/Origin values. It is separate from normal Webmail sessions and is unavailable once regular services start.

Open the complete setup URL printed by the launcher. Its fragment contains a random token; browser code removes the fragment and sends `X-Setup-Token` with every setup API request. The token is not a user password or the persistent internal service token.

| Method and path | Request or response |
| --- | --- |
| GET `/api/setup` | Returns `ok` and `defaults` for the setup form. Requires `X-Setup-Token`. |
| POST `/api/setup` | Validates configuration, creates the administrator, and commits configuration. Requires `X-Setup-Token`; returns `ok` and `web_url` on success. |

POST fields:

| Field | Meaning |
| --- | --- |
| `domain` | A valid ASCII mail domain. |
| `admin_username`, `admin_password` | Administrator email in that domain and password of at least 12 bytes. |
| `bind` | IPv4 or IPv6 listener address; defaults to loopback. |
| `data_dir` | Mail data directory; relative paths resolve beside the configuration. |
| `allow_insecure_auth` | Required boolean: explicitly select loopback development mode or TLS. |
| `tls_certificate`, `tls_private_key` | Matching readable PEM files; the private key must be unencrypted. Required for public listeners. |
| `ports` | Object containing auth, storage, filter, transfer, smtp, pop3, imap, web, and delivery_lock. Values are distinct integers in 1..65535. |
| `smarthost_host`, `smarthost_port`, `smarthost_tls` | Optional SMTP relay. TLS mode is starttls, implicit, or none. |
| `smarthost_username`, `smarthost_password_env` | Optional relay account and the environment variable supplying its password. No relay password is saved by the form. |
| `clamav_host`, `clamav_port` | Optional separately deployed ClamAV service. |

Public listening requires TLS with insecure authentication disabled. The auth port must differ from the active setup port because setup temporarily launches auth to provision the administrator. The API uses `ports.delivery_lock`; the saved configuration uses top-level `delivery_lock_port`.

Setup never replaces an existing configuration. A failed provisioning/commit may leave an administrator in the data directory; retry with the same credentials. Existing users are accepted only after successful password verification and an administrator-role check. Setup errors return `ok: false`, a stable `code`, and an English `error` string; the UI translates known error codes.

There is no API for changing the general configuration of an existing installation. Stop the service group, edit its configuration, and restart it.

## Status codes and health

Common status codes are 400 for invalid input, 401 for authentication/session failure, 403 for role/CSRF/transport restrictions, 404 for missing resources, 409 for conflicts, 413 for oversized requests, 415 for unsupported setup content type, 429 for rate limits, and 503 for unavailable dependencies or setup provisioning failure.

`GET /health` indicates that the normal web process is responding. It does not establish the health of the other services, the SMTP relay, or ClamAV. UI language selection does not change JSON field names or API semantics.
