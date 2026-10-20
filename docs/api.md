# Web and administration API

The mailbox JSON API shares an origin with Webmail, normally port 80. The administration API shares a separate origin with the dedicated administration service, normally port 8081. Requests with JSON bodies use `Content-Type: application/json`. A configured certificate enables HTTPS on both listeners. Registration requires an administrator-issued invitation. See [invitations, forwarding, verification codes and permissions](access.md).

With TLS and no explicit Web port, Webmail uses 443. [Mail client discovery](mail-clients.md) provides public HTTPS XML configuration endpoints. [Upgrade API endpoints](updates.md#administration-api) download and install changed modules through the native supervisor.

[IP security](security.md) records source IPs and rejects banned peers at public mail and Webmail/administration connection entrances. Automatic bans are temporary; manual bans can be permanent. Its administration endpoints use the explicit `security:read` and `security:write` permissions.

`postplus-web` exposes mailbox routes and rejects `/api/admin/*`. `postplus-admin` exposes administration routes and rejects mailbox/send routes. Both services provide their own login/session/logout routes. Only administrator accounts may log in to the administration service.

## Sessions

`GET /api/public/config` is available without a session on each permitted portal hostname. It returns `{"ok":true,"domain":"example.com","domains":["example.com"],"max_message_bytes":10485760}` for address inputs and the attachment size hint. A domain-specific Webmail host exposes only that domain; the shared Webmail host and administration expose active hosted domains. API login and account creation accept complete addresses, and accounts with the same local part on different domains remain independent.

Administration accepts only `admin_hostname` (default: primary `domain`). Webmail accepts each active domain for its own mailbox accounts, or the optional `webmail_shared_hostname` for all active domains. Unknown hostnames are rejected. `Host` determines the portal; `Forwarded` and `X-Forwarded-Host` do not override it. Password login, invitation inspection/redemption and mailbox Bearer keys enforce the same account-domain policy. Browser sessions are also bound to their login hostname, so copying a session cookie to another hostname cannot reuse it. Local development access requires an actual loopback connection, loopback Host, and `allow_insecure_auth`; loopback health probes are allowed without granting account access.

Administration DNS recommendations accept `GET /api/admin/dns?domain=example.net`; DNS checks accept an optional `domain` in `POST /api/admin/dns/check`. Only saved hosted domains are accepted, and the hostname, ports and probe targets still come from server settings. Both responses include the hosted `domains` list.

`POST /api/login` accepts:

```json
{"username":"user@localhost","password":"your-password"}
```

It returns `ok`, `username`, `admin`, `csrf`, and `expires_in`, and sets the `pp_session` cookie for Webmail or `pp_admin_session` for administration. Send the appropriate cookie on subsequent browser requests. Sessions and CSRF tokens are held independently by each process. All state-changing cookie-authenticated requests except login also require `X-CSRF-Token: <csrf>`. The browser administration portal continues to use its cookie and CSRF token; API keys support external administration and owner-bound mailbox clients.

`GET /api/session` returns the current account and CSRF token. `POST /api/logout` revokes the session and clears its cookie. Cookies are HttpOnly and SameSite=Strict, with Secure added over HTTPS. Sessions are kept in web-process memory, last one hour by default, and expire on restart.

## Hosted domain management

Domain management is available on the designated administration hostname. All
browser requests require an administrator session; POST requests also require
CSRF. Bearer keys use the permissions below. Domain edits use the configuration
revision returned by the list or latest mutation. A stale revision returns 409.

| Method and path | Body or query | Permission |
| --- | --- | --- |
| GET `/api/admin/domains` | Optional `q` (case-insensitive substring, at most 253 bytes), `offset` (zero or greater), `limit` (1–200, default 25) | `config:read` |
| POST `/api/admin/domains` | `{"revision":"…","domain":"example.net"}`; registers a pending domain, returns 201 | `config:write` |
| POST `/api/admin/domains/preview` | `{"domain":"example.net","dns":{}}`; returns expected DNS records without saving | `config:read` |
| POST `/api/admin/domains/check` | `{"revision":"…","domain":"example.net","dns":{}}`; saves server-generated verification evidence | `config:write` |
| POST `/api/admin/domains/activate` | `{"revision":"…","domain":"example.net"}` | `config:write` |
| POST `/api/admin/domains/remove` | `{"revision":"…","domain":"example.net"}`; preserves accounts and mail | `config:write` |

The list returns `items`, filtered `total`, unfiltered `total_domains`,
`active_count`, `offset`, `limit`, `revision`, and `restart_required`. The primary
domain appears first; other domains sort lexicographically. Each item contains
`domain`, `primary`, `status` (`active` or `pending`), `dns_status`, `checked_at`,
`can_activate`, `can_remove`, and saved `dns` expectations. Empty search results
are a successful empty page. There is no domain-count cap; configuration must
fit within the existing 1 MiB file limit.

Optional `dns` expectations use the existing diagnostic fields (`ipv4`, `ipv6`,
`spf`, `dkim_name`, `dkim_type`, `dkim_value`, `dmarc`). The server supplies the
domain, mail hostname, ports and resolver. A client cannot override them or
submit its own verification result. The check response adds a complete `dns`
report. Activation requires a matching MX plus a public A/AAAA address for the
configured mail server. Evidence expires after 24 hours and becomes invalid
when the relevant DNS expectations or server configuration change. Other DNS
diagnostics remain visible warnings, so activation is not a deliverability or
certificate guarantee.

Pending domains do not change running mail routing. Activation/removal return
`restart_required`; API clients then call `POST /api/admin/restart` with
`{"mode":"changed"}` and `services:write`, or restart independently launched
services manually. The administration UI uses this same restart API. The
primary domain cannot be removed. Generic configuration updates cannot edit
the hosted-domain array or registry, or change the primary domain after setup.

Login policy is configured through the existing revisioned
`POST /api/admin/config`, with `values.admin_hostname` and
`values.webmail_shared_hostname`. An empty administration hostname uses the
primary domain; an empty shared hostname disables shared Webmail. These changes
follow the ordinary configuration-save restart behavior. DNS and TLS coverage
for each public hostname must be configured separately.

## Mailbox

| Method and path | Request or response |
| --- | --- |
| GET `/api/folders` | Built-in and selectable client-created folders with `name`, `messages`, `unseen`, `bytes` (also `total`/`unread` aliases), and the current user's `usage`. |
| GET `/api/messages?folder=INBOX` | The selected folder (defaults to INBOX). Entries include id, uid, size, seen, and internal_date; up to the newest 100 include optional subject/from/date summaries. |
| GET `/api/messages/search` | Owner-bound decoded search with filters and newest-first pagination. Requires `mailbox:read`. See below. |
| GET `/api/messages/{id}/delivery-status` | Durable per-recipient delivery progress for an authenticated submission's Sent message. Requires `mailbox:read`; other owners and unavailable legacy histories return 404. |
| GET `/api/messages/{id}` | `raw` source and decoded `message` headers, text/HTML bodies, forwarded views, and inline images. Marks the message as seen. |
| GET `/api/messages/{id}?image={index}` | Fetch a remote raster image indexed in this message. Returns `content_type` and Base64 `data`; does not change message flags. |
| GET `/api/messages/{id}?attachment={index}` | Download exact decoded attachment bytes. Requires `mailbox:read`; does not change message flags. |
| DELETE `/api/messages/{id}` | Moves the current user's message to Trash. Explicit `?permanent=true` permanently deletes a message already in Trash, with a folder/UID guard. |
| POST `/api/messages/{id}/move` | `{ "folder": "Archive" }`; moves between supported folders. |
| POST `/api/drafts` | `to` array, `subject`, `text`, optional `cc`/`bcc` arrays, `html`, `attachments` and existing draft `id`. Empty recipients and content are allowed. Returns id/uid/folder. |
| POST `/api/send` | The same composition fields, with optional `draft_id`. At least one recipient across To/Cc/Bcc is required. Returns 202 after atomically queueing, storing a Sent copy and consuming the draft. |

Example send body:

```json
{"to":["friend@localhost"],"subject":"Hello","text":"A message from PostPlus."}
```

Composition supports up to 100 recipients across To/Cc/Bcc and 64 attachments. `html` creates a multipart/alternative body alongside `text`; attachments wrap that body in multipart/mixed. Add an uploaded file as `{"filename":"report.pdf","content_type":"application/pdf","data_base64":"..."}` or retain an existing owned file as `{"message_id":"...","index":0}`. The aggregate decoded content and final encoded MIME must fit `max_message_bytes`; uploads are bounded before parsing. Attachment references are resolved only in the authenticated owner's mailbox, including API-key requests. Drafts retain HTML, Cc, Bcc, attachments and reply references; sent wire messages omit Bcc while the envelope includes its recipients. `reply_to_id` uses an owned source to set In-Reply-To/References. Clients may alternatively supply validated `in_reply_to` and `references` strings when restoring a draft. Webmail provides rich-text formatting, reply/reply-all/forward, file selection/removal, and draft attachment restoration.

API keys using an attachment `message_id` reference or `reply_to_id` must also have `mailbox:read`, in addition to `mailbox:send` or `mailbox:write` for the composition route. Upload-only sends and drafts require only their respective send/write scope. Browser sessions retain the account's normal mailbox access.

Decoded `message.attachments` contains `{index,filename,content_type,size}` metadata; indexes are scoped to that message version. Downloads use `application/octet-stream`, `Content-Disposition: attachment` and a safe UTF-8 filename. Binary data is preserved without character conversion, including attached `.eml` files. Administration uses `/api/admin/messages/{id}?username={mailbox}&attachment={index}` with `mail:read`; downloads are audited and do not mark the message Seen.

Search accepts `q` (decoded subject, sender, recipients, body and attachment names), separate `from`, `to`, and `subject` substrings, `folder` (a selectable folder name or `all`, the default), `seen` and `has_attachment` (`true`/`false`), `after`/`before`, `limit` (1–100, default 50), and `offset` (0–100000). Recipient matching includes decoded To/Cc and Bcc where present in private draft source; submitted Bcc is absent from the Sent wire source. Results display the actual To header. Text filters are at most 256 UTF-8 bytes. Substrings are literal, including `%` and `_`; ASCII matching ignores case and decoded Unicode is preserved. Dates are UTC `YYYY-MM-DD` or Unix seconds, applied to the internal received/saved date, with inclusive `after` and exclusive `before`. Responses contain `messages` with envelope fields, folder, flags, attachment presence and a text snippet, plus `total`, `offset`, `limit`, and `has_more`. Search never marks mail read. Upgraded legacy mail is indexed in durable bounded batches: while `indexing:true`, results/counts are provisional and clients should repeat the request until it is false; `indexing_remaining` reports outstanding messages. Malformed MIME falls back to decoded headers and up to 16 MiB of wire text.

Delivery status contains `submission_id`, `recipients`, and a `notice`. Each recipient has `state` (`queued`, `retrying`, `delivered`, `rejected`, or `failed`), `attempts`, `error`, `created_at`, `updated_at`, `next_attempt`, `delivery_scope`, and a chronological `history` of state/attempt/error/`at` entries. `local_mailbox` confirms local storage; `remote_mta` confirms the receiving SMTP server accepted the message, without claiming Inbox placement or that it was read. Transient failures retry; permanent SMTP/policy rejections and age-expired failures remain durable. Histories survive queue removal and restarts; they are available for new authenticated submissions and queued legacy submissions, not already completed pre-upgrade mail. Responses bound history to the newest 100 events per recipient and a shared byte budget, setting `history_truncated` when necessary. Original mail bytes remain unchanged.

Storage and the mail protocols preserve original message bytes. Message views convert declared header/body character sets to UTF-8 for display. In addition to `subject`, `from`, `to`, `date`, and `text`, `message` includes `html`, a `forwarded` array of attached message views, and `inline_images` with `cid`, `content_type`, and Base64 `data` for supported raster CID images. Empty text/HTML parts use empty strings. MIME attachments are excluded from the main body; `message/rfc822` forwards retain their own headers and body. Forwarded views and inline images have depth, count, and size limits; raw source is retained for content outside those limits.

The browser reader sanitizes HTML and renders it in a sandboxed frame with a restrictive content policy. Scripts, forms, embedded pages, and external stylesheets are blocked. Safe inline styles, bounded sender stylesheet/media-query rules, and table layout attributes are preserved inside the opaque frame. Remote images load automatically through authenticated requests to the server and are embedded as validated raster data inside the frame. Opening a message can therefore contact its sender's image servers, without forwarding browser credentials or a referrer.

Each decoded view includes a `remote_images` array of `{url,index}` entries, sharing at most 64 distinct indexes across forwarded messages. The image endpoint accepts only an index belonging to the authorized message, with no caller-supplied URL. It allows public HTTP(S) destinations on their default ports, verifies HTTPS certificates, rejects redirects and private addresses, and limits responses to 2 MiB of PNG, JPEG, GIF or WebP data. It returns 400 for an invalid index, 404 for a missing message or image, and 502 for an unavailable or unsafe remote image. Administration inspection uses `/api/admin/messages/{id}?username={mailbox}&image={index}` with the same administrator authorization as message inspection.

The collapsed body-source view omits top-level transport headers. The API's `raw` field still contains the complete original message. Reading the ordinary message endpoint updates its Seen flag, so it should not be treated as a side-effect-free prefetch API.

## Administration

These routes require an administrator cookie session or, except for API-key management, an administrator API key in `Authorization: Bearer <key>`. Ordinary users receive 403. Bearer keys are accepted only over HTTPS or from loopback; remote plaintext HTTP is rejected. A Bearer request does not use a browser session or CSRF token. Administrator keys are not accepted by login, session, logout, setup, or mailbox routes. Owner-bound mailbox keys are supported on Webmail.

DKIM preparation returns `ok`, `domain`, `selector`, `name`, `type: "TXT"`, `value` and a SHA-256 `fingerprint` of the public record. It generates a private RSA-2048 key beside the configuration or reuses the selected existing key; no private material is returned. First-run setup uses `POST /api/setup/dkim` with the same body and `X-Setup-Token`, Host/Origin protection. Saving setup in direct mode requires `dkim_fingerprint` from the current record, `outbound_mode: "direct"`, `mail_hostname` and `dkim_selector`. Key generation survives a failed save or wizard restart. DNS is published separately; record availability is not a claim of Internet reachability.

| Method and path | Request or response |
| --- | --- |
| GET `/api/admin/users` | Usernames and administrator flags; no password material. |
| GET `/api/admin/api-keys` | Key metadata and limits; administrator cookie required. No full keys or hashes. |
| POST `/api/admin/api-keys` | `{ "name": "Monitoring", "expires_in_days": 90, "permissions": ["stats:read"] }`; creates a limited key and returns it once. Cookie and CSRF required. Returns 201. |
| PATCH `/api/admin/api-keys/{id}` | `{ "permissions": ["stats:read"] }`; changes permissions immediately without rotating the key. Cookie and CSRF required. |
| DELETE `/api/admin/api-keys/{id}` | Immediately revokes the key; idempotent. Cookie and CSRF required. |
| GET `/api/admin/messages?username=user%40example.com&folder=Sent` | Read-only view of a selected user's folder. |
| GET `/api/admin/messages/search?username=user%40example.com` | The same decoded search and filters for a selected account. Requires `mail:read`; access is audited without storing query text or mail content. |
| GET `/api/admin/messages/{id}/delivery-status?username=user%40example.com` | Read-only, audited delivery history for the selected account's outgoing message. Requires `mail:read`. |
| GET `/api/admin/folders?username=user%40example.com` | Built-in and selectable client-created folders for a selected user. Requires `mail:read`. |
| GET `/api/admin/messages/{id}?username=user%40example.com` | Original and decoded message. Does not mark Seen. Inspection is audited without logging message contents. |
| GET `/api/admin/quota?username=user%40example.com` | `bytes`, `messages`, effective `max_bytes`/`max_messages`, nullable override `quota_bytes`/`quota_messages`. |
| POST `/api/admin/quota` | `username`, `quota_bytes` (null to inherit, integer 1..2^50 to override); applies immediately. |
| POST `/api/admin/users` | `username`, `password`, `admin`. The address must use a configured primary or additional domain. Returns 201. |
| POST `/api/admin/password` | `username`, `password`. Invalidates that user's existing sessions in both administration and Webmail. |
| GET `/api/admin/password-policy` | Current account policy, revision, byte limit, and character-count convention. |
| POST `/api/admin/password-policy` | Full `policy` object and `revision`; saves immediately without a restart. |
| GET `/api/admin/stats` | messages, bytes, queued, queued_bytes, quarantined. |
| GET `/api/admin/queue` | Up to 100 jobs with state and errors; no message bodies. |
| GET `/api/admin/logs` | Recent structured events, filtered as described below. |
| GET `/api/admin/config` | Sanitized settings, editable-field schema, file revision, saved-secret status, and interface URLs. |
| POST `/api/admin/config` | `revision` and `values`; validates/saves settings and automatically restarts affected services when supervised; accepts optional `apply: false` to save without applying. |
| POST `/api/admin/dkim` | `{ "domain": "example.com", "selector": "postplus" }`; prepares/reuses a private server key and returns its public DNS record. |
| POST `/api/admin/backup` | `{}`; starts an asynchronous backup and returns 202 with `job_id` and `state: "running"`. |
| GET `/api/admin/backup?job_id=...` | `state` is `running`, `complete`, or `failed`. Completed jobs include `download_url`; failed jobs include `error`. |
| GET `/api/admin/backup/download?job_id=...` | Streams the current completed job as an attachment with content type `application/x-tar`. |
| POST `/api/admin/shutdown` | `{}`; asks the native supervisor to stop. Returns 202 with `state: "shutting_down"`; it does not save browser form values. |
| POST `/api/admin/restart` | `{ "mode": "all" }` for a full restart, or `{ "mode": "changed" }` to apply saved file changes. Returns 202 with a restart job. |
| GET `/api/admin/restart?job_id=...` | Restart job state, affected services, and updated URLs. |

Built-in folder names are `INBOX`, `Sent`, `Drafts`, `Trash`, `Junk`, and `Archive`; client-created folders use UTF-8 names with `/` hierarchy separators. Discover selectable names through the folder endpoints. URL-encode query values, especially a username containing `+` or a folder name containing non-ASCII characters. Administrator inspection is read-only; mailbox mutation routes remain exclusive to Webmail and its current user.

Backup and shutdown mutations require administrator authentication, with CSRF for cookie requests. The backup download also requires administrator authentication; its random job ID is not an authentication credential. A new backup replaces the previous completed job, returns 409 while another backup/download is active, and is discarded on a normal administration-service shutdown. Configuration saving and web shutdown return 409 during backup. Shutdown returns 503 if administration was started without the native supervisor. The web UI saves and validates its Server settings form through `/api/admin/config` with `apply: false` before calling `/api/admin/shutdown`, avoiding a competing automatic restart. See [maintenance.md](maintenance.md) for backup contents and restoration.

### External administration API keys

Sign in to the browser administration portal and open **API keys** to create a key, edit permissions, review usage, or revoke it. A key grants exactly its explicitly selected permissions; an empty array grants no API access. Legacy keys migrate with their previous administrator grants. Its owner is the administrator who created it. Key management always requires a browser cookie and `X-CSRF-Token`, including metadata GET and permission PATCH. Webmail provides separate owner-bound **Mailbox API keys**. See [permission IDs](access.md).

Create with `POST /api/admin/api-keys`:

```json
{"name":"Monitoring","expires_in_days":90,"permissions":["stats:read"]}
```

`name` must be nonempty and at most 80 UTF-8 bytes. `expires_in_days` is optional; when provided, it must be an integer from 1 to 3650. Omit it for no expiry. The service permits at most 100 active keys and 1000 stored entries. A successful response contains:

```json
{
  "ok": true,
  "key": "pp_<64 hexadecimal characters>",
  "api_key": {
    "id": "<32 hexadecimal characters>",
    "name": "Monitoring",
    "prefix": "pp_<public prefix>",
    "owner": "admin@example.com",
    "scope": "admin",
    "audience": "admin",
    "permissions": ["stats:read"],
    "created_at": 1791849600,
    "expires_at": 1799625600,
    "last_used_at": null,
    "revoked_at": null,
    "active": true
  }
}
```

The complete key is returned only by this creation response. The server stores a SHA-256 digest and metadata, not the usable key. The browser shows it once, supports copying or manual selection, and clears it on dialog close or sign-out; it does not save it in browser storage. Store it in a secret manager before closing the window. `GET /api/admin/api-keys` returns `api_keys` containing metadata only and `max_active_keys: 100` and `max_stored_keys: 1000`. Timestamp fields use Unix seconds; `expires_at`, `last_used_at`, and `revoked_at` can be null. An unused key has `last_used_at: null`. Revoked and expired entries remain visible for review until old inactive entries are pruned to retain at most 1000 records.

Keys persist across service restarts. A password reset does not revoke them; revoke them separately when rotating access. Every request checks that the owner still exists and is an administrator. Key-management errors include `invalid_api_key` (400), `api_key_not_found` (404), and `api_key_limit` (409).

For an external client, use the administration origin and send the key in the header:

```sh
# Load POSTPLUS_API_KEY from the integration's secret manager.
curl --fail --silent --show-error \
  -H "Authorization: Bearer $POSTPLUS_API_KEY" \
  https://mail.example.com:8081/api/admin/stats
```

For a mutation, also send JSON and its content type:

```sh
curl --fail --silent --show-error \
  -H "Authorization: Bearer $POSTPLUS_API_KEY" \
  -H "Content-Type: application/json" \
  --data '{"username":"user@example.com","quota_bytes":1073741824}' \
  https://mail.example.com:8081/api/admin/quota
```

Remote requests require HTTPS with a valid, trusted server certificate. Plain HTTP is accepted for loopback testing only. Keep the key out of URLs, source code, logs, and shell history; do not disable certificate verification. Browser cookies and CSRF headers are unnecessary for Bearer requests. If a key is lost or exposed, revoke it in the portal and create a replacement. `DELETE /api/admin/api-keys/{id}` takes effect immediately and is idempotent; revocation cannot be undone.

### Certificate requests

The following paths use the `/api/admin/acme` prefix in administration, or `/api/setup/acme` during first-run setup. Administration requires administrator authentication, with CSRF for cookie-authenticated mutations; setup requires `X-Setup-Token` on all ACME endpoints and validates Host/Origin. Only predefined Let's Encrypt staging/production directory names are accepted.

| Method and suffix | Contract |
| --- | --- |
| GET `/terms?directory=staging` | `ok`, `directory`, `terms_of_service`; read-only authority metadata. |
| POST `/start` | `domain`, `email`, `directory` (`staging`/`production`), `agree_terms: true`, `terms_of_service` (the exact displayed URL). Returns 202 with job_id/state. |
| GET `/status?job_id=...` | Current/latest job state and progress; success includes `result.tls_certificate`, `result.tls_private_key`, `result.expires_at`, `result.staging`. |
| POST `/cancel` | `{ "job_id": "..." }`; requests cancellation. |

Issuance does not save server settings or restart services. On an existing installation, save the returned file paths through the settings API; the supervisor then automatically restarts affected services. Standalone service executables require a manual restart. During first-run setup, include the paths in the setup submission; successful setup starts the services with that configuration. Private keys never leave the server. Terms are checked again before issuance and changed terms require fresh consent. See [certificate deployment prerequisites](configuration.md#lets-encrypt-certificates).

Both browser services check each authenticated request against the current credential version through authentication RPC. A password change through administration or the CLI invalidates older sessions on their next authenticated request, without requiring a service restart. A change to administrator status likewise invalidates a session whose stored role no longer matches. Credential-version values stay inside the service processes and are not returned to the browser.

### Account password policy

`GET /api/admin/password-policy` returns the current policy persisted in the authentication database. Defaults are:

```json
{
  "ok": true,
  "policy": {
    "min_length": 8,
    "require_uppercase": false,
    "require_lowercase": false,
    "require_digit": false,
    "require_symbol": false
  },
  "revision": 1,
  "max_password_bytes": 1024,
  "length_unit": "unicode_code_points",
  "restart_required": false
}
```

`POST /api/admin/password-policy` requires administrator authentication, with CSRF for cookie requests. Submit all five policy fields, with the revision from the last GET:

```json
{
  "revision": 1,
  "policy": {
    "min_length": 10,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_digit": true,
    "require_symbol": false
  }
}
```

The minimum must be an integer from 8 to 128 and cannot exceed the running authentication service's `max_password_bytes`. Diversity fields must be booleans. Uppercase means `A–Z`, lowercase `a–z`, digits `0–9`, and symbols printable ASCII punctuation (`!` through `/`, `:` through `@`, `[` through the backtick, and `{` through `~`). Whitespace and emoji do not satisfy these four optional ASCII categories. All valid Unicode code points count toward the minimum; one emoji outside the BMP counts as one code point, and a combining mark counts separately. The server never trims or normalizes passwords. The maximum is measured separately in UTF-8 bytes.

Successful POST returns the same shape as GET, with an incremented revision when the policy changed. Saving an unchanged policy with its current revision is idempotent. The change applies immediately to subsequent account creation/password resets through administration, CLI, and internal RPC, including writes whose password hashing began before the policy changed. Existing passwords and sessions keep working; the new policy does not run on login. The JSON server configuration is not rewritten, and services are not restarted.

Missing, unknown, mistyped, and out-of-range fields return HTTP 400:

```json
{"ok":false,"code":"invalid_password_policy","error":"Check the password policy fields.","errors":[{"field":"min_length","code":"out_of_range","min":8,"max":128}]}
```

Field-error codes are `required`, `unknown_field`, `invalid_type`, and `out_of_range`. A stale revision returns HTTP 409 with `code: "password_policy_conflict"` and the current `policy`/`revision`; reload and review before saving again.

Account creation/reset failures caused by this policy return HTTP 400, including from `/api/admin/users`:

```json
{"ok":false,"code":"password_policy_violation","error":"Password does not meet the account password policy.","violations":["min_length","require_digit"],"policy":{"min_length":12,"require_uppercase":false,"require_lowercase":false,"require_digit":true,"require_symbol":false},"revision":2,"max_password_bytes":1024,"length_unit":"unicode_code_points","restart_required":false}
```

Violation names are `min_length`, `max_password_bytes`, `require_uppercase`, `require_lowercase`, `require_digit`, `require_symbol`, and `invalid_utf8` (malformed JSON encoding is rejected before policy validation). Password values are never echoed or logged. Fresh first-run setup uses the default minimum of 8 Unicode code points.

### Server settings

`GET /api/admin/config` returns:

```json
{
  "ok": true,
  "values": {
    "domain": "localhost",
    "bind": "127.0.0.1",
    "admin_bind": "127.0.0.1",
    "ports": {"admin": 8081, "web": 80},
    "smarthost_password": ""
  },
  "revision": "opaque-file-revision",
  "schema": [],
  "secret_status": {"smarthost_password": false},
  "admin_url": "http://127.0.0.1:8081/",
  "web_url": "http://127.0.0.1:80/"
}
```

This is an abbreviated example. The actual `values` includes all supported settings. Each `schema` entry has `key`, `group`, `type`, `default`, `label`, and `help`, plus `min`/`max` for numbers, `options` for selections, or `readonly` for immutable paths. A dotted schema key such as `ports.admin` maps to the nested `values.ports.admin` JSON property. Types are `text`, `number`, `boolean`, `select`, `password`, `lines`, and `json`; `lines` and `json` values are arrays on the wire.

The response also includes `restart_available`, whether saved values differ from the actually applied configuration in `restart_required`, and the latest `restart` job when supervised. This lets a new browser session inspect progress or the result after administration itself restarts.

Save with `POST /api/admin/config` and administrator authentication. Cookie clients also send their CSRF token:

```json
{
  "revision": "revision-returned-by-GET",
  "values": {"log_level": "warn", "ports": {"admin": 8082}}
}
```

`values` may contain a supported subset. Omit read-only fields, even when unchanged. `data_dir`, `web_root`, and `log_dir` are view-only after setup. Service-token paths/settings and the raw relay-password file path cannot be changed through this API. Unsupported fields are rejected. The [configuration reference](configuration.md) lists fields, defaults, ranges, and cross-field constraints.

Send a nonempty `smarthost_password` to save a new relay password in a private file; omission or an empty string keeps the previous secret. Send `clear_smarthost_password: true` inside `values` to remove the active saved-password reference. Clearing and setting a new password in the same request is rejected. The old file is retained so configuration backups remain usable. An environment-provided password still takes precedence and is not cleared by this operation. Secrets are never returned. `secret_status.smarthost_password` indicates a configured saved-secret file, not the validity of that credential or whether an environment override exists.

Successful saves create a private backup and atomically replace the configuration. Under the native supervisor, the response has `restart_required: false`, `restart: { "job_id": "...", "state": "pending", "services": ["..."] }`, `admin_url`, and `web_url`; only affected services restart automatically. The URLs describe the saved configuration and may become reachable only as restarting completes. An administration-service restart clears its browser sessions, so clients must sign in again at its updated address. Other service restarts preserve the administration session.

Individually launched service executables return `restart_required: true` and require a manual restart. To save deliberately without applying changes, send top-level `apply: false` beside `revision` and `values`; the browser uses this for Save and shut down. A failed restart is reported separately from the successful configuration save. When the native supervisor can restore the previous affected-service snapshots, the failed job returns `rolled_back: true`; the newly saved configuration remains pending for correction and retry. This restores running services, not the saved file. A full systemd relaunch cannot automatically restore the old processes after the supervisor exits.

If the configuration was saved but a restart could not be scheduled, the response retains `restart_required: true` and includes `restart_error`. Review the saved configuration and service logs before requesting a restart; do not treat the save response as proof that services loaded the changes.

Revision conflicts return 409. Validation failures return 400 with a field identifier and error; filesystem failures can return 503. Fetch fresh values before retrying a conflict. Do not repeatedly overwrite a concurrent administrator's changes.

### Restarting services

`POST /api/admin/restart` requires administrator authentication and CSRF for cookie requests. Send `{ "mode": "all" }` to restart all services with the saved configuration, or `{ "mode": "changed" }` to apply supported changes already saved by manual file editing. It does not save browser form edits. A full restart under the supplied systemd installation automatically brings PostPlus back; shutdown is a separate action that leaves it stopped.

The schedule response is `{ "ok": true, "job_id": "...", "state": "pending", "services": ["..."], "admin_url": "...", "web_url": "..." }`. Poll `GET /api/admin/restart?job_id=...` for `pending`, `running`, `complete`, or `failed`, with the same metadata and an optional error plus `rolled_back` on failure. A completed state confirms service readiness; losing the HTTP connection does not. State survives an administration-service restart, but the old browser session does not. After that restart, sign in at the updated address before reading the result.

The UI retries transient connection failures for a bounded interval and shows reconnect links if authentication expires or the administration address moves. It does not repeatedly force the login screen or report completion from a disconnect. Without a native supervisor, the restart API is unavailable and settings saves report the manual fallback.

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

The native `postplus` launcher exposes this temporary API while the requested configuration is missing, while completing an eligible uninitialized configuration without a service-token source or completed-setup marker, or when the offline cleanup tool has marked the retained configuration with `setup_required: true`. An interactive first launch offers `127.0.0.1` or `0.0.0.0`; non-interactive launches default to `127.0.0.1:8081`. The CLI options `--setup-bind`, `--setup-port`, and `--setup-host` select another temporary listener and advertised hostname. Remote HTTP setup is supported without certificates; supplying both `--setup-tls-certificate` and `--setup-tls-private-key` enables HTTPS. A wildcard bind requires `--setup-host`. Host/Origin validation applies to both HTTP and HTTPS setup. This API is separate from normal browser sessions and is unavailable once regular services start. See the [setup option reference](configuration.md#first-run-command-line-options).

The launcher prints the HTTP or HTTPS setup URL, normally `http://127.0.0.1:8081/setup`, and a random one-time setup password. Enter it in the browser gate. Browser code keeps it in memory and sends it as `X-Setup-Token` with every setup API request. The password is not a permanent administrator password or the persistent internal service token; it expires when setup completes or the process stops.

| Method and path | Request or response |
| --- | --- |
| GET `/api/setup` | Returns `ok`, `defaults`, `schema`, and `completing_existing` for the form. Requires `X-Setup-Token`. |
| POST `/api/setup` | Validates configuration, creates the administrator, and commits configuration. Requires `X-Setup-Token`; returns `ok`, `admin_url`, and `web_url` on success. |
| POST `/api/setup/dns/check` | Checks draft DNS records without provisioning or saving settings. Requires `X-Setup-Token` and the same Host/Origin checks. |

POST fields:

| Field | Meaning |
| --- | --- |
| `domain` | A valid ASCII mail domain. |
| `admin_username`, `admin_password` | Administrator email in that domain and password of at least 8 Unicode code points (at most 1024 UTF-8 bytes). |
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

### Setup DNS checks

Send a JSON object to `/api/setup/dns/check` with the required text fields `domain` (mailbox domain) and `hostname` (mail server). Optional text fields are `ipv4`, `ipv6`, `spf`, `dkim_name` (full selector name), `dkim_type` (`TXT` or `CNAME`, default `TXT`), `dkim_value`, and `dmarc`. Unknown fields and invalid types or names return 400 with `code: "invalid_dns_input"`. For example:

```json
{
  "domain": "example.com",
  "hostname": "mail.example.com",
  "ipv4": "",
  "ipv6": "",
  "spf": "",
  "dkim_name": "",
  "dkim_type": "TXT",
  "dkim_value": "",
  "dmarc": "v=DMARC1; p=none"
}
```

Use real public addresses and the relay provider's actual authentication records when known. The response includes `ok`, `resolver`, `checked_at` (UTC), `limitations`, and six `records` with IDs `a`, `aaaa`, `mx`, `spf`, `dkim`, `dmarc`. Each record has `name`, `type`, arrays `expected` and `observed`, `status`, `code`, and `message`. Statuses are `matched`, `missing`, `mismatch`, `not_configured`, or `error`; `ok: true` means the check ran, not that every record matched. MX observations include priority. The check compares MX targets with the mail hostname, and reports CNAME mail hosts as unsuitable MX targets. It rejects multiple SPF/DMARC policies. Unconfigured A/AAAA are still queried so unexpected public addresses remain visible.

The resolver is fixed to Cloudflare `1.1.1.1:53` over UDP, with a ten-second overall budget and bounded packets. Browser requests cannot select a resolver, URL, port or timeout. Network, malformed and truncated-response errors leave the affected record in `error`, never `missing` or `matched`. Queries use one public resolver's current cached view; they do not establish SMTP reachability, PTR, relay DKIM signing, SPF/DMARC alignment, delivery or certificate issuance. The frontend invalidates results after input changes and discards responses to earlier drafts.

DNS guide fields are separate from saved server settings. Checking does not publish records, accept certificate terms, request a certificate, or create an administrator. Other setup work in progress returns 409 with `code: "setup_busy"`.

## Status codes and health

Common status codes are 400 for invalid input, 401 for authentication/session failure, 403 for role/CSRF/transport restrictions, 404 for missing resources, 409 for conflicts, 413 for oversized requests, 415 for unsupported setup content type, 429 for rate limits, and 503 for unavailable dependencies or setup provisioning failure.

`GET /health` indicates that the selected browser service is responding. It does not establish the health of the other services, the SMTP relay, or ClamAV. UI language selection does not change JSON field names or API semantics.
