# Internal RPC contract (v1)

Each service is a separate executable. Internal HTTP listeners bind loopback and require `Authorization: Bearer <service_token>` for POST /rpc. JSON bodies and replies; failures use `{"ok":false,"error":"..."}`. The `rpc` helper throws on HTTP errors, but returns application-level `ok:false` replies. All inputs are untrusted. No passwords or message bodies in logs.

Config is JSON. `Config::load` accepts `--config PATH` (default config/postplus.json). Ports map: auth 18081, storage 18082, filter 18083, transfer 18084, smtp 2525, pop3 1110, imap 1143, web 8080, admin 8081. `delivery_lock_port` defaults 18085. `service_token_env` defaults POSTPLUS_SERVICE_TOKEN; when unset or empty, `service_token_file` supplies the shared token. Tokens must contain 32–1024 bytes with no embedded CR, LF, or NUL. The first-run wizard generates a private token file. Paths resolve relative to the config file. Shared limits: max_message_bytes (10485760), max_connections (32), timeout_seconds (30), max_auth_attempts (5). `bind` and independent `admin_bind` default 127.0.0.1. `domain` defaults localhost. TLS certificate/key optional (`tls_certificate`, `tls_private_key`); authentication without TLS only if `allow_insecure_auth` is explicitly true AND socket peer is loopback. `data_dir` path. `web_root` path. Structured service logs default to `<data_dir>/logs`; `log_level`, `log_max_bytes`, and `log_backups` control severity and retention. The [configuration reference](configuration.md) defines additional settings and browser editability.

`raw` fields in this document describe the in-process API. On the HTTP wire they are encoded as `raw_base64` strings, including raw fields inside queue job arrays; core performs conversion. Messages may contain non-UTF-8 bytes but not literal NUL; binary attachments use MIME transfer encoding. JSON nesting is bounded to 64. Replies without raw fields use ordinary JSON.

## Auth

- create: username (full normalized email), password, admin(bool) -> ok, username. Reject duplicate, short password (<12).
- verify: username, password, session(optional bool) -> ok, username, admin. Invalid credentials -> ok:false. With session:true, successful verification also returns credential_version for server-side session validation; it must not be exposed through the browser API.
- session_check: username, credential_version -> ok:true, valid:bool, admin:bool. Validates the stored credential version against the current account. Password changes replace the version; both browser services reject stale versions or changed roles on the next authenticated request.
- exists: username -> ok:true, exists:bool.
- list -> ok:true, users:[{username,admin}].
- change_password: username,password -> ok.

## Storage

SQLite owned exclusively by storage process; auth owns a separate auth SQLite DB.

- enqueue: sender, recipients:[full email], raw -> ok,id (queue submission ID). Persist each recipient as a separate job before accepting SMTP DATA.
- queue_list: limit optional -> ok,jobs:[{id,sender,recipient,raw,attempts}] (only due jobs; delivery is single worker).
- queue_finish: id -> ok (remove job).
- queue_retry: id,delay(seconds),error -> ok (increment attempts, set next due; no automatic dropping).
- queue_reject: id,error -> ok (persistent quarantined state, excluded from queue_list).
- queue_inspect: limit (max 1000),offset -> ok,jobs (pending and quarantined metadata including last_error; no raw).
- deliver: username,raw,delivery_id -> ok,id (idempotent by delivery_id+username).
- list: username,include_envelope(optional bool) -> ok,messages:[{id,uid,size,seen,internal_date}], uidvalidity (stable positive int), uidnext. Ordered by uid; internal_date is Unix seconds. Optional envelope adds subject/from/date to latest 100 messages from their first 16 KiB, each field at most 1024 bytes, without changing Seen.
- get: username,id -> ok,raw.
- delete: username,ids:[id] -> ok (atomic batch).
- flags: username,id,seen:bool -> ok.
- stats -> ok,messages,queued,bytes,queued_bytes,quarantined.

## Filter

- scan: raw -> ok,action (accept/reject),reason,spam_score,antivirus. EICAR and configured blocked terms baseline; optional ClamAV INSTREAM TCP integration. ClamAV configured but unavailable returns ok:false,action:defer; no false clean result.

## Transfer

- send: sender,recipient,raw -> ok on accepted upstream SMTP; failure ok:false,error. Uses configured smarthost only; no implicit public relay/DNS-MX claim.
- smarthost_timeout_seconds defaults 30 and bounds the entire upstream transaction. The internal transfer RPC waits this budget plus 10 seconds. RCPT accepts 250 or 251. Final DATA 250 is immediately successful; no waiting for QUIT.

## Protocol and Web ownership

SMTP and Web enqueue after checking every recipient is a local existing user (nonlocal requires authenticated submission AND configured smarthost). Delivery scans queued mail then delivers locally or invokes transfer. SMTP must not be an open relay. Webmail owns authenticated mailbox list/read/delete/send routes. Administration is a separate process with administrator-only login, account management, stats, queues, logs, and configuration settings. Each browser service issues its own bounded, expiring cryptographic sessions and validates them with session_check. There is no registration endpoint. Internal service secrets and credential versions are never sent to the browser. See the [HTTP API](api.md) for route ownership and settings revisions.
