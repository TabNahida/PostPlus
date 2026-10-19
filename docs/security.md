# Login security and IP bans

Administration → **Security** configures live login protection and shows the
current ban pool. Password logins to Webmail, administration, SMTP, IMAP and
POP3, and Bearer API key authentication share the authentication service's IP
failure counters. Reconnecting or switching protocols does not reset them.

The default policy enables protection with a five-minute window. An IP is
temporarily blocked from authentication after five failures for nonexistent
accounts, or twenty total authentication failures. The ban lasts fifteen
minutes. Repeated attempts at the same missing account count, as do attempts
at different missing accounts. Existing accounts still return the same generic
invalid-credential error; public responses do not disclose account existence.

Adjust the window, thresholds and duration, add exact IP addresses or CIDR
networks to the automatic-ban allowlist, and manually ban or unban addresses
from the Security page. Duration inputs support seconds, minutes, hours and
days; the API continues to use whole seconds. Manual bans can instead be
permanent and remain in effect until an administrator unbans the address or
replaces the ban with a timed one. Automatic protection always creates timed
bans. Changes apply immediately without restarting services.
Counters and bans persist across authentication-service restarts; expired bans
stop blocking automatically. Successful authentication does not erase other
failures from that IP. Existing per-connection and global rate limits remain.

Bans reject new public connections to SMTP (including incoming delivery),
submission, POP3, IMAP, Webmail and administration. PostPlus closes the accepted
socket before TLS negotiation, protocol greetings, HTTP parsing or credential
processing. This is application-level admission control, not an OS firewall;
the operating system may still complete a TCP handshake. The indexed IP check
uses authenticated internal RPC with a two-second total deadline. If the
authentication service is unavailable or incompatible, public connections
close without proceeding. Internal RPC and the first-run configuration wizard
are excluded so setup and trusted recovery remain possible.

Already-open connections are not forcibly disconnected; credential checks on
them still enforce active bans. Browser cookies and API keys do not bypass the
connection check, so an existing browser login cannot reconnect from a blocked
IP. Use an authenticated administrator session from another unblocked IP, or
the trusted internal RPC with the service token, to unban the address. Timed
bans also stop blocking when they expire. Do not publish internal service
listeners or their shared token.

An explicit loopback-IP ban also blocks public-port health probes from that
address. Remove such a ban through trusted local RPC before restarting the
service group, otherwise its readiness checks can fail.

The recorded address comes from the actual TCP connection. Client JSON fields,
`Forwarded` and `X-Forwarded-For` headers do not override it. With a reverse
proxy or TCP relay, the source may therefore be that proxy. Use a correctly
scoped allowlist and edge rate limits for that deployment; broad proxy
allowlisting also exempts traffic arriving through it from automatic IP bans.
Allowlisting or disabling automatic protection does not remove an active ban;
unban that address first or wait for a timed ban's expiry. Permanent bans count
toward the same 10,000-address limit as timed bans.

Authentication logs include source IP, protocol, attempted account and outcome
for success, failure and blocked attempts. Ban creation, expiry, removal and
policy changes are logged. Rejected connections record their socket IP and
reason in the public service log, with the ban check also audited by `auth`.
Search the IP in **Service logs**.
Passwords, complete API keys and SASL payloads are never logged. Log rotation
and retention continue to apply; the ban pool is a current-state view.

## Administration API

An administrator browser session requires CSRF for mutations. Administrator
API keys require `security:read` for the view and `security:write` for changes.
Existing keys do not gain these permissions automatically.

| Method | Endpoint | Body |
| --- | --- | --- |
| GET | `/api/admin/security` | None |
| PUT | `/api/admin/security/policy` | `{"revision":1,"policy":{...}}` |
| POST | `/api/admin/security/ban` | `{"ip":"192.0.2.10","seconds":900,"reason":"Repeated login attempts"}` |
| POST | `/api/admin/security/ban` | `{"ip":"192.0.2.10","permanent":true,"reason":"Permanent administrator ban"}` |
| POST | `/api/admin/security/unban` | `{"ip":"192.0.2.10"}` |

The view returns `policy`, `revision`, `bans`, `server_time` and
`restart_required:false`. Supply the current revision when saving a complete
policy; a stale revision returns HTTP 409. The policy fields are `enabled`,
`window_seconds`, `failure_threshold`, `unknown_user_threshold`, `ban_seconds`
and `allowlist`. The window ranges from 1 to 86,400 seconds and the automatic
ban duration from 1 to 604,800 seconds. Manual timed bans use the same duration
range. The optional `permanent` field must be a boolean: `true` requires
omitting `seconds`, while `false` or an omitted `permanent` requires a valid
`seconds` value. Invalid changes leave an existing ban unchanged.

Each ban includes `permanent`. Timed bans expose an integer Unix `expires_at`;
permanent bans expose `expires_at:null`. This is compatible with existing timed
ban records and requires no data reset. A login request that creates a ban, or
a credential check on an already-open connection, can return HTTP 429 with code
`ip_banned` and a `permanent` boolean. Timed bans also
return `retry_after` seconds and the `Retry-After` header. Permanent bans omit
both retry fields and advise contacting an administrator. Later connections
from the banned IP close before HTTP, including connections with valid cookies
or API keys; no HTTP response or retry header is sent at this boundary.
