# Login security and temporary IP bans

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
from the Security page. Changes apply immediately without restarting services.
Counters and bans persist across authentication-service restarts; expired bans
stop blocking automatically. Successful authentication does not erase other
failures from that IP. Existing per-connection and global rate limits remain.

Bans apply to new credential checks, including API keys. They do not act as an
OS firewall and do not reject ordinary unauthenticated incoming SMTP delivery.
Existing browser sessions remain usable, allowing a signed-in administrator to
unban an address. If no administrator session is available, wait for expiry or
use the trusted internal RPC with the service token to unban the address. Do
not publish internal service listeners or their shared token.

The recorded address comes from the actual TCP connection. Client JSON fields,
`Forwarded` and `X-Forwarded-For` headers do not override it. With a reverse
proxy or TCP relay, the source may therefore be that proxy. Use a correctly
scoped allowlist and edge rate limits for that deployment; broad proxy
allowlisting also exempts traffic arriving through it from automatic IP bans.
Allowlisting or disabling automatic protection does not remove an active ban;
unban that address first or wait for expiry.

Authentication logs include source IP, protocol, attempted account and outcome
for success, failure and blocked attempts. Ban creation, expiry, removal and
policy changes are logged. Search the IP in **Service logs**, selecting `auth`.
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
| POST | `/api/admin/security/unban` | `{"ip":"192.0.2.10"}` |

The view returns `policy`, `revision`, `bans`, `server_time` and
`restart_required:false`. Supply the current revision when saving a complete
policy; a stale revision returns HTTP 409. The policy fields are `enabled`,
`window_seconds`, `failure_threshold`, `unknown_user_threshold`, `ban_seconds`
and `allowlist`. HTTP authentication blocked by a ban returns 429 with code
`ip_banned`, `retry_after` seconds and the `Retry-After` header.
