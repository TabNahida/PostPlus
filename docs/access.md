# Mailbox features and API permissions

[Login security and IP bans](security.md) documents the shared authentication policy, audit logs and dedicated API-key permissions.

Webmail badges show unread counts for Inbox, Junk and Archive, and unsent draft counts for Drafts. Sent and Trash have no count badges.

## Latest verification code

`GET /api/verification-code` on the Webmail origin accepts a session cookie or a mailbox key with `codes:read`. It searches up to 30 newest messages from the past 15 minutes, with a bounded source-byte budget. The optional `folder=INBOX` (default) or `folder=Trash` selects the current folder; all other folders and account/message filters are rejected. Webmail displays this panel only in Inbox and Trash. Drafts are excluded; lookup/copy does not mark messages Seen. Account/message filters are rejected.

Decoded plain text and HTML are checked for confident digit/alphanumeric verification codes. Attachments, forwarded/quoted content, hidden HTML, URLs and ambiguous competing codes are ignored. A match returns:

```json
{"ok":true,"found":true,"code":"123456","message_id":"...","from":"...","subject":"...","received_at":1791849600,"expires_at":1791850500}
```

No match returns `{"ok":true,"found":false}`. Times are Unix seconds. `expires_at` is the lookup/display cutoff; actual validity is determined by the sender. The Webmail card offers copying, refreshes every 15 seconds while the page is visible, and clears expired results.

In 0.5.0, add `include_links=true` to also recognize email/account verification, activation, sign-in and password-reset links. For example, `GET /api/verification-code?folder=INBOX&include_links=true` returns the newest message with a confident code or action link. Its response adds `link: {"url":"https://accounts.example.com/verify?token=...","label":"Verify your email"}` or `link:null`; `code` is `null` for a link-only result. Omitting this option preserves the original response and newest-code behavior. The same `codes:read` permission, ownership checks and lookup limits apply.

Recognition uses decoded MIME text, visible anchor labels, nearby action wording and URL routes. It handles fullwidth digits, nonbreaking separators, individually spaced digits and common passcode labels. Unlabelled years, attachments, hidden/quoted content, competing equally confident links, unsubscribe/tracking routes, ordinary social footers and malformed URLs are excluded. Social services' actual account verification links remain eligible. Only absolute HTTP(S) links without embedded credentials are returned; redirects are never followed and no extraction step fetches a URL. Recognition is deliberately conservative and is not an authenticity or phishing verdict.

Webmail displays the sender and complete destination with an **Open verification link** action. Opening requires a click, uses a separate tab without an opener or referrer, and expired links are removed alongside codes. Check the sender and destination before opening; real validity and any action performed remain controlled by the sender. API consumers should treat link tokens as private and apply their own navigation policy.

## Mailbox invitations

Administration → **User accounts** → **Invite to mailbox** opens invitation creation, metadata and revocation in a dialog beside **Create user**. Closing it clears any one-time registration link, including a late creation reply.

The account table starts expanded, can be collapsed, and filters email addresses as you type. Mail forwarding is a separate, initially collapsed table above the account password policy. All three disclosure headers have the same dimensions. Invitation creation and the one-time link/copy actions appear above the independently scrolling invitation history.

## Account deletion

**Delete account** asks for the complete email address before removing an account. The signed-in account and the last administrator are protected. The equivalent API is `DELETE /api/admin/users` with `{"username":"friend@example.com","confirm_username":"friend@example.com"}` and `users:write`; session requests also require CSRF.

Deletion first disables credentials, API keys and invitations, then purges stored messages, mailbox quota, forwarding rules targeting the inbox, and queued mail to or from the account. Work already sent to an external SMTP server cannot be recalled. Existing Webmail, IMAP, POP3 and authenticated SMTP sessions stop working; credential versions prevent old sessions accessing a later account at the same address.

If storage cleanup is unavailable, the account stays disabled and appears as **Deletion pending**. **Finish deletion** retries cleanup; the address cannot be registered again until cleanup succeeds. This state survives service restarts. A successfully reused address gets an empty mailbox and fresh UID validity. Empty delivery receipts prevent an already-running worker from restoring mail from a deleted queue snapshot.

## Invitation API

| Method and path | Body / result | Key permission |
| --- | --- | --- |
| GET `/api/admin/invitations` | Metadata only; no reusable links. | `invites:read` |
| POST `/api/admin/invitations` | `name`, optional `domain` (a hosted suffix; defaults to primary), `localpart`, `expires_in_days` (1–365, default 7), `max_uses` (1–100, default 1); returns 201 with one-time `registration_url` and metadata. | `invites:write` |
| DELETE `/api/admin/invitations/{id}` | Revokes unused capacity immediately. | `invites:write` |

Invitations register ordinary accounts in their selected hosted domain. Listing includes `domain` (primary) and `domains` (all hosted suffixes). Removing an invitation's domain makes it inactive without redirecting registration to a different domain. An assigned localpart requires `max_uses:1`; blank allows invitees to choose. Links use the Webmail hostname and `/register#pp_inv_...`, keeping tokens out of URL requests/referrers. The page clears the fragment from history and posts JSON to public Webmail endpoints:

- POST `/api/public/invitations/inspect`: `{ "token": "pp_inv_..." }`; returns domain, assigned localpart, expiry and password policy.
- POST `/api/public/invitations/redeem`: `{ "token": "pp_inv_...", "localpart": "friend", "password": "..." }`; creates the ordinary account and returns 201.

Secure account transport and rate limits apply; loopback development can explicitly enable insecure auth. Live password policy, creation and consumption are checked atomically. Failed registration preserves remaining uses. Invalid/expired/revoked/exhausted tokens return 410; duplicate mailbox returns 409. Only token digests are stored.

## Local mail forwarding

Administration → **User accounts** manages local inbox routing.

| Method and path | Body / result | Key permission |
| --- | --- | --- |
| GET `/api/admin/forwarding` | Local rules and total. | `forwarding:read` |
| POST `/api/admin/forwarding` | `{"pattern":"sales-*","destination":"owner@example.com"}`; returns 201. | `forwarding:write` |
| DELETE `/api/admin/forwarding/{id}` | Removes the rule for future mail. | `forwarding:write` |

Use an exact source address or prefix, such as `support@example.com` or `support`, for ordinary forwarding. The source can be an existing account or an alias without an account. An exact rule redirects delivery to its destination inbox; it does not keep an additional copy in the source inbox. Exact self-forwarding is rejected.

Patterns optionally include a hosted domain, for example `sales-*@example.net`. A prefix-only pattern applies to the primary domain. Rules never match across suffixes; each domain may have the same independent pattern. `*` matches any string; `?` matches one character. Domain wildcards and regular expressions are unsupported. Wildcard rules apply only to unregistered addresses, preserving normal delivery to accounts without an exact forwarding rule. Overlapping patterns prefer most literal characters, fewest `*`, fewest `?`, then lowest rule ID.

Destinations must be existing mailboxes in any hosted domain, so forwarding from one hosted suffix to another is supported. Listing includes rules from every domain, including retained rules for removed suffixes so administrators can remove them. Routing is a single hop directly into the destination inbox; destination forwarding rules are not evaluated again. Chained or cyclic rules therefore cannot loop or unexpectedly move the message onward. External mailbox destinations are unsupported.

SMTP and Webmail share routing, preserve original MIME recipients, pin the chosen inbox in the durable queue, and deduplicate equivalent destinations. Rule edits cannot reroute queued mail. Missing targets retry rather than silently dropping mail. An unknown address without a rule remains unknown. Unauthenticated external relay remains blocked.

## API key permissions

Create keys with explicit `permissions`. Unknown or duplicate IDs are rejected. An empty array grants no operations. Listing keys returns available IDs in `permissions`; each key contains its own array plus `audience` (`admin` or `mailbox`, also exposed as `scope` for compatibility). Existing keys migrate with previous full administrator grants.

Administrator IDs are `users:read/write`, `quota:read/write`, `policy:read/write`, `config:read/write`, `backup:read/write`, `updates:read/write`, `invites:read/write`, `forwarding:read/write`, plus `mail:read`, `stats:read`, `queue:read`, `logs:read`, `services:write`. Here `:read/write` means two separate IDs, such as `users:read` and `users:write`. Certificates use `config`; restart/shutdown use `services:write`; update checks use `updates:read`, installation uses `updates:write`.

Webmail **Mailbox API keys** manages the signed-in user's credentials using GET/POST `/api/api-keys` and PATCH/DELETE `/api/api-keys/{id}`. Create accepts `name`, optional `expires_in_days`, and `permissions`. PATCH accepts only `permissions`. All key management requires cookie and CSRF, including GET. Keys cannot manage keys.

| Mailbox permission | Operations |
| --- | --- |
| `mailbox:read` | Folders and messages; opening a message uses the normal Seen behavior. |
| `mailbox:write` | Message moves/deletion and drafts. |
| `mailbox:send` | Send as the key owner. |
| `codes:read` | Latest verification code or opt-in verification link without message source or Seen changes. |

Mailbox keys cannot select another account or access administration. Administrator keys cannot access mailbox APIs. Every request rechecks owner, permissions, expiry and revocation; changes apply without restart or key rotation. Missing permissions return 403, invalid credentials return 401. Explicit Bearer credentials never fall back to cookies. Remote requests require HTTPS.

```sh
curl --fail --silent --show-error \
  -H "Authorization: Bearer $POSTPLUS_MAILBOX_KEY" \
  https://mail.example.com/api/verification-code
```
