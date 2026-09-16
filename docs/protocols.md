# Protocol support in PostPlus 0.1

PostPlus is an initial implementation. The following table describes actual behavior; it is not a claim of full RFC compliance or compatibility with every desktop mail client. Each listener runs in its own process and uses standalone Asio through the shared connection layer.

## Transport and authentication

SMTP `STARTTLS`, POP3 `STLS`, and IMAP `STARTTLS` use the configured server certificate and key. After a TLS upgrade, clients must authenticate again; SMTP also requires a new greeting. Failed TLS negotiation closes the connection. Authentication over plaintext is permitted only when both `allow_insecure_auth` is true and the socket peer is loopback. Use the default false value in deployed configurations.

Accounts use full email addresses. SMTP PLAIN authorization identities must be empty or equal to the authenticating username. Authentication, mailbox operations, and queue submissions use authenticated internal RPC; a failed dependency produces a protocol error rather than accepting unpersisted work.

Each protocol connection closes after `max_auth_attempts` failed credential checks (default 5, bounded to 1–20). This limits work on one connection; deployments also need connection/IP rate limits at their ingress, since reconnecting starts a new connection counter.

## SMTP

Implemented commands: `EHLO`, `HELO`, `STARTTLS`, `AUTH PLAIN`, `AUTH LOGIN`, `MAIL FROM`, `RCPT TO`, `DATA`, `RSET`, `NOOP`, `HELP`, `QUIT`.

- EHLO advertises SIZE, HELP, and authentication/TLS capabilities only when available in the current connection state.
- Ordinary commands are bounded to 512 bytes including CRLF (AUTH permits the larger RFC 4954 limit). DATA lines are bounded to 1,000 bytes including CRLF, excluding the extra transparency dot. The configured message size limit applies to the unstuffed message including line endings. `max_recipients` bounds each transaction (default 100, bounded to 1–100, matching storage and Webmail).
- `smtp_data_timeout_seconds` limits the entire DATA reception stage (default 120; configuration must be an integer from 1 to 3,600). Continuous valid lines do not extend this absolute deadline. Expiry closes the connection without queuing partial mail. Once the terminating dot is received, ordinary operation timeouts apply again to storage and the SMTP response.
- `MAIL FROM` accepts the ESMTP `SIZE` parameter. Unsupported MAIL and RCPT parameters are rejected. An empty reverse path is accepted for delivery status messages.
- Local recipients must exist in the authentication service. External recipients require an authenticated session and a configured `smarthost_host`.
- Dot transparency is implemented. DATA receives a successful final response only after the storage service durably queues all recipient jobs. Scanning happens in the delivery process; policy rejections are retained in the queue for operator inspection.
- STARTTLS resets the authentication and transaction state. Messages cannot request a TLS upgrade partway through a transaction.
- A new MAIL command resets the old transaction even if its address or SIZE argument is rejected, so old recipients cannot leak into a later submission.

Not implemented: SMTPUTF8, 8BITMIME negotiation, CHUNKING/BDAT, DSN negotiation, public MX lookup, DKIM signing, SPF or DMARC verification. Outgoing remote delivery uses the configured smarthost. This is not a public Internet mail gateway yet.

## POP3

Implemented commands: `CAPA`, `STLS`, `USER`, `PASS`, `STAT`, `LIST`, `UIDL`, `RETR`, `TOP`, `DELE`, `RSET`, `NOOP`, `QUIT`.

The mailbox is snapshotted after successful authentication. Message numbers are stable within the session. UIDL uses the persisted UID. DELE marks messages within the session, RSET clears those marks, and QUIT commits all deletions in one storage transaction. Disconnecting does not commit deletions. RETR/TOP use CRLF and dot-stuff response lines. New mail is visible after reconnecting. Concurrent sessions share storage; a message removed by another session can become unavailable before RETR.

Not implemented: APOP, SASL POP authentication, implicit TLS ports, expiry policies, and exclusive maildrop locking.

## IMAP

IMAP exposes six fixed mailboxes: `INBOX`, `Sent`, `Drafts`, `Trash`, `Junk`, and `Archive`. It reports `IMAP4rev1` for client protocol negotiation, but currently implements only the subset below. The project does **not** claim complete IMAP4rev1 conformance. Applications requiring custom folders, APPEND, COPY, MOVE, ENVELOPE, BODYSTRUCTURE, full SEARCH, or IDLE cannot use this release as a complete IMAP replacement. Webmail can save drafts and move messages through its HTTP API.

Implemented commands:

- `CAPABILITY`, `STARTTLS`, `LOGIN`, `AUTHENTICATE PLAIN`, `NOOP`, `LOGOUT`.
- `LIST`, `LSUB` (the six fixed subscribed mailboxes), `SELECT`, `EXAMINE`, `STATUS`, `CHECK`, `CLOSE`, `EXPUNGE`.
- `FETCH` and `UID FETCH`: `FLAGS`, `UID`, `INTERNALDATE`, `RFC822.SIZE`, `RFC822`, `RFC822.HEADER`, `RFC822.TEXT`, `FAST`, `BODY[]`, `BODY[HEADER]`, `BODY[TEXT]`, `BODY[HEADER.FIELDS (...)]`, and `BODY[HEADER.FIELDS.NOT (...)]`. BODY.PEEK variants and `<offset.count>` partial reads are supported. MIME numeric part sections and the ALL/FULL macros are rejected.
- `STORE` and `UID STORE`: FLAGS, +FLAGS, -FLAGS and their .SILENT variants, for `\Seen` and `\Deleted`. Seen is persisted; Deleted is session-local, as stated by the PERMANENTFLAGS response. EXPUNGE/CLOSE commit marked deletions atomically. EXAMINE prevents changes and CLOSE on an examined mailbox simply deselects it.
- `SEARCH` and `UID SEARCH`: sequence sets, UID sets, ALL, SEEN, UNSEEN, DELETED, UNDELETED, HEADER, FROM, TO, CC, BCC, SUBJECT, BODY, TEXT, LARGER, SMALLER, NOT, OR, and parenthesized AND groups. US-ASCII and UTF-8 charset labels are accepted. String matching folds ASCII case; general Unicode case folding and charset conversion are not implemented. MIME body searches inspect decoded leaf content. All messages currently have no Recent flag: OLD matches all, RECENT/NEW match none.
- `STATUS`: MESSAGES, RECENT, UIDNEXT, UIDVALIDITY, UNSEEN.

UIDs and UIDVALIDITY persist across service restarts. Message numbers remain fixed during FETCH/STORE/SEARCH; NOOP refreshes the selected mailbox and announces additions/removals. Reads of message bodies mark Seen unless PEEK or EXAMINE applies. Synchronizing command literals are accepted up to 16 KiB each, with at most 8 literals and 64 KiB per command. Invalid framing closes the connection to prevent command desynchronization. LITERAL+ is not advertised or accepted. Unsupported operations return tagged BAD/NO.

POP3 reads only `INBOX`; its QUIT deletions and IMAP EXPUNGE/CLOSE permanently remove messages as required by those protocols. Webmail's Delete action moves mail to Trash and permanently deletes it only when already in Trash. Messages moved between folders receive fresh IMAP UIDs; draft content replacements do too. Protocol deletions check the selected folder and snapshotted UID so a concurrent move cannot accidentally delete a message from its new location. Authenticated SMTP submissions and Webmail sends store a Sent copy atomically with queue acceptance; inbound unauthenticated SMTP does not create a Sent copy. SMTP Sent ownership follows the authenticated account.

## MIME

The shared `postplus::mime` library supports unfolded headers, multipart boundaries and nested parts, message/rfc822 nesting, base64, quoted-printable, and RFC 2047 B/Q encoded words. Parsing bounds total input and aggregate decoded bytes (including nested message containers), header bytes, header count, part count, and nesting depth. Malformed transfer encodings, duplicate structural MIME headers, and incomplete multipart bodies are rejected.

Decoded content is returned as bytes, preserving its declared charset; conversion from legacy charsets is not implemented. The composer produces text/plain UTF-8 messages, folded encoded subjects, Date, Message-ID, and MIME headers. It validates sender/recipient addresses and rejects CR/LF/NUL subject injection. HTML rendering, attachment composition, S/MIME, and PGP/MIME are outside this initial API.
