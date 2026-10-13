# Protocol support in PostPlus

PostPlus is an initial implementation. The following sections describe actual behavior; they are not a claim of full RFC compliance or compatibility with every desktop mail client. Each protocol service runs in its own process and uses standalone Asio through the shared connection layer.

## Transport and authentication

SMTP `STARTTLS`, POP3 `STLS`, and IMAP `STARTTLS` use the configured server certificate and key. After a TLS upgrade, clients must authenticate again; SMTP also requires a new greeting. Failed TLS negotiation closes the connection. Authentication over plaintext is permitted only when both `allow_insecure_auth` is true and the socket peer is loopback. Use the default false value in deployed configurations.

Default public ports are SMTP 25, submission 587, SMTPS 465, POP3 110/995, and IMAP 143/993. Port 587 requires STARTTLS and authentication; port 465 requires implicit TLS and authentication. Ports 995 and 993 use implicit TLS. The four encrypted client listeners start only when both TLS certificate and key are configured, and each can be disabled by setting its port to `0`. The loopback plaintext-authentication option never permits plaintext authentication on submission 587. SMTP 25 accepts unauthenticated mail only for existing local recipients. Explicitly configured ports are preserved.

Accounts use full email addresses. SMTP PLAIN authorization identities must be empty or equal to the authenticating username. Authentication, mailbox operations, and queue submissions use authenticated internal RPC; a failed dependency produces a protocol error rather than accepting unpersisted work.

Each protocol connection closes after `max_auth_attempts` failed credential checks (default 5, bounded to 1–20). This limits work on one connection; deployments also need connection/IP rate limits at their ingress, since reconnecting starts a new connection counter.

## SMTP

Implemented commands: `EHLO`, `HELO`, `STARTTLS`, `AUTH PLAIN`, `AUTH LOGIN`, `MAIL FROM`, `RCPT TO`, `DATA`, `RSET`, `NOOP`, `HELP`, `QUIT`.

- EHLO advertises SIZE, 8BITMIME, HELP, and authentication/TLS capabilities only when available in the current connection state.
- Ordinary commands are bounded to 512 bytes including CRLF (AUTH permits the larger RFC 4954 limit). DATA lines are bounded to 1,000 bytes including CRLF, excluding the extra transparency dot. The configured message size limit applies to the unstuffed message including line endings. `max_recipients` bounds each transaction (default 100, bounded to 1–100, matching storage and Webmail).
- `smtp_data_timeout_seconds` limits the entire DATA reception stage (default 120; configuration must be an integer from 1 to 3,600). Continuous valid lines do not extend this absolute deadline. Expiry closes the connection without queuing partial mail. Once the terminating dot is received, ordinary operation timeouts apply again to storage and the SMTP response.
- `MAIL FROM` accepts ESMTP `SIZE` and `BODY=7BIT`/`BODY=8BITMIME` parameters. Duplicate or unsupported MAIL parameters and all RCPT parameters are rejected. An empty reverse path is accepted for delivery status messages.
- Local recipients must exist in the authentication service. External recipients require an authenticated session and enabled direct or relay delivery.
- Dot transparency is implemented. DATA receives a successful final response only after the storage service durably queues all recipient jobs. Scanning happens in the delivery process; policy rejections are retained in the queue for operator inspection.
- STARTTLS resets the authentication and transaction state. Messages cannot request a TLS upgrade partway through a transaction.
- A new MAIL command resets the old transaction even if its address or SIZE argument is rejected, so old recipients cannot leak into a later submission.

Outgoing delivery supports public MX lookup, priority/address failover, bounded retries and RSA-SHA256 DKIM signing. Direct mode uses TCP 25 and verified STARTTLS when offered; required TLS can be selected. Remote public recipients cannot route delivery to private/loopback addresses. Not implemented: SMTPUTF8, 8BITMIME negotiation, CHUNKING/BDAT, DSN negotiation/generation, incoming SPF/DKIM/DMARC verification, DANE and MTA-STS.

## POP3

Implemented commands: `CAPA`, `STLS`, `USER`, `PASS`, `STAT`, `LIST`, `UIDL`, `RETR`, `TOP`, `DELE`, `RSET`, `NOOP`, `QUIT`.

The mailbox is snapshotted after successful authentication. Message numbers are stable within the session. UIDL uses the persisted UID. DELE marks messages within the session, RSET clears those marks, and QUIT commits all deletions in one storage transaction. Disconnecting does not commit deletions. RETR/TOP use CRLF and dot-stuff response lines. New mail is visible after reconnecting. Concurrent sessions share storage; a message removed by another session can become unavailable before RETR.

Not implemented: APOP, SASL POP authentication, expiry policies, and exclusive maildrop locking.

## IMAP

IMAP exposes six fixed mailboxes: `INBOX`, `Sent`, `Drafts`, `Trash`, `Junk`, and `Archive`. It reports `IMAP4rev1`, `UIDPLUS`, and `MOVE` for client protocol negotiation, but currently implements only the subset below. The project does **not** claim complete IMAP4rev1 conformance. Custom folders, full SEARCH, and IDLE remain unsupported.

Implemented commands:

- `CAPABILITY`, `STARTTLS`, `LOGIN`, `AUTHENTICATE PLAIN` with continuation or SASL initial response, `NOOP`, `LOGOUT`.
- `LIST`, `LSUB`, `SUBSCRIBE`, `UNSUBSCRIBE`, `SELECT`, `EXAMINE`, `STATUS`, `CHECK`, `CLOSE`, `UNSELECT`, `EXPUNGE`, `UID EXPUNGE`. Subscriptions are fixed to the six mailboxes; SUBSCRIBE/UNSUBSCRIBE validate an existing mailbox but do not persist subscription changes.
- `FETCH` and `UID FETCH`: `FLAGS`, `UID`, `INTERNALDATE`, `RFC822.SIZE`, `RFC822`, `RFC822.HEADER`, `RFC822.TEXT`, `ENVELOPE`, `BODY`, `BODYSTRUCTURE`, `FAST`, `ALL`, `FULL`, `BODY[]`, `BODY[HEADER]`, `BODY[TEXT]`, `BODY[HEADER.FIELDS (...)]`, and `BODY[HEADER.FIELDS.NOT (...)]`. Numeric MIME sections, nested `message/rfc822` sections, BODY.PEEK variants, and `<offset.count>` partial reads are supported. Fetches retain original transfer-encoded bytes; missing numeric parts return NIL.
- `STORE` and `UID STORE`: FLAGS, +FLAGS, -FLAGS and their .SILENT variants, for `\Seen`, `\Answered`, `\Flagged`, `\Draft`, and `\Deleted`. All except Deleted are persisted; Deleted is session-local, as stated by the PERMANENTFLAGS response. EXPUNGE/CLOSE commit marked deletions atomically; UID EXPUNGE restricts deletion to the specified UIDs. EXAMINE prevents changes and CLOSE on an examined mailbox simply deselects it.
- `APPEND` accepts a synchronizing message literal within the configured message size limit, optional persistent flags, and an optional internal date. `APPENDUID` reports the durable new UID. `COPY`/`UID COPY` and `MOVE`/`UID MOVE` retain content, date, and persistent flags, enforce quota, and return `COPYUID`; moves assign a fresh destination UID atomically.
- `SEARCH` and `UID SEARCH`: sequence sets, UID sets, ALL, SEEN, UNSEEN, ANSWERED, UNANSWERED, FLAGGED, UNFLAGGED, DRAFT, UNDRAFT, DELETED, UNDELETED, HEADER, FROM, TO, CC, BCC, SUBJECT, BODY, TEXT, LARGER, SMALLER, NOT, OR, and parenthesized AND groups. US-ASCII and UTF-8 charset labels are accepted. String matching folds ASCII case; general Unicode case folding and charset conversion are not implemented. MIME body searches inspect decoded leaf content. All messages currently have no Recent flag: OLD matches all, RECENT/NEW match none.
- `STATUS`: MESSAGES, RECENT, UIDNEXT, UIDVALIDITY, UNSEEN.

UIDs and UIDVALIDITY persist across service restarts. Message numbers remain fixed during FETCH/STORE/SEARCH; NOOP refreshes the selected mailbox and announces additions/removals. Reads of message bodies mark Seen unless PEEK or EXAMINE applies. Synchronizing command literals are accepted up to 16 KiB each, with at most 8 literals and 64 KiB per command; APPEND's final message literal instead uses the configured message size limit. Invalid framing closes the connection to prevent command desynchronization. LITERAL+ is not advertised or accepted. Unsupported operations return tagged BAD/NO.

POP3 reads only `INBOX`; its QUIT deletions and IMAP EXPUNGE/CLOSE permanently remove messages as required by those protocols. Webmail's Delete action moves mail to Trash and permanently deletes it only when already in Trash. Messages moved between folders receive fresh IMAP UIDs; draft content replacements do too. Protocol deletions check the selected folder and snapshotted UID so a concurrent move cannot accidentally delete a message from its new location. Authenticated SMTP submissions and Webmail sends store a Sent copy atomically with queue acceptance; inbound unauthenticated SMTP does not create a Sent copy. SMTP Sent ownership follows the authenticated account.

## MIME

The shared `postplus::mime` library supports unfolded headers, multipart boundaries and nested parts, message/rfc822 nesting, base64, quoted-printable, and RFC 2047 B/Q encoded words. Parsing bounds total input and aggregate decoded bytes (including nested message containers), header bytes, header count, part count, and nesting depth. Malformed transfer encodings, duplicate structural MIME headers, and incomplete multipart bodies are rejected.

MIME leaf bodies remain decoded bytes in their original character set. Display helpers convert declared charsets to UTF-8, including Chinese legacy encodings, and decode RFC 2047 header charsets; storage and protocol fetches preserve the original message. Multipart alternatives expose plain text and HTML, related raster CID images are available to the isolated browser renderer, and attached RFC 822 messages have separate forwarded views. The composer produces text/plain UTF-8 messages, folded encoded subjects, Date, Message-ID, and MIME headers. It validates sender/recipient addresses and rejects CR/LF/NUL subject injection. Attachment composition, S/MIME, and PGP/MIME are outside this initial API.
