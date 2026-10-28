# PACE backend integration

PostPlus uses the unmodified PACE 0.4.0 Xmake package. Production source no longer
depends on Asio; an independent Asio TLS client remains in interoperability tests.
The public APIs, configuration schema, and on-disk formats are unchanged.

| Component | Implementation |
|---|---|
| TCP listeners and connections | PACE TCP, including IPv4, IPv6, dual-stack listeners and numeric scope IDs |
| Timers and cancellation | PACE reactor callback timers and socket readiness cancellation |
| Hostname resolution | PACE DNS / c-ares |
| Public DNS diagnostics | PACE UDP `async_exchange` with source filtering and a shared deadline; validated DNS wire format and TCP fallback |
| Internal RPC client | PACE HTTP/1 `async_fetch` with bounded headers/body and an absolute exchange deadline |
| HTTP servers | Existing PostPlus framing, admission, response and file streaming policy over PACE transport |
| Mail and HTTPS TLS | OpenSSL application adapter over PACE-owned sockets and readiness |
| ACME, ClamAV, relay, MX delivery, port probes | Shared PACE connection/listener facade |

## Execution and compatibility

One PACE reactor per process owns every socket. Synchronous mail/database handlers
run in a bounded worker pool, submitting network coroutines through futures.
Socket creation, cancellation and destruction stay on the reactor. A blocked
client therefore does not hold up another connection's network operations.
The service admission cap also bounds queued sessions. Shutdown closes listeners,
cancels active session I/O when requested, and joins workers before the reactor.

The absolute connection deadline spans repeated reads and DNS/connect retries;
incoming fragments cannot restart it. Polling is separate from connection failure:
an IMAP IDLE timeout leaves the connection usable for notifications and DONE.
STARTTLS still rejects buffered plaintext and never falls back after a failed
handshake. IPv6 and mapped-address policy, CIDRs, and outbound SSRF restrictions
retain their existing behavior.

The TLS adapter preserves TLS 1.2 minimum, server-side renegotiation rejection, system trust roots,
chain and hostname/IP verification, per-domain SNI and failure isolation. Ordinary
outbound TLS requires verified certificates. Only the private supervisor probe
uses the existing exact configured-leaf match, including the previous readiness
behavior for self-signed or expired local certificates.

Certificate and trust-store preparation runs on workers before the handshake, and
counts toward its deadline. A bounded cache shares immutable server contexts;
each preparation checks certificate/key metadata and reloads changed pairs.
Broken optional credentials affect only their matching SNI hostname. Concurrent
connections retain their own certificate-selection state.

## High-level API boundaries

PostPlus 1.3.0 adopts PACE 0.4.0's `http::async_fetch` for internal RPC and
`udp::async_exchange` for public DNS. The executor's deadline overload wraps both
in `pace::with_deadline`, including dispatch delay and nested socket waits, and
maps timeout errors to the existing application exception. PACE owns and closes
each exchange's socket before completion. This removes the RPC socket-pointer
handoff and manual cancellation timer, along with the hand-written UDP receive
and source-filtering loop. The shared reactor remains in use; direct blocking
clients that create a context for every request are unnecessary here.

RPC preserves its bearer token, loopback endpoint, request framing, 32 KiB header
limit, configured body bound and response validation. DNS keeps its 8 KiB receive
bound, truncation checks, transaction/question validation and TCP fallback.
Filtering by IP, port, address family and scope is provided by PACE's exchange.

The application HTTP server still owns header-first authorization, Host/CSRF
checks, duplicate/framing rejection, body limits, bounded rejection drain and
streamed backup responses. Its handlers perform synchronous database and RPC
work on the bounded worker pool. The existing TLS adapter also retains per-domain
SNI, platform trust, reusable mail input polling and exact readiness pinning.
Those application policies are outside this targeted client API migration.

See PACE's [0.4.0 client migration guide](https://github.com/TabNahida/PACE/blob/v0.4.0/docs/reference/direct-clients.md)
and [deadline contracts](https://github.com/TabNahida/PACE/blob/v0.4.0/docs/reference/structured-concurrency.md).

## Validation and performance

`xmake test -v` includes native IPv6, absolute-budget, cancellation, concurrent
connection, DNS, outbound delivery, certificate selection and TLS polling tests.
`python tests/integration.py --bin-dir <directory>` exercises real temporary
services, including HTTP security, STARTTLS/IDLE, portals, setup, restart and update.

Historical migration validation on 2026-10-23 (before the 0.4.0 upgrade):

- Windows x64 / MSVC: release build and all 16 native tests passed. The full
  integration suite passed during migration; HTTP security, TLS transfer, IMAP,
  portal, setup and restart suites were then rerun after the connection/TLS changes.
  The final client TLS compatibility adjustment was checked again with all native
  tests and TLS transfer integration.
- Ubuntu 24.04 under WSL2 / GCC 13.3: final release build, all 16 native tests,
  and all six integration suites listed above passed in an isolated temporary
  project. Linux also passed active-session SIGTERM shutdown, which the Windows
  test skips because `terminate()` uses `TerminateProcess` there.
- IMAP tests on both platforms withhold the tail of a TLS 1.2/1.3 record across
  IDLE poll expiry, verify outbound mailbox notifications, then complete the
  record and verify DONE plus the next command. Certificate tests cover concurrent
  SNI, repeated handshakes, same-path certificate/key rotation and failure recovery.

macOS was not executed locally. Windows symlink testing was skipped when the host
did not provide the required privilege. These runs use temporary services and data.

The benchmark methodology, raw measurements and limitations are recorded in
[network migration benchmark](pace-benchmark.md). The comparison measures this
PostPlus integration, including its worker/reactor bridge, rather than PACE's
standalone maximum throughput.
