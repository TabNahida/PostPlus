# PACE backend integration

PostPlus uses the unmodified PACE 0.1.1 Xmake package. Production source no longer
depends on Asio; an independent Asio TLS client remains in interoperability tests.
The public APIs, configuration schema, and on-disk formats are unchanged.

| Component | Implementation |
|---|---|
| TCP listeners and connections | PACE TCP, including IPv4, IPv6, dual-stack listeners and numeric scope IDs |
| Timers and cancellation | PACE reactor callback timers and socket readiness cancellation |
| Hostname resolution | PACE DNS / c-ares |
| Public DNS diagnostics | Existing validated DNS wire protocol over PACE UDP/TCP |
| Internal RPC client | PACE HTTP/1 client with bounded headers/body and an absolute exchange deadline |
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

PACE 0.1.1's HTTP admission callback is synchronous on the reactor. PostPlus
preflight can call authentication RPC, so moving it directly into that callback
would either deadlock or serialize network progress. The server keeps its current
header-first authorization, Host/CSRF checks, duplicate/framing rejection, request
body limits, absolute receive budget, bounded rejection drain, and streamed backup
responses. The transport beneath that code is PACE.

PACE's owning HTTP server coroutine also does not expose a lifetime-safe handle
for canceling one transferred connection. Retaining only its numeric socket handle
would be unsafe after library-owned close and operating-system handle reuse.
Adopting that server API is a separate follow-up requiring asynchronous admission
and safe per-connection cancellation, tracked upstream in
[PACE #12](https://github.com/TabNahida/PACE/issues/12) and
[PACE #13](https://github.com/TabNahida/PACE/issues/13).

PACE TLS cancellation currently closes the underlying transport. A reusable TLS
input poll is requested in [PACE #14](https://github.com/TabNahida/PACE/issues/14). The application
adapter keeps PostPlus's reusable TLS poll/read cancellation and exact readiness
pinning semantics without patching or forking PACE. It does not claim to use the
PACE TLS stream or HTTP server parser.

## Validation and performance

`xmake test -v` includes native IPv6, absolute-budget, cancellation, concurrent
connection, DNS, outbound delivery, certificate selection and TLS polling tests.
`python tests/integration.py --bin-dir <directory>` exercises real temporary
services, including HTTP security, STARTTLS/IDLE, portals, setup, restart and update.

Validation on 2026-10-23:

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
