# PACE bridge performance follow-up

This follow-up reduces selected PostPlus networking overhead while retaining the
unmodified PACE 0.1.1 dependency. Measurements are mixed; they do not establish an
overall or production-capacity gain. The final comparison includes the bounded
connection-admission repair found during cross-platform validation.

## Changes

- Create outbound sockets when connecting. Accepted connections use the socket
  supplied by the listener, avoiding a throwaway OS socket and reactor handoff
  on every accept attempt, including idle accept polling.
- Capture the peer endpoint when connect/accept succeeds. Admission and HTTP
  handlers can reuse that immutable identity without another reactor handoff.
- Combine HTTP headers and in-memory bodies up to 64 KiB into one write. Larger
  responses and file downloads retain their bounded streaming behavior.
- For complete requests with small plaintext HTTP responses, write and initiate
  TCP shutdown on the reactor. The PACE client can observe response completion
  without waiting for a worker to resume and destroy the connection. Trailing
  input drain is bounded to 100 ms and 8 KiB. TLS, early rejection and incomplete
  request handling retain their existing paths.
- At connection capacity, allow one accepted waiter per listener for up to
  200 ms while completed sessions release their slots. The active/queued worker
  limit remains unchanged; saturation still rejects excess connections, and
  shutdown wakes waiters. This fixes the handoff race exposed by Linux/macOS
  concurrency tests after initiating graceful close earlier. A deterministic
  capacity-1 regression fails before the fix and passes afterwards; capacity-2
  concurrent requests and sustained-capacity rejection are also covered.

The last change uses PACE's existing server-side graceful close; it does not patch
PACE or bypass PostPlus's framing, authentication, deadlines, or cancellation.

## Final same-host comparison

The final comparison uses a fixed **A → B → B → A** order, with A = frozen
PostPlus 1.0.0 (`9e2513130327528143ab91861d5cf60ea35564aa`) and B = the completed
changes including the admission fix (`1a39d51f2f372c330d57a8af5a2cdc5b19b783b3`).
Before every block, host TCP `TIME_WAIT` connections were allowed to fall below
1,000 (observed counts: 39, 31, 23, 19). This avoids carrying the previous block's
large volume of closed connections into the next measurement.

Both builds use MSVC Release, official PACE 0.1.1, frozen 1.0.0 Web assets and
configuration, the same harness, Windows 11 x64 and Python 3.13.3. Local builds,
probes and integration tests were stopped. Every block contains three rounds of
the existing [benchmark method](pace-benchmark.md#method): concurrency 8, a new
connection per operation, 1,000 health requests, 300 mailbox requests, 1,000 storage
RPC requests and 80 SMTP messages per round. Warmup is 40 requests or 8 messages,
with 50 seeded messages of 4,096 bytes and a server connection limit of 128.

Each version therefore has six measured rounds: **14,280 operations without
errors** and all **528 SMTP messages delivered**, including warmup. Throughput is
the median of all six round rates; latency percentiles pool their individual
samples. The queue and complete delivery are checked after each timed round.

| Block | Build | UTC on 2026-10-23 | Raw schema-2 JSON (gzip) |
|---|---|---|---|
| A1 | 1.0.0 | 18:05:50–18:06:05 | [A1](benchmarks/postplus-abba-A1-windows-2026-10-23.json.gz) |
| B1 | Final changes | 18:08:06–18:08:22 | [B1](benchmarks/postplus-abba-B1-windows-2026-10-23.json.gz) |
| B2 | Final changes | 18:10:23–18:10:39 | [B2](benchmarks/postplus-abba-B2-windows-2026-10-23.json.gz) |
| A2 | 1.0.0 | 18:12:40–18:12:56 | [A2](benchmarks/postplus-abba-A2-windows-2026-10-23.json.gz) |

The [summary and evidence manifest](benchmarks/postplus-abba-summary-windows-2026-10-23.json)
retains binary/harness hashes, host details, parameters, all rates and percentiles,
and compressed/uncompressed hashes of the raw files.

| Workload | Baseline ops/s | Final ops/s | Median change | Baseline p95 ms | Final p95 ms |
|---|---:|---:|---:|---:|---:|
| HTTP health | 2,531.07 | 3,711.14 | +46.6% | 5.434 | 2.306 |
| Authenticated mailbox | 984.24 | 959.42 | −2.5% | 23.906 | 26.498 |
| Storage RPC | 5,489.84 | 6,472.82 | +17.9% | 1.687 | 1.658 |
| SMTP durable acceptance | 237.30 | 245.10 | +3.3% | 53.244 | 50.238 |

| Workload | Baseline round range, ops/s | Final round range, ops/s |
|---|---:|---:|
| HTTP health | 2,339–3,244 | 2,883–4,597 |
| Authenticated mailbox | 942–1,081 | 726–1,132 |
| Storage RPC | 3,879–6,511 | 5,972–6,724 |
| SMTP durable acceptance | 228–250 | 215–283 |

All round ranges overlap. HTTP health and RPC have higher medians in this final
measurement, but mailbox throughput and p95 worsened. The small SMTP median
increase is within substantial variation, and SMTP p99 worsened from 63.146 to
69.382 ms. The fixed order counterbalances some time drift; it is not randomized
and does not establish statistical significance. These short, closed-loop runs
share a host with the load generator and do not establish sustained capacity,
production, TLS, Linux or macOS gains.

## Earlier and excluded measurements

These results are retained to avoid selecting only a favorable measurement:

- The initial [baseline](benchmarks/postplus-100-before-optimization-windows-2026-10-23.json)
  and [pre-admission-fix candidate](benchmarks/postplus-bridge-optimized-windows-2026-10-23.json)
  (`42057e6`) gave +33.1%, −3.1%, +30.2%, −13.3% in workload table order.
- The [intermediate candidate](benchmarks/postplus-bridge-intermediate-windows-2026-10-23.json)
  (`fa30072`, before reactor-side HTTP close) gave +7.3%, −10.4%, +4.9%, −10.3%
  against that initial baseline.
- A later short pair using the final code, without counterbalancing or a TCP-state
  cooldown, gave **−19.4%, +11.0%, −10.3%, −10.5%**. Both the
  [baseline](benchmarks/postplus-short-final-baseline-windows-2026-10-23.json.gz)
  and [candidate](benchmarks/postplus-short-final-candidate-windows-2026-10-23.json.gz)
  are retained. Reversed directions prompted the fixed-order, cooled comparison;
  they reinforce the limits of short local measurements.
- An attempt to increase each workload count fivefold failed during the second
  baseline round with Windows ephemeral-port exhaustion (`WinError 10048`),
  alongside connection resets. The host's dynamic port range was 49,152–65,535.
  Its [partial raw result](benchmarks/postplus-failed-large-baseline-windows-2026-10-23.json.gz)
  is not a valid performance comparison. No candidate block ran in that attempt.
- Earlier exploratory files remain under `build/perf-maintenance/before.json`
  and `after.json`; the candidate overlapped preparation of the PACE probe and
  is excluded from the reported comparisons.

To reproduce the final comparison, preserve baseline binaries/assets/configuration
and run `scripts/benchmark_network.py` four times with default counts in A/B/B/A
order, matching `--web-root`, `--config-template`, and correct `--source-revision`.
Stop local builds/tests and wait for fewer than 1,000 host TCP `TIME_WAIT` entries
before each block. Use the harness's `summarize()` on the six rounds per version;
do not average block percentiles. `--compare` validates matching provenance for
individual pairs. Never compare incomplete runs or relabel existing binaries.

## Independently reproduced PACE cost

[PACE #15](https://github.com/TabNahida/PACE/issues/15) reports that the HTTP client
waits for graceful transport close after receiving an already fully framed
`Content-Length` response. With an independently delayed server close, a complete
two-byte response can be withheld until peer FIN or the approximately 100 ms close
budget. There is currently no public client option to change that budget.

The issue contains a standalone reproducer using unmodified PACE, without PostPlus,
worker bridges, authentication or databases. All 100 exchanges returned the exact
expected body. [Raw probe samples](benchmarks/pace-http-close-windows-2026-10-23.csv)
are retained. Ten samples per condition gave these median `send()` durations:

| Requested peer-close delay | Connection: close | Connection: keep-alive |
|---|---:|---:|
| 0 ms | 0.14 ms | 0.05 ms |
| 1 ms | 13.64 ms | 0.05 ms |
| 10 ms | 13.92 ms | 0.05 ms |
| 50 ms | 60.35 ms | 0.05 ms |
| 200 ms | 106.53 ms | 0.05 ms |

Windows timer granularity affects the actual requested sleep. This isolates an
extra close wait; it does not attribute all PostPlus performance differences to
PACE. PostPlus's reactor-side server shutdown reduces its own contribution to
that wait, while the upstream request concerns the general HTTP client policy.
