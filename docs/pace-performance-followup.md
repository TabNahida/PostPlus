# PACE bridge performance follow-up

This follow-up reduces PostPlus's own networking overhead while retaining the
unmodified PACE 0.1.1 dependency. In this Windows loopback comparison, HTTP health
and storage RPC throughput increased, but authenticated mailbox and SMTP medians
did not improve. This is not evidence of an overall or production-capacity gain.

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

The last change uses PACE's existing server-side graceful close; it does not patch
PACE or bypass PostPlus's framing, authentication, deadlines, or cancellation.

## Same-host comparison

| Input | Baseline | Optimized |
|---|---|---|
| PostPlus source | `9e2513130327528143ab91861d5cf60ea35564aa` (1.0.0) | `42057e6f76fd4aff33bc3b7aedb2fea107000f6c` |
| Raw result | [Baseline](benchmarks/postplus-100-before-optimization-windows-2026-10-23.json) | [Optimized](benchmarks/postplus-bridge-optimized-windows-2026-10-23.json) |
| Measured UTC on 2026-10-23 | 17:21:30–17:21:46 | 17:41:28–17:41:44 |

Both use the same local MSVC Release configuration, official PACE 0.1.1, frozen
1.0.0 Web assets and configuration, benchmark harness, Windows 11 x64 host and
Python 3.13.3. Builds, probes and integration tests were not running during these
two measurements. Baseline executables were copied before making changes; raw
results retain executable hashes, host details and both harness hashes.

The existing [benchmark method](pace-benchmark.md#method) is unchanged: three
rounds, concurrency 8, a fresh connection for each operation, 1,000 health requests,
300 authenticated mailbox requests, 1,000 storage RPC requests and 80 SMTP messages
per round. Warmup is 40 requests or 8 SMTP messages, with 50 seeded messages of
4,096 bytes. Both versions completed **7,140 measured operations without errors**
and delivered all **264 SMTP messages**, including warmup. Each round verifies
the durable queue and its complete delivery after timing.

| Workload | Baseline ops/s | Optimized ops/s | Median change | Baseline p95 ms | Optimized p95 ms |
|---|---:|---:|---:|---:|---:|
| HTTP health | 2,448.13 | 3,259.55 | +33.1% | 8.908 | 3.440 |
| Authenticated mailbox | 1,103.58 | 1,069.01 | −3.1% | 15.345 | 24.517 |
| Storage RPC | 5,510.45 | 7,176.67 | +30.2% | 1.811 | 1.507 |
| SMTP durable acceptance | 257.03 | 222.76 | −13.3% | 47.917 | 57.892 |

| Workload | Baseline round range, ops/s | Optimized round range, ops/s |
|---|---:|---:|
| HTTP health | 1,986–2,537 | 2,779–3,593 |
| Authenticated mailbox | 734–1,297 | 940–1,175 |
| Storage RPC | 5,198–6,453 | 7,092–7,276 |
| SMTP durable acceptance | 242–270 | 220–297 |

Health/RPC ranges do not overlap in these runs. Mailbox/SMTP ranges overlap, but
their lower medians and worse p95 remain negative measurements, not improvements.
The run order was not randomized or counterbalanced. These are short, closed-loop
measurements sharing a host with the Python load generator; scheduling, filesystem
activity and host drift can affect them. They do not establish significance,
sustained capacity, TLS performance, or gains on Linux/macOS. Further profiling
is needed before claiming mailbox or SMTP improvements.

An [intermediate result](benchmarks/postplus-bridge-intermediate-windows-2026-10-23.json)
at `fa30072f2a9b753ec082bda492269ef3e8285ac0` contains the first three changes but
not reactor-side HTTP shutdown. Against the same baseline its median changes were
+7.3%, −10.4%, +4.9%, and −10.3%, in table order. This prompted investigation of
response teardown. Earlier exploratory files remain under
`build/perf-maintenance/before.json` and `after.json`; the candidate overlapped
preparation of the independent PACE probe, so those files are not used here.

To reproduce, preserve the baseline binaries, Web assets and example configuration,
then run `scripts/benchmark_network.py` for each build with the same `--web-root`
and `--config-template`, default counts, and the appropriate `--source-revision`.
Allow TCP state to settle and stop local builds/tests before each measurement.
Run `--compare <baseline.json> <candidate.json>` to verify matching provenance and
calculate the comparison; do not compare incomplete runs or relabel old binaries.

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
