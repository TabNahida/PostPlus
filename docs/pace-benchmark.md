# Network migration benchmark

The PACE 0.1.1 transport integration passes the compatibility checks described in
[network integration](pace-migration.md), but this Windows application benchmark
shows **no overall performance improvement**. HTTP health throughput regressed
39.7%, and its p95 increased from 1.809 to 13.207 ms. Mailbox throughput was 14.9%
lower. Storage RPC had a higher median throughput but wide variation and worse
p99. SMTP throughput was 3.9% lower with overlapping round ranges and worse tails.

## Implementations and evidence

| Input | Asio baseline | PACE candidate |
|---|---|---|
| PostPlus revision | `205254ff8041f2ee5f83f9e1c162951f3e3da134` (0.5.2) | `6a45b1670d8620ab0713b8f21950d2b7614a6a4b` |
| Transport | Asio 1.34.2 | Unmodified PACE 0.1.1 |
| UTC run, 2026-10-23 | 14:18:52–14:19:05 | 14:22:24–14:22:40 |
| Raw schema 2 result | [Asio JSON](benchmarks/asio-windows-2026-10-23-paired.json) | [PACE JSON](benchmarks/pace-windows-2026-10-23-paired.json) |

PACE source: `61fe0e21d62205fca77d1fb1e07e91aa200b6050`; inspected `tab-repo`
recipe: `a880ca1bb53e8cb8a5b7bba330540f3823d44932`. Both builds use static
OpenSSL 3.6.1 and the same pinned database/JSON dependencies. The candidate
replaces production Asio with PACE sockets, reactor, DNS and the HTTP RPC client.
HTTP servers retain PostPlus framing/admission/streaming policy; mail/HTTPS TLS
uses an OpenSSL application adapter on PACE sockets. This does not benchmark
PACE's HTTP server parser or TLS stream API.

Host: Windows 11 build 26200, AMD64, Intel Family 6 Model 198 Stepping 2,
24 logical processors; MSVC release builds and Python 3.13.3. All builds and tests
finished before measurement. Frozen baseline executable hashes were verified.
Both runs used `build/pace-baseline/web` and its `example.json`; no source,
binaries, harness or fixture changed between runs.

The comparison command accepted both complete results with identical host,
parameters, configuration hash and harness hashes. Harness SHA-256:

- `scripts/benchmark_network.py`: `2b061c19f79e3b2111a2920cca22771f6c4cc635a9696c540e1f3d62856ecb56`
- `tests/integration.py`: `87a571b9fdb28311d57c9a3d2a4e5b9aaeaa63cfc6471d4205485b0f4d4fb0d9`

## Method

Three rounds each create temporary data, random loopback ports, a service token,
one mailbox and 50 seeded messages. Six services run during timing, with 128
connection slots and client concurrency 8. Every operation opens a new connection.
Logging is error-only; external scanners and outbound delivery are disabled.
There are no public DNS queries, external mail deliveries or production changes.

| Workload | Operations per round | Warmup | Verification |
|---|---:|---:|---|
| `GET /health` | 1,000 | 40 | HTTP 200 and `ok`; includes public connection security check |
| Authenticated `GET /api/messages` | 300 | 40 | HTTP 200 and 50 messages |
| Authenticated storage `/rpc` stats | 1,000 | 40 | `ok` and expected message count |
| SMTP durable acceptance | 80 | 8 | EHLO, MAIL, RCPT, DATA, QUIT and durable queue count |

Messages are exactly 4,096 bytes. SMTP latency includes QUIT after durable DATA
acceptance. After timing, the delivery worker starts; every accepted message must
reach the mailbox and the queue must empty. **Each backend completed 7,140 measured
operations with zero errors and delivered all 264 SMTP messages including warmup.**
Warmups and resource collection also had zero errors. No paired run was discarded.

Throughput is successful operations divided by elapsed wall-clock time; the report
uses its three-round median. Latencies use nearest-rank percentiles pooled across
successful measured operations. Failed/incomplete results cannot be compared.

## Throughput and latency

Latency columns are milliseconds; changes compare median throughput.

| Workload | Asio ops/s | PACE ops/s | Change | Asio p50 / p95 / p99 | PACE p50 / p95 / p99 |
|---|---:|---:|---:|---|---|
| HTTP health | 3,755.17 | 2,263.66 | −39.7% | 1.341 / 1.809 / 17.174 | 1.522 / 13.207 / 24.749 |
| Authenticated mailbox | 854.28 | 726.66 | −14.9% | 3.433 / 27.066 / 28.563 | 4.937 / 25.342 / 32.241 |
| Storage RPC | 6,089.36 | 6,741.17 | +10.7% | 1.145 / 1.638 / 2.159 | 1.107 / 1.591 / 11.029 |
| SMTP durable acceptance | 266.27 | 255.98 | −3.9% | 24.994 / 42.956 / 50.012 | 25.666 / 49.013 / 71.599 |

| Workload | Asio ops/s, rounds 1 / 2 / 3 | PACE ops/s, rounds 1 / 2 / 3 |
|---|---|---|
| HTTP health | 5,659.50 / 3,755.17 / 3,693.44 | 2,852.11 / 2,263.66 / 2,140.24 |
| Authenticated mailbox | 806.72 / 854.28 / 899.56 | 721.68 / 936.00 / 726.66 |
| Storage RPC | 6,561.19 / 6,089.36 / 4,472.10 | 6,783.78 / 3,884.61 / 6,741.17 |
| SMTP durable acceptance | 266.27 / 279.58 / 256.13 | 255.98 / 291.56 / 252.34 |

HTTP health ranges do not overlap in this pair. Other ranges overlap; the RPC
median alone is not evidence of a stable improvement. Worker/reactor handoffs in
the new synchronous bridge and Windows PACE's WSAPoll/UDP wakeup are candidates
for profiling, **not established causes**. No scheduler/CPU profile or isolated
library experiment was collected. This is a PostPlus integration regression and
cannot be attributed uniquely to PACE. Further HTTP server adoption depends on
[asynchronous admission (#12)](https://github.com/TabNahida/PACE/issues/12) and
[safe connection cancellation (#13)](https://github.com/TabNahida/PACE/issues/13).

## Resource use and limits

CPU is aggregate server CPU seconds from `GetProcessTimes`; RSS is aggregate
resident memory sampled by `GetProcessMemoryInfo`. Both cover auth, storage,
filter, transfer, SMTP and Web, excluding Python and the post-timing delivery worker.

| Workload | Asio CPU s, rounds 1 / 2 / 3 | PACE CPU s, rounds 1 / 2 / 3 |
|---|---|---|
| HTTP health | 0.921875 / 0.890625 / 1.062500 | 0.578125 / 0.484375 / 0.671875 |
| Authenticated mailbox | 0.953125 / 0.578125 / 1.265625 | 0.640625 / 0.765625 / 0.859375 |
| Storage RPC | 0.296875 / 0.281250 / 0.125000 | 0.281250 / 0.312500 / 0.250000 |
| SMTP durable acceptance | 0.156250 / 0.250000 / 0.359375 | 0.203125 / 0.281250 / 0.296875 |

| Workload | Asio peak sampled RSS MiB, rounds 1 / 2 / 3 | PACE peak sampled RSS MiB, rounds 1 / 2 / 3 |
|---|---|---|
| HTTP health | 100.76 / 101.42 / 101.02 | 100.85 / 100.41 / 100.78 |
| Authenticated mailbox | 107.53 / 107.83 / 108.00 | 107.38 / 107.34 / 107.62 |
| Storage RPC | 107.52 / 107.57 / 108.07 | 107.47 / 107.01 / 107.66 |
| SMTP durable acceptance | 109.44 / 109.81 / 110.29 | 109.64 / 109.14 / 109.61 |

Timed windows last only 0.15–0.47 seconds. CPU-counter granularity, scheduling and
background activity can materially affect them. RSS is sampled every 100 ms
(3–6 samples per measured window), missing possible transient peaks. Python shares
the host and can limit throughput. This closed-loop fixed-concurrency measurement
does not cover TLS, WAN traffic, sustained saturation, externally fixed arrival
rates or maximum capacity. It establishes neither statistical significance nor a
universal library speedup.

## Port pressure and history

TIME_WAIT counts were 34 before the baseline and 22,133 afterward. Measurement
paused until the count fell to 20 before running PACE. No TCP settings changed.
Public requests also create internal RPC connections; repeated fresh-connection
runs without settling can create transient port pressure.

The [historical schema 1 Asio result](benchmarks/asio-windows-2026-10-23.json) is
archival and not used above. An earlier high-volume trial (8,000 health, 8,000 RPC,
2,000 mailbox, 400 SMTP per round) had connection errors; partial diagnostic data
remains in `build/pace-benchmark/high-volume-partial.json`. The schema 2 pair above
was freshly measured after compatibility tests. PACE 0.1.0 requests #7–#10 were
addressed before this integration. Remaining boundaries are described in
[network integration](pace-migration.md).

## Reproduce

Preserve baseline binaries/assets/config before building the candidate. Use the
same host, Python, harness, fixture, Web assets and configuration for both runs.
Stop builds/tests and allow TCP state to settle between commands:

```powershell
$common = @('--web-root', 'build/pace-baseline/web',
  '--config-template', 'build/pace-baseline/example.json',
  '--rounds', '3', '--concurrency', '8', '--http-requests', '1000',
  '--rpc-requests', '1000', '--mailbox-requests', '300', '--smtp-messages', '80',
  '--warmup', '40', '--smtp-warmup', '8', '--seed-messages', '50', '--message-bytes', '4096')
python scripts/benchmark_network.py --bin-dir build/pace-baseline `
  --label asio-paired --source-revision 205254ff8041f2ee5f83f9e1c162951f3e3da134 `
  --output build/pace-benchmark/asio-rerun.json @common
# Wait for TCP state to settle before running the next command.
python scripts/benchmark_network.py --bin-dir build/windows/x64/release `
  --label pace-0.1.1-paired --source-revision 6a45b1670d8620ab0713b8f21950d2b7614a6a4b `
  --output build/pace-benchmark/pace-rerun.json @common
python scripts/benchmark_network.py --compare `
  build/pace-benchmark/asio-rerun.json build/pace-benchmark/pace-rerun.json
```

Use these revision labels only with binaries from those revisions. Raw results
include binary hashes and checkpoints of partial failures. Retain failures under
separate filenames. `python scripts/benchmark_network.py --self-test` checks
failure retention and comparison validation without starting services.
