# Network migration benchmark

## Status

The existing Asio backend has a measured baseline. The PACE migration and its
measurement are pending upstream compatibility work; there is **no PACE result or
claimed performance improvement** yet.

The integration is waiting for an upstream release, as requested. PostPlus still
uses Asio and its production dependencies are unchanged. The following PACE
v0.1.0 requirements were filed against upstream:

| Issue | Required capability | Evidence |
|---|---|---|
| [PACE #7](https://github.com/TabNahida/PACE/issues/7) | IPv6 TCP listeners and connections | A local `::1` listener probe prints `expected a numeric IPv4 address` and exits 1 |
| [PACE #8](https://github.com/TabNahida/PACE/issues/8) | Server SNI certificate selection and application trust stores | Public API and implementation review; no failing TLS experiment claimed |
| [PACE #9](https://github.com/TabNahida/PACE/issues/9) | Admission before the complete request body, per-request limits, streamed responses | Local HTTP probe returns 401 only after the 1,024-byte body is sent |
| [PACE #10](https://github.com/TabNahida/PACE/issues/10) | Publish the Xmake package recipe | `repo-xmake` tree contains only README and LICENSE at the inspected commit |

The probes used PACE commit `66ed7c34129b6b2d95ae01e053da5755a0739ffe`
(`v0.1.0`), Windows x64, MSVC 14.51.36231, and Xmake 3.1.1. The package tree
was checked at `3b3f8a60c90306b7d7cd8f3660aa497eb48e03c8`. The issues contain
reproduction details and acceptance scenarios. No compatibility fork has been
added to PostPlus.

When a suitable upstream version is available, first verify these capabilities,
then migrate and run the existing HTTP security, IPv6/DNS/outbound, domain TLS,
STARTTLS/IMAP IDLE, portal and lifecycle tests. Only compare performance after
those behavior checks pass, using paired Asio and PACE runs on the same host.

The baseline was collected on 2026-10-23 from release binaries at commit
`205254ff8041f2ee5f83f9e1c162951f3e3da134`, before production changes. Seven service
executables, the public Web assets, and the example configuration were copied to
`build/pace-baseline/`. The copy excludes user configuration, databases, credentials,
and private keys. `manifest.json` records executable sizes and SHA-256 hashes.

## Workloads and method

`scripts/benchmark_network.py` uses the real-process integration fixture. Every round
gets a new temporary database, random loopback ports, a random service token, one
mailbox, and 50 identical seeded messages. All processes and temporary data are
removed afterward. The server has 128 connection slots; client concurrency is 8.
All requests open and close a fresh TCP connection. No public DNS queries, external
mail deliveries, production configuration changes, or builds are performed.

Three rounds use exactly the same workload sizes:

| Workload | Measured operations per round | Warmup | Verification |
|---|---:|---:|---|
| `GET /health` | 1,000 | 40 | HTTP 200 and `ok` |
| Authenticated `GET /api/messages` | 300 | 40 | HTTP 200 and 50 seeded messages |
| Authenticated storage `/rpc` stats | 1,000 | 40 | `ok` and expected message count |
| SMTP receive and durable acceptance | 80 | 8 | EHLO, MAIL, RCPT, DATA, QUIT; durable queue count |

SMTP messages are exactly 4,096 bytes, with lines below the SMTP length limit.
Its latency includes connection establishment through `QUIT`; acceptance requires
durable queue storage. After timing, the delivery worker starts and every accepted
message must reach the local mailbox with an empty remaining queue. All 264 messages
(warmup included) were delivered across the three rounds.

The load generator is closed loop with fixed concurrency. Throughput is successful
operations divided by the round's wall-clock time. The table uses the median
throughput of three rounds and nearest-rank percentiles pooled over successful
operations. Failures are counted separately and prevent the comparison command from
presenting a performance comparison. Raw latency samples, per-round measurements,
binary hashes, host details, CPU counters, and memory samples are saved in
[`benchmarks/asio-windows-2026-10-23.json`](benchmarks/asio-windows-2026-10-23.json),
with the original working copy at `build/pace-benchmark/baseline.json`.

## Asio baseline

Host: Windows 11 build 26200, AMD64, Intel Family 6 Model 198 Stepping 2, 24 logical
processors; Python 3.13.3. Retained run: 12:14:46–12:14:59 UTC on 2026-10-23.

| Workload | Median ops/s | Round range ops/s | p50 ms | p95 ms | p99 ms | Errors / attempts |
|---|---:|---:|---:|---:|---:|---:|
| HTTP health | 3,682.50 | 2,577.65–4,064.09 | 1.346 | 2.319 | 20.035 | 0 / 3,000 |
| Authenticated mailbox | 720.74 | 580.05–782.86 | 3.518 | 27.173 | 28.460 | 0 / 900 |
| Storage RPC | 5,802.40 | 5,764.14–6,572.94 | 1.199 | 1.687 | 2.033 | 0 / 3,000 |
| SMTP durable acceptance | 269.36 | 252.33–272.64 | 25.940 | 41.118 | 47.964 | 0 / 240 |

CPU time is measured with `GetProcessTimes`; resident memory uses
`GetProcessMemoryInfo`. Both cover the six running server services, excluding the
Python load generator. The delivery worker runs after measurement. Per-round CPU
seconds and sampled aggregate resident memory were:

| Workload | CPU seconds, rounds 1 / 2 / 3 | Peak sampled RSS MiB, rounds 1 / 2 / 3 |
|---|---|---|
| HTTP health | 0.765625 / 1.015625 / 1.156250 | 100.49 / 101.17 / 101.20 |
| Authenticated mailbox | 0.609375 / 1.421875 / 1.250000 | 107.38 / 107.35 / 107.32 |
| Storage RPC | 0.218750 / 0.281250 / 0.265625 | 107.57 / 107.28 / 107.25 |
| SMTP durable acceptance | 0.328125 / 0.343750 / 0.234375 | 109.76 / 109.43 / 109.54 |

These are short local measurements, not capacity claims. Individual timed windows
lasted approximately 0.15–0.52 seconds, so OS scheduling and CPU-counter granularity
can materially affect results. The observed variation is reported rather than
hidden. RSS was sampled every 100 ms (3–6 samples per window) and can miss transient
peaks. Client and server share one machine, and Python can limit peak throughput.
This does not measure TLS, WAN latency, sustained saturation, or latency under an
externally fixed arrival rate. A later comparison must rerun the Asio baseline
alongside the PACE candidate on the same host and parameters; small differences
within the observed variation should not be treated as improvements.

## Windows port-pressure diagnostic

An initial, discarded trial used 8,000 health requests, 8,000 storage requests,
2,000 mailbox requests, and 400 SMTP messages per round. It produced 2 SMTP errors
in round 1, then widespread connection resets in round 2; it is not a valid
performance baseline. Its completed first round is retained separately in
`build/pace-benchmark/high-volume-partial.json` for diagnosis.

Read-only OS inspection afterward showed a TCP dynamic range of 49,152–65,535
(16,384 ports) and 35,708 `TIME_WAIT` entries. Public requests also create internal
RPC connections, so application operation count understates connection churn. This
is evidence of substantial transient port pressure, but the discarded trial alone
does not establish a unique cause for every error. No operating-system TCP settings
were changed. After reducing the default workload and allowing the earlier churn
to clear during investigation, all three retained rounds completed with zero
errors. Avoid running repeated fresh-connection benchmarks back to back; allow
the host's TCP state to settle between comparison runs, and retain failed output
separately instead of reporting it as a successful sample.

## Reproduce and compare

From the repository root, with the same release binary snapshot and Python:

```powershell
python scripts/benchmark_network.py --bin-dir build/pace-baseline `
  --web-root build/pace-baseline/web `
  --config-template build/pace-baseline/example.json `
  --label asio-baseline --source-revision 205254ff8041f2ee5f83f9e1c162951f3e3da134 `
  --output build/pace-benchmark/baseline-rerun.json
```

Once PACE is integrated, repeat with its release binary directory, an accurate
candidate source revision, and a different output name. Keep the same pinned Web
assets, template, and default workload counts. Then compare:

```powershell
python scripts/benchmark_network.py --compare `
  build/pace-benchmark/baseline-rerun.json build/pace-benchmark/pace.json
```

The current script writes schema 2 results, checkpointing each completed workload
and retaining partial results plus failure details when validation fails. It records
SHA-256 hashes of itself and `tests/integration.py`. The comparison rejects missing
or mismatched harness hashes, incomplete runs, mismatched workload parameters,
template hashes, host descriptions, and any request errors.

The historical baseline above uses schema 1, collected before these diagnostic
improvements. Keep it as an archived observation; the comparison command deliberately
requires rerunning **both** implementations with the same current script. Its
original script SHA-256 was
`5de9efbcae72add14122a54bc09edeb24478c575c586938c6dd2d1829093ec17`;
the integration fixture SHA-256 was
`87a571b9fdb28311d57c9a3d2a4e5b9aaeeaa63cfc6471d4205485b0f4d4fb0d9`.

Run `python scripts/benchmark_network.py --self-test` for offline checks of failure
retention and comparison validation. CPU/RSS collection is available on Windows
and Linux; unsupported platforms report unavailable data explicitly.
